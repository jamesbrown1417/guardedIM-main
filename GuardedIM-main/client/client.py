import base64
import datetime
import json
import os
import socket
import struct
import threading

from dotenv import load_dotenv

from common import encryption

load_dotenv()


class ChatClient:
    def __init__(self, username: str, on_message_received, on_user_list: list) -> None:
        self.username = username
        self.aes_key = encryption.generate_aes_key()
        self.conn = None
        self.on_message_received = on_message_received
        self.on_user_list = on_user_list
        self.session_token = None

    def connect(self) -> None:
        db_path = os.getenv("CLIENT_LOCALDB_PATH", "/home/user/.guardedim/client.db")
        IP = os.getenv("IP_ADDRESS")
        PORT = int(os.getenv("PORT"))

        self.conn = socket.create_connection((IP, PORT))
        public_key_bytes = self.conn.recv(4096)
        encrypted_key = encryption.rsa_encrypt_key(
            public_key_bytes, self.aes_key)

        self.conn.sendall(encrypted_key)
        self.conn.sendall(self.username.encode())

    def start_receiving(self) -> None:
        threading.Thread(target=self.receive_loop, daemon=True).start()

    def receive_loop(self) -> None:
        conn_file = self.conn.makefile('rb')
        while True:
            try:
                header = conn_file.read(4)
                if not header:
                    print("Server closed the connection")
                    break
                msg_len = struct.unpack(">I", header)[0]
                data = conn_file.read(msg_len)
                if len(data) < msg_len:
                    print("Incomplete message received")
                    break

                decrypted = encryption.decrypt_message(data, self.aes_key)
                payload = json.loads(decrypted)

                match payload.get("type"):
                    case "user_list":
                        users = payload.get("users")
                        if self.on_user_list:
                            self.on_user_list(users)

                    case "login_success":
                        # Implement on server-side.
                        self.session_token = payload.get("token")

                    case "error":
                        print(f"Server error: {payload.get('message', [])}")
                        self.conn.close()
                        return

                    case "message":
                        chat_type = payload.get("from")
                        sender = payload.get("sender", chat_type)
                        message = payload.get("payload")
                        self.on_message_received(chat_type, message, sender)
                    
                    case "group_message":
                        chat_type = f"#{payload.get('to')}"
                        sender = payload.get("from")
                        message = payload.get("payload")
                        self.on_message_received(chat_type, message, sender)

                    case "group_invite":
                        group_name = payload.get("group_name")
                        display_name = f"#{group_name}"
                        self.on_message_received(
                            display_name, f"Added to {group_name}", "System")

                    case "group_created":
                        group_name = payload.get("group_name")
                        display_name = f"#{group_name}"
                        self.on_message_received(display_name, f"Group {group_name} created.", "System")

                    case "message_file" | "group_file":
                        filename = payload.get("filename")
                        encoded_data = payload.get("payload")
                        sender = payload.get("from")
                        to = payload.get("to")
                        to_type = payload.get("to_type")

                        if not filename or not encoded_data:
                            print("Missing filename or filedata in payload.")
                            break

                        try:
                            filedata = base64.b64decode(encoded_data + "===")
                        except Exception as e:
                            print("Base64 decode failed:", e)
                            break

                        path = f"chat_media/user_{self.username}/from_{sender}"
                        os.makedirs(path, exist_ok=True)
                        save_path = os.path.join(path, filename)

                        try:
                            with open(save_path, 'wb') as f:
                                f.write(filedata)
                        except Exception as e:
                            print("File write failed:", e)
                            break
                        chat_target = f"#{to}" if to_type == "group" else sender
                        self.on_message_received(
                            chat_target, f"Received: {filename} from {sender}", "System")

                    case _:
                        print("payload key not recognised.")
            except Exception as e:
                print("Error in receive loop:", e)
                continue

    def send_encrypted(self, payload: str) -> None:
        encrypted = encryption.encrypt_message(payload, self.aes_key)
        length_prefix = struct.pack(">I", len(encrypted))
        self.conn.sendall(length_prefix + encrypted)

    def send_group_message(self, to_group: str, message: str) -> bool:
        payload = json.dumps({
            "type": "group_message",
            "from": self.username,
            "to": to_group.lstrip("#"),
            "to_type": "group",
            "payload": message,
            "payload_type": "text",
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat() + "Z"
        })

        if not encryption.check_message_size(payload):
            self.on_message_received(
                "System", f"Message too long. Limit is {encryption.MAX_MESSAGE_SIZE} bytes.")
            return False

        self.send_encrypted(payload)
        return True

    def send_message(self, to_user: str, message: str) -> bool:
        payload = json.dumps({
            "type": "message",
            "from": self.username,
            "to": to_user,
            "to_type": "user",
            "payload": message,
            "payload_type": "text",
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat() + "Z"
            })

        if not encryption.check_message_size(payload):
            self.on_message_received(
                "System", f"Message too long. Limit is {encryption.MAX_MESSAGE_SIZE} bytes.")
            return False

        self.send_encrypted(payload)
        return True

    def create_group(self, group_name: str, members: list[str]) -> bool:
        payload = json.dumps({
            "type": "create_group",
            "from": self.username,
            "group_name": group_name,
            "members": members,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat() + "Z" 
        })

        self.send_encrypted(payload)
        return True

    def send_file(self, to_user: str, file_path: str) -> bool:
        block_set = ('.exe', '.bat', '.cmd', '.msi', '.sh')

        if file_path.lower().endswith(block_set):
            self.on_message_received(
                "System", f"Blocked dangerous file: {file_path}")
            return False

        try:
            with open(file_path, 'rb') as f:
                file = f.read()
                encoded_file = base64.b64encode(file).decode('utf-8')

            payload = json.dumps({
                "type": "message_file",
                "from": self.username,
                "to": to_user,
                "to_type": "user",
                "payload": encoded_file,
                "payload_type": "file",
                "filename": os.path.basename(file_path),
                "payload_id": None,
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat() + "Z"
            })

            if not encryption.check_file_size(encoded_file):
                self.on_message_received(
                    "System", f"File too large. Limit is {encryption.MAX_FILE_SIZE} bytes.")
                return False

            self.send_encrypted(payload)
            self.on_message_received(
                "System", f"Sent {os.path.basename(file_path)} to {to_user}")
            return True
        except Exception as e:
            self.on_message_received("System", f"File upload failed: {e}")
            return False

    def send_group_file(self, to_group:str, file_path:str) -> bool:
        block_set = ('.exe', '.bat', '.cmd', '.msi', '.sh')
        if file_path.lower().endswith(block_set):
            self.on_message_received(
                "System", f"Blocked dangerous file: {file_path}")
            return False

        try:
            with open(file_path, 'rb') as f:
                file = f.read()
                encoded_file = base64.b64encode(file).decode('utf-8')

            payload = json.dumps({
                "type": "group_file",
                "from": self.username,
                "to": to_group.lstrip("#"),
                "to_type": "group",
                "payload": encoded_file,
                "payload_type": "file",
                "filename": os.path.basename(file_path),
                "payload_id": None,
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat() + "Z"
            })

            if not encryption.check_file_size(encoded_file):
                self.on_message_received(
                    "System", f"File too large. Limit is {encryption.MAX_FILE_SIZE} bytes.")
                return False

            self.send_encrypted(payload)
            self.on_message_received(
                "System", f"Sent {os.path.basename(file_path)} to {to_group}")
            return True
        except Exception as e:
            self.on_message_received("System", f"File upload failed: {e}")
            return False

    def disconnect(self):
        try:
            if self.conn:
                self.conn.close()
        except Exception as e:
            print("Error disconnecting: ", e)
