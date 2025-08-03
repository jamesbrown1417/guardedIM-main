import datetime
import json
import os
import socket
import struct
import threading

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from dotenv import load_dotenv

from common import encryption

load_dotenv()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
KEYS_DIR = os.path.join(BASE_DIR, "..", "keys")
os.makedirs(KEYS_DIR, exist_ok=True)
PRIVATE_KEY_PATH = os.path.join(KEYS_DIR, "private_key.pem")
PUBLIC_KEY_PATH = os.path.join(KEYS_DIR, "public_key.pem")

clients = {}
groups = {}


def broadcast_user_list() -> None:
    usernames = list(clients.keys())
    for _, (conn, key) in clients.items():
        try:
            payload = json.dumps({"type": "user_list", "users": usernames})
            encrypted = encryption.encrypt_message(payload, key)
            conn.sendall(struct.pack(">I", len(encrypted)) + encrypted)
        except Exception as e:
            print(f"Broadcast user list failed: {e}")
            continue


def forward_payload(to_user: str, payload: json) -> None:
    if to_user in clients:
        dest_conn, dest_key = clients[to_user]
        encrypted = encryption.encrypt_message(json.dumps(payload), dest_key)
        dest_conn.sendall(struct.pack(">I", len(encrypted)) + encrypted)


def handle_client(conn: socket.socket, private_key: RSAPrivateKey) -> None:
    username = None
    try:
        encrypted_aes_key = conn.recv(256)
        aes_key = private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                         algorithm=hashes.SHA256(), label=None)
        )

        username = conn.recv(1024).decode().strip()
        if not username:
            print("No username received.")
            return

        clients[username] = (conn, aes_key)

        try:
            payload = json.dumps({
                "type": "user_list",
                "users": list(clients.keys())
            })

            encrypted = encryption.encrypt_message(payload, aes_key)
            conn.sendall(struct.pack(">I", len(encrypted)) + encrypted)
        except Exception as e:
            print(f"Failed to send user list to {username}: ", e)
        broadcast_user_list()

        conn_file = conn.makefile('rb')
        while True:
            header = conn_file.read(4)
            if not header:
                break
            msg_len = struct.unpack(">I", header)[0]
            data = conn_file.read(msg_len)
            if len(data) < msg_len:
                break

            if not data:
                break
            try:
                decrypted = encryption.decrypt_message(data, aes_key)
                payload = json.loads(decrypted)

                match payload.get("type"):
                    case "create_group":
                        group_name = payload.get("group_name")
                        members = payload.get("members")
                        admin = payload.get("from")

                        if group_name in groups:
                            system_message = json.dumps({
                                "type": "System",
                                "message": "Group already exists."
                            })
                            encrypted = encryption.encrypt_message(
                                system_message, aes_key)
                            conn.sendall(struct.pack(
                                ">I", len(encrypted)) + encrypted)
                            continue

                        groups[group_name] = {"members": members}

                        for member in members:
                            if member != admin and member in clients:
                                dest_conn, dest_key = clients[member]

                                group_invite = json.dumps({
                                    "type": "group_invite",
                                    "group_name": group_name,
                                    "members": members
                                })
                                encrypted = encryption.encrypt_message(
                                    group_invite, dest_key)
                                dest_conn.sendall(struct.pack(
                                    ">I", len(encrypted)) + encrypted)

                        ack = json.dumps({
                            "type": "group_created",
                            "group_name": group_name
                        })

                        admin_conn, admin_key = clients[admin]
                        encrypted = encryption.encrypt_message(ack, admin_key)
                        admin_conn.sendall(struct.pack(
                            ">I", len(encrypted)) + encrypted)

                    case "group_message":
                        group_name = payload.get("to")
                        sender = payload.get("from")
                        message = payload.get("payload")

                        payload["to"] = group_name
                        payload["payload"] = message
                        payload["payload_type"] = "text"
                        payload["to_type"] = "group"
                        payload["timestamp"] =  datetime.datetime.now(datetime.timezone.utc).isoformat() + "Z"

                        if group_name in groups:
                            for member in groups[group_name]["members"]:
                                if member != sender and member in clients:
                                    mem_conn, mem_key = clients[member]
                                    relay = json.dumps(payload)
                                    encrypted = encryption.encrypt_message(
                                        relay, mem_key)
                                    mem_conn.sendall(struct.pack(
                                        ">I", len(encrypted)) + encrypted)

                    case "message":
                        if not encryption.check_message_size(payload.get("payload")):
                            system_message = json.dumps({
                                "type": "System",
                                "message": f"Message dropped. Exceeds limit of {encryption.MAX_MESSAGE_SIZE}."
                            })
                            encrypted = encryption.encrypt_message(
                                system_message, aes_key)
                            conn.sendall(struct.pack(
                                ">I", len(encrypted)) + encrypted)
                            continue

                        payload["payload_type"] = "text"
                        payload["to_type"] = "user"
                        payload["timestamp"] = datetime.datetime.now(datetime.timezone.utc).isoformat() + "Z"
                        forward_payload(payload.get('to'), payload)

                    case "message_file" | "group_file":
                        file_data = payload.get("payload")
                        file_to = payload.get("to").lstrip("#")
                        sender = payload.get("from")
                        filename = payload.get("filename")
                        is_group = payload.get("to_type") == "group"

                        if not file_data or not filename:
                            raise ValueError("Missing filedata or filename.")

                        if not encryption.check_file_size(file_data):
                            system_message = json.dumps({
                                "type": "System",
                                "message": f"Message dropped. Exceeds limit of {encryption.MAX_FILE_SIZE} bytes."
                            })
                            encrypted = encryption.encrypt_message(
                                system_message, aes_key)
                            conn.sendall(struct.pack(
                                ">I", len(encrypted)) + encrypted)
                            continue

                        payload["payload_type"] = "file"
                        payload["timestamp"] = datetime.datetime.now(datetime.timezone.utc).isoformat() + "Z"

                        if is_group and file_to in groups:
                            for member in groups[file_to]["members"]:
                                if member != sender and member in clients:
                                    mem_conn, mem_key = clients[member]
                                    relay = json.dumps(payload)
                                    encrypted = encryption.encrypt_message(relay, mem_key)
                                    mem_conn.sendall(struct.pack(">I", len(encrypted)) + encrypted)
                        else:
                            forward_payload(file_to, payload)
            except Exception as e:
                print(f"Decryption error: {e}")

    finally:
        if username in clients:
            del clients[username]
        broadcast_user_list()
        conn.close()


def generate_keys() -> None:
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    with open(PRIVATE_KEY_PATH, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    with open(PUBLIC_KEY_PATH, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ))


def main(generate_keys_flag: bool = False) -> None:
    IP = os.getenv("IP_ADDRESS")
    PORT = int(os.getenv("PORT"))

    if generate_keys_flag:
        generate_keys()

    with open(PRIVATE_KEY_PATH, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(), password=None)

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((IP, PORT))

    server.listen(5)
    print(f"Server started on {IP}:{PORT}")

    with open(PUBLIC_KEY_PATH, "rb") as f:
        public_key = f.read()

    while True:
        conn, _ = server.accept()

        conn.sendall(struct.pack(">I", len(public_key)) + public_key)
        threading.Thread(target=handle_client, args=(
            conn, private_key), daemon=True).start()


if __name__ == "__main__":
    import sys
    main("--gen-keys" in sys.argv)
