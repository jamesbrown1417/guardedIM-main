import datetime
import sys
import tkinter as tk
from tkinter import END, RIGHT, Scrollbar, Y, filedialog, simpledialog
from typing import List, Optional

from client.client import ChatClient


class ChatGUI:
    def __init__(self) -> None:
        self.window = tk.Tk()
        self.window.title("GuardedIM Chat")
        self.window.geometry("680x1100")
        self.window.call('tk', 'scaling', 2.0)
        self.window.protocol("WM_DELETE_WINDOW", self.on_close)
        self.chat_histories = {}
        self.active_user = None
        self.known_users = set()
        self.username = simpledialog.askstring("Login", "Enter your username:")

        if not self.username:
            sys.exit()

        self.window.title(f"GuardedIM Chat - {self.username}")
        self.setup_widgets()

        self.client = ChatClient(self.username, self.on_message_received,self.update_user_list)
        self.client.connect()
        self.client.start_receiving()

    def setup_widgets(self) -> None:
        # Left panel: User list
        self.user_list_frame = tk.Frame(self.window, width=200, bg="#527F56")
        self.user_list_frame.pack(side=tk.LEFT, fill=tk.Y)

        self.user_listbox = tk.Listbox(
            self.user_list_frame, bg="#527F56", fg="white", font=("Ubuntu", 12))
        self.user_listbox.pack(fill=tk.BOTH, expand=True)
        self.user_listbox.bind("<<ListboxSelect>>", self.switch_user)

        # Main frame for chat + entry
        self.main_frame = tk.Frame(self.window, bg="#E5DDD5")
        self.main_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Chat area with scrollbar
        self.chat_canvas = tk.Canvas(self.main_frame, bg="#E5DDD5")
        self.chat_frame = tk.Frame(self.chat_canvas, bg="#E5DDD5")

        self.scrollbar = Scrollbar(
            self.main_frame, orient="vertical", command=self.chat_canvas.yview)
        self.chat_canvas.configure(yscrollcommand=self.scrollbar.set)

        self.scrollbar.pack(side=RIGHT, fill=Y)
        self.chat_canvas.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
        self.chat_canvas.create_window(
            (0, 0), window=self.chat_frame, anchor='nw')
        self.chat_frame.bind("<Configure>", self.chat_canvas.configure(
            scrollregion=self.chat_canvas.bbox("all")))

        # Bottom frame for entry and send button
        self.bottom_frame = tk.Frame(self.main_frame, bg="#E0E0E0")
        self.bottom_frame.pack(side=tk.BOTTOM, fill=tk.X)

        self.entry_field = tk.Entry(
            self.bottom_frame, bg="#FFFFFF", fg="black", font=("Ubuntu", 12))
        self.entry_field.pack(fill=tk.X, padx=10, pady=10,
                              side=tk.LEFT, expand=True)
        self.entry_field.bind("<Return>", lambda event: self.send())

        self.send_button = tk.Button(
            self.bottom_frame, text="Send", command=self.send, state=tk.DISABLED, font=("Ubuntu", 16))
        self.send_button.pack(padx=5, pady=5, side=tk.RIGHT)

        self.upload_button = tk.Button(
            self.bottom_frame, text="Upload", command=self.upload, state=tk.DISABLED, font=("Ubuntu", 16))
        self.upload_button.pack(padx=5, pady=5, side=tk.RIGHT)

        self.new_group_button = tk.Button(
            self.bottom_frame, text="New Group", command=self.new_group, state=tk.ACTIVE, font=("Ubuntu", 16))
        self.new_group_button.pack(padx=5, pady=5, side=tk.RIGHT)

    def new_group(self) -> None:
        group_name = simpledialog.askstring(
            "Create Group", "Enter group name:")
        members = simpledialog.askstring(
            "New Group", "Add members (comma separated):")

        if not group_name or not members:
            return

        members_list = [self.username] + [member.strip()
                                          for member in members.split(',')]

        if len(members_list) < 2:
            self.on_message_received(
                "System", "Group chat must have at least two members.")
            return

        if self.client.create_group(group_name, members_list):
            group_display_name = f"#{group_name}"
            if group_display_name not in self.user_listbox.get(0, END):
                self.user_listbox.insert(END, group_display_name)
                self.chat_histories.setdefault(group_display_name, [])
            self.active_user = group_display_name
            self.update_chat_display()
        else:
            self.on_message_received("System", "Failed to create group chat.")

    def on_message_received(self, from_user: str, message: str, sender:Optional[str]=None) -> None:
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")

        def format_username(username: str) -> str:
            if not username:
                return ""
            return username.replace(" (online)", "").strip()

        from_user_strip = format_username(from_user)
        actual_sender = format_username(sender if sender else from_user)

        if from_user_strip == "System":
            self.chat_histories.setdefault(self.active_user, []).append(
                (timestamp, "System", message))
            self.update_chat_display()
            return

        self.chat_histories.setdefault(from_user_strip, []).append(
            (timestamp, actual_sender, message)
        )

        existing_users = [format_username(self.user_listbox.get(user)) for user in range(self.user_listbox.size())]
        if from_user_strip != self.username and from_user_strip not in existing_users:
            self.user_listbox.insert(END, from_user_strip)

        if from_user_strip == self.active_user:
            self.update_chat_display()

    def switch_user(self, event: tk.Event) -> None:
        selection = event.widget.curselection()
        if not selection:
            return

        selected_text = self.user_listbox.get(selection[0])
        user = selected_text.split(" (")[0]
        self.active_user = user
        self.window.title(
            f"GuardedIM Chat - {self.username} chatting with {self.active_user}")
        self.update_chat_display()

        if self.active_user: 
            self.send_button.config(state=tk.NORMAL)
            self.upload_button.config(state=tk.NORMAL)
        else:
            self.send_button.config(state=tk.DISABLED)
            self.upload_button.config(state=tk.DISABLED)

    def send(self, event: Optional[tk.Event] = None) -> None:
        if not self.active_user:
            return
        message = self.entry_field.get().strip()
        if message:
            if self.active_user.startswith("#"):
                success = self.client.send_group_message(
                    self.active_user[1:], message)
            else:
                success = self.client.send_message(self.active_user, message)

            if success:
                timestamp = datetime.datetime.now().strftime("%H:%M:%S")
                self.chat_histories.setdefault(self.active_user, []).append(
                    (timestamp, "You", message))
                self.update_chat_display()
            self.entry_field.delete(0, END)

    def update_chat_display(self):
        for widget in self.chat_frame.winfo_children():
            widget.destroy()

        for timestamp, sender, message in self.chat_histories.get(self.active_user, []):
            frame = tk.Frame(self.chat_frame, bg="#E5DDD5")

            if sender == "You":
                bg = "#DCF8C6"
                bubble_anchor = "e"
                frame_anchor = "e"
                frame_padx = 10
            elif sender == "System":
                bg = "#949494"
                bubble_anchor = "center"
                frame_anchor = "center"
                frame_padx = 0
            else:
                bg = "white"
                bubble_anchor = "w"
                frame_anchor = "w"
                frame_padx = 10

            if sender not in ("You", "System"):
                sender_label = tk.Label(frame, text=sender, font=(
                    "Ubuntu", 11), bg="#E5DDD5", fg="gray")
                sender_label.pack(anchor="w", padx=5)

            bubble = tk.Label(
                frame,
                text=message,
                bg=bg,
                fg="black",
                font=("Ubuntu", 16),
                padx=10,
                pady=5,
                wraplength=400,
                justify="left",
                anchor="w"
            )
            bubble.pack(anchor=bubble_anchor, padx=5)

            time_label = tk.Label(frame, text=timestamp, font=(
                "Ubuntu", 10), bg="#E5DDD5", fg="gray")
            time_label.pack(anchor=bubble_anchor, padx=5)

            frame.pack(anchor=frame_anchor, padx=frame_padx, pady=2)

        self.chat_canvas.update_idletasks()
        self.chat_canvas.yview_moveto(1.0)

    def update_user_list(self, online_users: List[str]) -> None:
        self.known_users.update(online_users)
        self.user_listbox.delete(0, END)
        for user in sorted(self.known_users):
            if user == self.username:
                continue
            is_online = user in online_users
            status_text = "online" if is_online else "offline"
            display_name = f"{user} ({status_text})"
            color = "yellow" if is_online else "red"
            self.user_listbox.insert(END, display_name)
            self.user_listbox.itemconfig(END, {'fg':color})

    def on_close(self):
        try:
            self.client.disconnect()
        except Exception as e:
            print("Failed to close: ", e)
        self.window.destroy()
        sys.exit()

    def upload(self) -> None:
        if not self.active_user:
            return
        if file_path := filedialog.askopenfilename():
            target = self.active_user
            if self.active_user.startswith("#"):
                group_name = self.active_user[1:]
                self.client.send_group_file(group_name, file_path)
            else:
                self.client.send_file(target, file_path)

    def run(self) -> None:
        self.window.mainloop()


if __name__ == "__main__":
    app = ChatGUI()
    app.run()
