import tkinter as tk
from tkinter import scrolledtext, messagebox
from pymongo import MongoClient
import hashlib

# Đảm bảo thay thế 'your_username', 'your_password' với thông tin xác thực MongoDB Atlas của bạn
client = MongoClient('mongodb+srv://akirasumeragi699:nhim1234@cluster0.vnjc8mq.mongodb.net/')
db = client['chat_app']
users = db['users']
messages = db['messages']

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def is_username_exist(username):
    return users.find_one({"username": username}) is not None

def register(username, password):
    if is_username_exist(username):
        messagebox.showerror("Register Failed", "Username already exists. Please try a different username.")
        return False
    
    password_hash = hash_password(password)
    users.insert_one({"username": username, "password": password_hash})
    messagebox.showinfo("Register", "User registered successfully!")
    return True

def login(username, password):
    password_hash = hash_password(password)
    user = users.find_one({"username": username, "password": password_hash})
    return user is not None

def save_message(sender, recipient, message):
    messages.insert_one({"sender": sender, "recipient": recipient, "message": message})

def load_messages_for_user(username):
    cursor = messages.find({"$or": [{"sender": username}, {"recipient": username}]})
    return [f'{"You" if msg["sender"] == username else msg["sender"]} to {msg["recipient"]}: {msg["message"]}' for msg in cursor]

class Peer2PeerChatApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.geometry("1000x800")
        self.title("Chat Application")
        self.initialize_login_screen()

    def initialize_login_screen(self):
        self.login_frame = tk.Frame(self)
        self.login_frame.pack(pady=20)

        self.username_entry = tk.Entry(self.login_frame)
        self.username_entry.grid(row=0, column=1)
        tk.Label(self.login_frame, text="Username:").grid(row=0, column=0)

        self.password_entry = tk.Entry(self.login_frame, show="*")
        self.password_entry.grid(row=1, column=1)
        tk.Label(self.login_frame, text="Password:").grid(row=1, column=0)

        tk.Button(self.login_frame, text="Login", command=self.perform_login).grid(row=2, column=0, columnspan=2, pady=5)
        tk.Button(self.login_frame, text="Register", command=self.perform_register).grid(row=3, column=0, columnspan=2, pady=5)

    def perform_login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        if login(username, password):
            self.login_frame.destroy()
            self.initialize_chat_screen(username)
        else:
            messagebox.showerror("Login Failed", "Incorrect username or password")

    def perform_register(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        if not username or not password:
            messagebox.showerror("Register Failed", "Username and password cannot be empty.")
            return
        if register(username, password):
            self.username_entry.delete(0, tk.END)
            self.password_entry.delete(0, tk.END)

    def initialize_chat_screen(self, username):
        self.chat_frame = tk.Frame(self)
        self.chat_frame.pack(pady=20)

        self.chat_text = scrolledtext.ScrolledText(self.chat_frame, height=15, width=100, state='disabled')
        self.chat_text.pack(pady=5)

        self.refresh_chat(username)

        self.recipient_entry = tk.Entry(self.chat_frame, width=20)
        self.recipient_entry.pack(side=tk.LEFT, padx=5)
        self.recipient_entry.insert(0, "Recipient's username")

        self.msg_entry = tk.Entry(self.chat_frame, width=60)
        self.msg_entry.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5)
        self.msg_entry.insert(0, "Type your message here")

        self.send_button = tk.Button(self.chat_frame, text="Send", command=lambda: self.send_message(username))
        self.send_button.pack(side=tk.LEFT, padx=5)

        self.logout_button = tk.Button(self.chat_frame, text="Logout", command=self.logout)
                # Logout button continued
        self.logout_button.pack(side=tk.RIGHT, padx=5)

    def send_message(self, username):
        recipient = self.recipient_entry.get()
        message = self.msg_entry.get()
        # Clear the input fields for recipient and message
        self.recipient_entry.delete(0, tk.END)
        self.msg_entry.delete(0, tk.END)
        if recipient and message:
            if not is_username_exist(recipient):
                messagebox.showerror("Error", f"The recipient '{recipient}' does not exist.")
                return
            save_message(username, recipient, message)
            self.refresh_chat(username)  # Refresh the chat to display the new message
        else:
            messagebox.showerror("Error", "Recipient and message fields cannot be empty.")

    def refresh_chat(self, username):
        """Refresh the chat text area."""
        self.chat_text.config(state='normal')
        self.chat_text.delete(1.0, tk.END)  # Clear the current chat
        messages = load_messages_for_user(username)
        for message in messages:
            self.chat_text.insert(tk.END, message + "\n")
        self.chat_text.config(state='disabled')

    def logout(self):
        """Handle the logout action."""
        self.chat_frame.destroy()  # Destroy the chat frame and all its widgets
        self.initialize_login_screen()  # Go back to the login screen

if __name__ == "__main__":
    app = Peer2PeerChatApp()
    app.mainloop()