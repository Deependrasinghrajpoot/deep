"""
Advanced Chat Client - Advanced Level
GUI Chat Application with Tkinter
Features: Authentication, Multiple Rooms, Message History, Emojis, Notifications
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import socket
import threading
import json
import base64
from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class ChatClientGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Chat Application")
        self.root.geometry("900x700")
        self.root.configure(bg='#2C3E50')
        
        self.client_socket = None
        self.username = None
        self.current_room = None
        self.connected = False
        self.init_encryption()
        
        # Emoji list
        self.emojis = ['😀', '😃', '😄', '😁', '😅', '😂', '🤣', '😊', '😇', '🙂',
                      '🙃', '😉', '😌', '😍', '🥰', '😘', '😗', '😙', '😚', '😋',
                      '😛', '😝', '😜', '🤪', '🤨', '🧐', '🤓', '😎', '🤩', '🥳',
                      '😏', '😒', '😞', '😔', '😟', '😕', '🙁', '😣', '😖', '😫',
                      '😩', '🥺', '😢', '😭', '😤', '😠', '😡', '🤬', '🤯', '😳',
                      '🥵', '🥶', '😱', '😨', '😰', '😥', '😓', '🤗', '🤔', '🤭',
                      '🤫', '🤥', '😶', '😐', '😑', '😬', '🙄', '😯', '😦', '😧',
                      '😮', '😲', '🥱', '😴', '🤤', '😪', '😵', '🤐', '🥴', '🤢',
                      '🤮', '🤧', '😷', '🤒', '🤕', '🤑', '🤠', '😈', '👿', '👹',
                      '👺', '🤡', '💩', '👻', '💀', '☠️', '👽', '👾', '🤖', '🎃',
                      '😺', '😸', '😹', '😻', '😼', '😽', '🙀', '😿', '😾']
        
        self.show_login_screen()
    
    def init_encryption(self):
        """Initialize encryption (same key as server)"""
        password = b"chat_app_secret_key_2024"
        salt = b"chat_app_salt_2024"
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        self.cipher = Fernet(key)
    
    def show_login_screen(self):
        """Display login/registration screen"""
        # Clear window
        for widget in self.root.winfo_children():
            widget.destroy()
        
        # Main frame
        main_frame = tk.Frame(self.root, bg='#2C3E50', padx=50, pady=50)
        main_frame.pack(expand=True, fill='both')
        
        # Title
        title_label = tk.Label(main_frame, text="Advanced Chat Application", 
                              font=('Arial', 24, 'bold'), bg='#2C3E50', fg='#ECF0F1')
        title_label.pack(pady=(0, 30))
        
        # Login frame
        login_frame = tk.Frame(main_frame, bg='#34495E', padx=30, pady=30, relief=tk.RAISED, bd=2)
        login_frame.pack(expand=True)
        
        tk.Label(login_frame, text="Username:", font=('Arial', 12), 
                bg='#34495E', fg='#ECF0F1').grid(row=0, column=0, sticky='w', pady=10)
        self.username_entry = tk.Entry(login_frame, font=('Arial', 12), width=25)
        self.username_entry.grid(row=0, column=1, pady=10, padx=10)
        
        tk.Label(login_frame, text="Password:", font=('Arial', 12), 
                bg='#34495E', fg='#ECF0F1').grid(row=1, column=0, sticky='w', pady=10)
        self.password_entry = tk.Entry(login_frame, font=('Arial', 12), 
                                       show='*', width=25)
        self.password_entry.grid(row=1, column=1, pady=10, padx=10)
        
        tk.Label(login_frame, text="Server:", font=('Arial', 12), 
                bg='#34495E', fg='#ECF0F1').grid(row=2, column=0, sticky='w', pady=10)
        self.server_entry = tk.Entry(login_frame, font=('Arial', 12), width=25)
        self.server_entry.insert(0, 'localhost:8888')
        self.server_entry.grid(row=2, column=1, pady=10, padx=10)
        
        # Buttons
        button_frame = tk.Frame(login_frame, bg='#34495E')
        button_frame.grid(row=3, column=0, columnspan=2, pady=20)
        
        login_btn = tk.Button(button_frame, text="Login", font=('Arial', 12, 'bold'),
                             bg='#3498DB', fg='white', width=12, command=self.login)
        login_btn.pack(side=tk.LEFT, padx=5)
        
        register_btn = tk.Button(button_frame, text="Register", font=('Arial', 12, 'bold'),
                                bg='#27AE60', fg='white', width=12, command=self.register)
        register_btn.pack(side=tk.LEFT, padx=5)
        
        self.username_entry.focus()
        self.password_entry.bind('<Return>', lambda e: self.login())
        self.username_entry.bind('<Return>', lambda e: self.password_entry.focus())
    
    def connect_to_server(self):
        """Connect to chat server"""
        try:
            server_info = self.server_entry.get().split(':')
            host = server_info[0]
            port = int(server_info[1]) if len(server_info) > 1 else 8888
            
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((host, port))
            self.connected = True
            
            # Start receiving thread
            receive_thread = threading.Thread(target=self.receive_messages)
            receive_thread.daemon = True
            receive_thread.start()
            
            return True
        except Exception as e:
            messagebox.showerror("Connection Error", f"Failed to connect: {str(e)}")
            return False
    
    def login(self):
        """Handle user login"""
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        
        if not username or not password:
            messagebox.showerror("Error", "Please enter username and password")
            return
        
        if not self.connect_to_server():
            return
        
        # Send login request
        login_msg = json.dumps({
            'type': 'login',
            'username': username,
            'password': password
        })
        self.client_socket.send(login_msg.encode('utf-8'))
        self.username = username
    
    def register(self):
        """Handle user registration"""
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        
        if not username or not password:
            messagebox.showerror("Error", "Please enter username and password")
            return
        
        if not self.connect_to_server():
            return
        
        # Send registration request
        register_msg = json.dumps({
            'type': 'register',
            'username': username,
            'password': password
        })
        self.client_socket.send(register_msg.encode('utf-8'))
        self.username = username
    
    def receive_messages(self):
        """Receive messages from server"""
        while self.connected:
            try:
                data = self.client_socket.recv(4096).decode('utf-8')
                if not data:
                    break
                
                try:
                    message = json.loads(data)
                    msg_type = message.get('type')
                    
                    if msg_type == 'login_response':
                        if message.get('success'):
                            self.root.after(0, self.show_chat_interface, message.get('rooms', []))
                        else:
                            self.root.after(0, messagebox.showerror, "Login Failed", 
                                          message.get('message', 'Invalid credentials'))
                            self.connected = False
                    
                    elif msg_type == 'register_response':
                        if message.get('success'):
                            self.root.after(0, messagebox.showinfo, "Registration", 
                                          "Registration successful! Please login.")
                            self.connected = False
                        else:
                            self.root.after(0, messagebox.showerror, "Registration Failed", 
                                          message.get('message', 'Registration failed'))
                    
                    elif msg_type == 'room_joined':
                        self.root.after(0, self.on_room_joined, message)
                    
                    elif msg_type == 'message':
                        self.root.after(0, self.display_message, message)
                    
                    elif msg_type == 'user_joined':
                        self.root.after(0, self.on_user_joined, message.get('username'))
                    
                    elif msg_type == 'user_left':
                        self.root.after(0, self.on_user_left, message.get('username'))
                    
                except json.JSONDecodeError:
                    continue
                    
            except Exception as e:
                print(f"Error receiving message: {e}")
                break
    
    def show_chat_interface(self, rooms):
        """Display main chat interface"""
        # Clear window
        for widget in self.root.winfo_children():
            widget.destroy()
        
        # Main container
        main_container = tk.PanedWindow(self.root, orient=tk.HORIZONTAL, bg='#2C3E50')
        main_container.pack(fill=tk.BOTH, expand=True)
        
        # Left panel - Rooms and Users
        left_panel = tk.Frame(main_container, bg='#34495E', width=200)
        main_container.add(left_panel, minsize=200)
        
        # Rooms section
        rooms_label = tk.Label(left_panel, text="Chat Rooms", font=('Arial', 14, 'bold'),
                              bg='#34495E', fg='#ECF0F1')
        rooms_label.pack(pady=10)
        
        self.rooms_listbox = tk.Listbox(left_panel, font=('Arial', 11), bg='#2C3E50', 
                                       fg='#ECF0F1', selectbackground='#3498DB')
        self.rooms_listbox.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        for room in rooms:
            self.rooms_listbox.insert(tk.END, room)
        
        self.rooms_listbox.bind('<<ListboxSelect>>', self.on_room_select)
        
        # Users section
        users_label = tk.Label(left_panel, text="Online Users", font=('Arial', 14, 'bold'),
                              bg='#34495E', fg='#ECF0F1')
        users_label.pack(pady=(10, 5))
        
        self.users_listbox = tk.Listbox(left_panel, font=('Arial', 11), bg='#2C3E50',
                                       fg='#ECF0F1', height=10)
        self.users_listbox.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Right panel - Chat area
        right_panel = tk.Frame(main_container, bg='#ECF0F1')
        main_container.add(right_panel, minsize=500)
        
        # Chat header
        header_frame = tk.Frame(right_panel, bg='#3498DB', height=50)
        header_frame.pack(fill=tk.X)
        header_frame.pack_propagate(False)
        
        self.room_label = tk.Label(header_frame, text="Select a room", font=('Arial', 16, 'bold'),
                                   bg='#3498DB', fg='white')
        self.room_label.pack(side=tk.LEFT, padx=15, pady=15)
        
        logout_btn = tk.Button(header_frame, text="Logout", font=('Arial', 10),
                              bg='#E74C3C', fg='white', command=self.logout)
        logout_btn.pack(side=tk.RIGHT, padx=15, pady=10)
        
        # Chat messages area
        self.chat_display = scrolledtext.ScrolledText(right_panel, font=('Arial', 11),
                                                      bg='white', fg='#2C3E50', wrap=tk.WORD,
                                                      state=tk.DISABLED)
        self.chat_display.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Configure tags for message styling
        self.chat_display.tag_config('timestamp', foreground='gray', font=('Arial', 9))
        self.chat_display.tag_config('username', foreground='#3498DB', font=('Arial', 11, 'bold'))
        self.chat_display.tag_config('message', foreground='#2C3E50', font=('Arial', 11))
        self.chat_display.tag_config('system', foreground='green', font=('Arial', 10, 'italic'))
        
        # Input area
        input_frame = tk.Frame(right_panel, bg='#ECF0F1')
        input_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Emoji button
        emoji_btn = tk.Button(input_frame, text="😀", font=('Arial', 16),
                             command=self.show_emoji_picker, bg='#ECF0F1', relief=tk.FLAT)
        emoji_btn.pack(side=tk.LEFT, padx=5)
        
        # Message entry
        self.message_entry = tk.Entry(input_frame, font=('Arial', 12), bg='white')
        self.message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.message_entry.bind('<Return>', lambda e: self.send_message())
        
        # Send button
        send_btn = tk.Button(input_frame, text="Send", font=('Arial', 12, 'bold'),
                            bg='#3498DB', fg='white', width=10, command=self.send_message)
        send_btn.pack(side=tk.LEFT, padx=5)
        
        # Auto-join General room
        if rooms:
            self.join_room('General')
    
    def show_emoji_picker(self):
        """Show emoji picker window"""
        emoji_window = tk.Toplevel(self.root)
        emoji_window.title("Emoji Picker")
        emoji_window.geometry("400x300")
        emoji_window.configure(bg='#ECF0F1')
        
        emoji_frame = tk.Frame(emoji_window, bg='#ECF0F1')
        emoji_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        row = 0
        col = 0
        for emoji in self.emojis:
            btn = tk.Button(emoji_frame, text=emoji, font=('Arial', 16),
                           command=lambda e=emoji: self.insert_emoji(e, emoji_window),
                           bg='white', relief=tk.FLAT, width=3, height=1)
            btn.grid(row=row, column=col, padx=2, pady=2)
            col += 1
            if col > 9:
                col = 0
                row += 1
    
    def insert_emoji(self, emoji, window):
        """Insert emoji into message entry"""
        self.message_entry.insert(tk.END, emoji)
        window.destroy()
        self.message_entry.focus()
    
    def on_room_select(self, event):
        """Handle room selection"""
        selection = self.rooms_listbox.curselection()
        if selection:
            room = self.rooms_listbox.get(selection[0])
            self.join_room(room)
    
    def join_room(self, room):
        """Join a chat room"""
        if self.current_room == room:
            return
        
        if self.current_room:
            # Leave current room
            leave_msg = json.dumps({
                'type': 'leave_room',
                'room': self.current_room
            })
            self.client_socket.send(leave_msg.encode('utf-8'))
        
        self.current_room = room
        self.room_label.config(text=f"Room: {room}")
        
        # Clear chat display
        self.chat_display.config(state=tk.NORMAL)
        self.chat_display.delete('1.0', tk.END)
        self.chat_display.config(state=tk.DISABLED)
        
        # Send join room message
        join_msg = json.dumps({
            'type': 'join_room',
            'room': room
        })
        self.client_socket.send(join_msg.encode('utf-8'))
    
    def on_room_joined(self, message):
        """Handle room joined response"""
        room = message.get('room')
        users = message.get('users', [])
        history = message.get('history', [])
        
        # Update users list
        self.users_listbox.delete(0, tk.END)
        for user in users:
            self.users_listbox.insert(tk.END, user)
        
        # Display message history
        self.chat_display.config(state=tk.NORMAL)
        for msg in history:
            timestamp = msg.get('timestamp', '')[:19] if len(msg.get('timestamp', '')) > 19 else msg.get('timestamp', '')
            username = msg.get('username', 'Unknown')
            message_text = msg.get('message', '')
            
            self.chat_display.insert(tk.END, f"[{timestamp}] ", 'timestamp')
            self.chat_display.insert(tk.END, f"{username}: ", 'username')
            self.chat_display.insert(tk.END, f"{message_text}\n", 'message')
        
        self.chat_display.config(state=tk.DISABLED)
        self.chat_display.see(tk.END)
    
    def send_message(self):
        """Send message to server"""
        message = self.message_entry.get().strip()
        if not message or not self.current_room:
            return
        
        msg_data = json.dumps({
            'type': 'message',
            'message': message
        })
        self.client_socket.send(msg_data.encode('utf-8'))
        self.message_entry.delete(0, tk.END)
    
    def display_message(self, message):
        """Display received message"""
        try:
            encrypted_msg = message.get('message', '')
            # Decrypt message
            decrypted_msg = self.cipher.decrypt(encrypted_msg.encode()).decode()
            username = message.get('username', 'Unknown')
            timestamp = message.get('timestamp', '')
            
            self.chat_display.config(state=tk.NORMAL)
            self.chat_display.insert(tk.END, f"[{timestamp}] ", 'timestamp')
            self.chat_display.insert(tk.END, f"{username}: ", 'username')
            self.chat_display.insert(tk.END, f"{decrypted_msg}\n", 'message')
            self.chat_display.config(state=tk.DISABLED)
            self.chat_display.see(tk.END)
            
            # Notification (sound or system notification could be added here)
            if username != self.username:
                self.root.bell()  # System beep
        except Exception as e:
            print(f"Error displaying message: {e}")
    
    def on_user_joined(self, username):
        """Handle user joined notification"""
        self.chat_display.config(state=tk.NORMAL)
        self.chat_display.insert(tk.END, f"{username} joined the room\n", 'system')
        self.chat_display.config(state=tk.DISABLED)
        self.chat_display.see(tk.END)
        
        # Update users list (simplified - in production, server should send updated list)
    
    def on_user_left(self, username):
        """Handle user left notification"""
        self.chat_display.config(state=tk.NORMAL)
        self.chat_display.insert(tk.END, f"{username} left the room\n", 'system')
        self.chat_display.config(state=tk.DISABLED)
        self.chat_display.see(tk.END)
    
    def logout(self):
        """Handle user logout"""
        if self.current_room:
            leave_msg = json.dumps({
                'type': 'leave_room',
                'room': self.current_room
            })
            try:
                self.client_socket.send(leave_msg.encode('utf-8'))
            except:
                pass
        
        self.connected = False
        if self.client_socket:
            self.client_socket.close()
        
        self.show_login_screen()

if __name__ == "__main__":
    root = tk.Tk()
    app = ChatClientGUI(root)
    root.mainloop()

