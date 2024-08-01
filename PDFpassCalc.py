import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import PyPDF2
import itertools
import string
import threading
import concurrent.futures
import queue

class PDFCrackerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("PDF Password Cracker")

        # Create widgets
        self.create_widgets()

        # Queue for updating GUI from the background thread
        self.queue = queue.Queue()
        self.root.after(100, self.process_queue)

    def create_widgets(self):
        # PDF file selection
        self.pdf_label = tk.Label(self.root, text="Select PDF file:")
        self.pdf_label.pack()
        self.pdf_button = tk.Button(self.root, text="Browse", command=self.browse_file)
        self.pdf_button.pack()
        self.pdf_path_label = tk.Label(self.root, text="")
        self.pdf_path_label.pack()

        # Character set selection
        self.charset_label = tk.Label(self.root, text="Select Character Set:")
        self.charset_label.pack()
        self.charset_var = tk.StringVar(value="Alphabet only")
        self.charset_options = [
            "Alphabet only",
            "Alphabet + Numbers",
            "Numbers only",
            "Unknown",
            "Lowercase only",
            "Uppercase only",
            "Alphabet + Numbers + Symbols"
        ]
        self.charset_menu = tk.OptionMenu(self.root, self.charset_var, *self.charset_options)
        self.charset_menu.pack()

        # Password length selection
        self.length_label = tk.Label(self.root, text="Enter Password Length (or Unknown):")
        self.length_label.pack()
        self.length_entry = tk.Entry(self.root)
        self.length_entry.pack()

        # Advanced settings
        self.adv_settings_label = tk.Label(self.root, text="Advanced Settings:")
        self.adv_settings_label.pack()

        self.prefix_label = tk.Label(self.root, text="Prefix (e.g., first n characters):")
        self.prefix_label.pack()
        self.prefix_entry = tk.Entry(self.root)
        self.prefix_entry.pack()

        self.prefix_length_label = tk.Label(self.root, text="Prefix Length:")
        self.prefix_length_label.pack()
        self.prefix_length_entry = tk.Entry(self.root)
        self.prefix_length_entry.pack()

        self.suffix_label = tk.Label(self.root, text="Suffix (e.g., last m characters):")
        self.suffix_label.pack()
        self.suffix_entry = tk.Entry(self.root)
        self.suffix_entry.pack()

        self.suffix_length_label = tk.Label(self.root, text="Suffix Length:")
        self.suffix_length_label.pack()
        self.suffix_length_entry = tk.Entry(self.root)
        self.suffix_length_entry.pack()

        # Start button
        self.start_button = tk.Button(self.root, text="Start Cracking", command=self.start_cracking)
        self.start_button.pack()

        # Progress bar
        self.progress = ttk.Progressbar(self.root, orient="horizontal", length=300, mode="determinate")
        self.progress.pack(pady=10)
        self.progress_label = tk.Label(self.root, text="")
        self.progress_label.pack()

    def browse_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("PDF files", "*.pdf")])
        if file_path:
            self.pdf_path_label.config(text=file_path)
            self.pdf_path = file_path

    def start_cracking(self):
        if not hasattr(self, 'pdf_path'):
            messagebox.showerror("Error", "Please select a PDF file.")
            return

        # Get user inputs
        charset_option = self.charset_var.get()
        length = self.length_entry.get()
        prefix = self.prefix_entry.get()
        prefix_length = self.prefix_length_entry.get()
        suffix = self.suffix_entry.get()
        suffix_length = self.suffix_length_entry.get()

        # Determine charset based on user input
        charset = ""
        if charset_option == "Alphabet only":
            charset = string.ascii_letters
        elif charset_option == "Alphabet + Numbers":
            charset = string.ascii_letters + string.digits
        elif charset_option == "Numbers only":
            charset = string.digits
        elif charset_option == "Lowercase only":
            charset = string.ascii_lowercase
        elif charset_option == "Uppercase only":
            charset = string.ascii_uppercase
        elif charset_option == "Alphabet + Numbers + Symbols":
            charset = string.ascii_letters + string.digits + string.punctuation
        elif charset_option == "Unknown":
            charset = string.ascii_letters + string.digits + string.punctuation

        # Determine password length
        if length.isdigit():
            length = int(length)
        else:
            length = None

        # Determine prefix and suffix length
        if prefix_length.isdigit():
            prefix_length = int(prefix_length)
        else:
            prefix_length = None

        if suffix_length.isdigit():
            suffix_length = int(suffix_length)
        else:
            suffix_length = None

        # Start password cracking in a separate thread
        threading.Thread(target=self.crack_password, args=(charset, length, prefix, prefix_length, suffix, suffix_length)).start()

    def crack_password(self, charset, length, prefix, prefix_length, suffix, suffix_length):
        pdf_reader = PyPDF2.PdfReader(self.pdf_path)
        if not pdf_reader.is_encrypted:
            self.queue.put(("info", "The PDF is not encrypted."))
            return

        # Load and filter weak passwords
        weak_passwords = self.load_weak_passwords('weakpasslist.txt', charset, length)
        total_combinations = len(weak_passwords)
        tried_combinations = 0

        for pwd in weak_passwords:
            tried_combinations += 1
            self.queue.put(("progress", tried_combinations, total_combinations))
            if self.try_password(pdf_reader, pwd):
                self.queue.put(("info", f"Password found: {pwd}"))
                return

        # Then try common weak passwords
        common_weak_passwords = [
            "1234", "1111", "password", "abc123", "qwerty",
            "letmein", "welcome", "admin", "user", "pass"
        ]

        for pwd in common_weak_passwords:
            tried_combinations += 1
            self.queue.put(("progress", tried_combinations, total_combinations))
            if self.try_password(pdf_reader, pwd):
                self.queue.put(("info", f"Password found: {pwd}"))
                return

        # Then start brute force attack
        total_combinations += self.calculate_total_combinations(charset, length, prefix, prefix_length, suffix, suffix_length)

        with concurrent.futures.ThreadPoolExecutor() as executor:
            futures = []
            if length:
                for pwd in self.generate_passwords(charset, length, prefix, prefix_length, suffix, suffix_length):
                    futures.append(executor.submit(self.try_password, pdf_reader, pwd))
                    tried_combinations += 1
                    self.queue.put(("progress", tried_combinations, total_combinations))
            else:
                for l in range(1, 20):  # 20 is an arbitrary choice, can be adjusted
                    for pwd in self.generate_passwords(charset, l, prefix, prefix_length, suffix, suffix_length):
                        futures.append(executor.submit(self.try_password, pdf_reader, pwd))
                        tried_combinations += 1
                        self.queue.put(("progress", tried_combinations, total_combinations))

            for future in concurrent.futures.as_completed(futures):
                if future.result():
                    return

        self.queue.put(("info", "Failed to crack the password."))

    def try_password(self, pdf_reader, password):
        try:
            pdf_reader.decrypt(password)
            # Attempt to read a page to verify decryption success
            pdf_reader.pages[0]
            return True
        except:
            return False

    def update_progress(self, tried, total):
        if total:
            progress = (tried / total) * 100
            self.progress["value"] = progress
            self.progress_label.config(text=f"Progress: {tried}/{total} ({progress:.2f}%)")
        else:
            self.progress_label.config(text=f"Progress: Tried {tried} passwords")

    def calculate_total_combinations(self, charset, length, prefix, prefix_length, suffix, suffix_length):
        if prefix:
            length -= len(prefix)
        if suffix:
            length -= len(suffix)
        if prefix_length:
            length -= prefix_length
        if suffix_length:
            length -= suffix_length
        return sum(len(charset) ** i for i in range(1, length + 1)) if length else None

    def generate_passwords(self, charset, length, prefix, prefix_length, suffix, suffix_length):
        if prefix:
            base_prefix = prefix
            length -= len(prefix)
        elif prefix_length:
            base_prefix = ''.join(itertools.islice(itertools.cycle(charset), prefix_length))
            length -= prefix_length
        else:
            base_prefix = ""

        if suffix:
            base_suffix = suffix
            length -= len(suffix)
        elif suffix_length:
            base_suffix = ''.join(itertools.islice(itertools.cycle(charset), suffix_length))
            length -= suffix_length
        else:
            base_suffix = ""

        for pwd in itertools.product(charset, repeat=length):
            pwd = ''.join(pwd)
            password = base_prefix + pwd + base_suffix
            yield password

    def load_weak_passwords(self, filename, charset, length):
        try:
            with open(filename, 'r') as file:
                weak_passwords = [line.strip() for line in file]
            # Filter weak passwords by charset and length
            filtered_passwords = [
                pwd for pwd in weak_passwords
                if all(char in charset for char in pwd) and (length is None or len(pwd) == length)
            ]
            return filtered_passwords
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load weak password list: {e}")
            return []

    def process_queue(self):
        try:
            while True:
                msg = self.queue.get_nowait()
                if msg[0] == "info":
                    messagebox.showinfo("Result", msg[1])
                elif msg[0] == "progress":
                    self.update_progress(msg[1], msg[2])
        except queue.Empty:
            pass
        self.root.after(100, self.process_queue)

if __name__ == "__main__":
    root = tk.Tk()
    app = PDFCrackerApp(root)
    root.mainloop()
