import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import os
import subprocess
import threading
import queue
import winsound
from tkinterdnd2 import DND_FILES, TkinterDnD
import time
from typing import Optional, List


class RARPasswordTester:
    def __init__(self, root):
        self.root = root
        self.root.title("WinRAR Password Tester")
        self.root.geometry("580x465")
        self.root.resizable(False, False)

        # State variables
        self.password_queue = queue.Queue()
        self.tested_passwords = 0
        self.total_passwords = 0
        self.password_found = False
        self.pause_event = threading.Event()
        self.pause_event.set()  # Initially not paused
        self.stop_event = threading.Event()
        self.threads: List[threading.Thread] = []
        self.lock = threading.Lock()
        self.start_time = 0
        self.unrar_path = ""
        self.current_password = ""

        # GUI Setup
        self.setup_gui()

        # Configure styles
        self.style = ttk.Style()
        self.style.configure("TButton", padding=6)
        self.style.configure("TEntry", padding=5)
        self.style.configure("TLabel", padding=5)

    def setup_gui(self):
        # Main container
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # File Path
        ttk.Label(main_frame, text="RAR File Path:").grid(
            row=0, column=0, padx=5, pady=5, sticky="e"
        )
        self.entry_file_path = ttk.Entry(main_frame, width=50)
        self.entry_file_path.grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(main_frame, text="Browse", command=self.browse_file).grid(
            row=0, column=2, padx=5
        )

        # Dictionary Path
        ttk.Label(main_frame, text="Dictionary File Path:").grid(
            row=1, column=0, padx=5, pady=5, sticky="e"
        )
        self.entry_dict_path = ttk.Entry(main_frame, width=50)
        self.entry_dict_path.grid(row=1, column=1, padx=5, pady=5)
        ttk.Button(main_frame, text="Browse", command=self.browse_dictionary).grid(
            row=1, column=2, padx=5
        )

        # UnRAR Path
        ttk.Label(main_frame, text="UnRAR Path:").grid(
            row=2, column=0, padx=5, pady=5, sticky="e"
        )
        self.entry_unrar_path = ttk.Entry(main_frame, width=50)
        self.entry_unrar_path.grid(row=2, column=1, padx=5, pady=5)
        ttk.Button(main_frame, text="Auto-Detect", command=self.auto_detect_unrar).grid(
            row=2, column=2, padx=5
        )

        # Threads
        ttk.Label(main_frame, text="Threads:").grid(
            row=3, column=0, padx=5, pady=5, sticky="e"
        )
        self.thread_entry = ttk.Entry(main_frame, width=10)
        self.thread_entry.insert(0, "4")
        self.thread_entry.grid(row=3, column=1, padx=5, pady=5, sticky="w")

        # Control Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=4, column=0, columnspan=3, pady=10)

        self.btn_start = ttk.Button(
            button_frame, text="Start", command=self.start_testing
        )
        self.btn_start.pack(side=tk.LEFT, padx=5)

        self.btn_pause = ttk.Button(
            button_frame, text="Pause", command=self.toggle_pause, state=tk.DISABLED
        )
        self.btn_pause.pack(side=tk.LEFT, padx=5)

        self.btn_stop = ttk.Button(
            button_frame, text="Stop", command=self.stop_testing, state=tk.DISABLED
        )
        self.btn_stop.pack(side=tk.LEFT, padx=5)

        # Progress
        self.status_label = ttk.Label(main_frame, text="Ready")
        self.status_label.grid(row=5, column=0, columnspan=3, pady=5)

        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(
            main_frame, variable=self.progress_var, length=500, mode="determinate"
        )
        self.progress_bar.grid(row=6, column=0, columnspan=3, pady=5)

        # Current Password
        self.current_password_label = ttk.Label(
            main_frame, text="Current password: None", wraplength=500
        )
        self.current_password_label.grid(row=7, column=0, columnspan=3, pady=5)

        # Time Elapsed
        self.time_label = ttk.Label(main_frame, text="Time elapsed: 00:00:00")
        self.time_label.grid(row=8, column=0, columnspan=3, pady=5)

        # Info
        info_frame = ttk.Frame(main_frame)
        info_frame.grid(row=9, column=0, columnspan=3, pady=10)

        info_label = ttk.Label(
            info_frame,
            text="RAR Password Cracker - Developed by Dev Ashrafee\n"
            "Email: dev.ashrafee@gmail.com | WhatsApp: +8801612381085",
            justify=tk.CENTER,
        )
        info_label.pack()

        linkedin_label = ttk.Label(
            info_frame, text="LinkedIn: Click here", foreground="blue", cursor="hand2"
        )
        linkedin_label.pack()
        linkedin_label.bind(
            "<Button-1>",
            lambda e: os.system(
                "start https://www.linkedin.com/in/abdullahalashrafee/"
            ),
        )

        # Drag and Drop support
        self.entry_file_path.drop_target_register(DND_FILES)
        self.entry_file_path.dnd_bind(
            "<<Drop>>", lambda e: self.drop_file(e, self.entry_file_path)
        )

        self.entry_dict_path.drop_target_register(DND_FILES)
        self.entry_dict_path.dnd_bind(
            "<<Drop>>", lambda e: self.drop_file(e, self.entry_dict_path)
        )

    def drop_file(self, event, entry):
        file_path = event.data.strip()
        if file_path.startswith("{") and file_path.endswith("}"):
            file_path = file_path[1:-1]
        entry.delete(0, tk.END)
        entry.insert(0, file_path)

    def browse_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("RAR files", "*.rar")])
        if file_path:
            self.entry_file_path.delete(0, tk.END)
            self.entry_file_path.insert(0, file_path)

    def browse_dictionary(self):
        dict_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if dict_path:
            self.entry_dict_path.delete(0, tk.END)
            self.entry_dict_path.insert(0, dict_path)

    def auto_detect_unrar(self):
        possible_paths = [
            os.path.join(os.getcwd(), "unrar.exe"),
            os.path.join(os.getcwd(), "UnRAR.exe"),
            "C:\\Program Files\\WinRAR\\unrar.exe",
            "C:\\Program Files (x86)\\WinRAR\\unrar.exe",
            "C:\\Program Files\\WinRAR\\UnRAR.exe",
            "C:\\Program Files (x86)\\WinRAR\\UnRAR.exe",
        ]

        for path in possible_paths:
            if os.path.isfile(path):
                self.entry_unrar_path.delete(0, tk.END)
                self.entry_unrar_path.insert(0, path)
                return

        messagebox.showwarning(
            "Not Found", "Could not auto-detect unrar.exe. Please specify manually."
        )

    def validate_inputs(self) -> bool:
        rar_path = self.entry_file_path.get().strip()
        dict_path = self.entry_dict_path.get().strip()
        unrar_path = self.entry_unrar_path.get().strip()
        threads = self.thread_entry.get().strip()

        # Check RAR file
        if not rar_path:
            messagebox.showerror("Error", "Please select a RAR file.")
            return False
        if not os.path.isfile(rar_path):
            messagebox.showerror("Error", "Invalid RAR file path.")
            return False

        # Check dictionary file
        if not dict_path:
            messagebox.showerror("Error", "Please select a dictionary file.")
            return False
        if not os.path.isfile(dict_path):
            messagebox.showerror("Error", "Invalid dictionary file path.")
            return False

        # Check unrar.exe
        if not unrar_path:
            messagebox.showerror("Error", "Please specify the path to unrar.exe.")
            return False
        if not os.path.isfile(unrar_path):
            messagebox.showerror("Error", "unrar.exe not found at the specified path.")
            return False

        # Check threads
        if not threads.isdigit() or int(threads) <= 0:
            messagebox.showerror(
                "Error", "Please enter a valid number of threads (>= 1)."
            )
            return False

        return True

    def start_testing(self):
        if not self.validate_inputs():
            return

        # Reset state
        self.password_found = False
        self.stop_event.clear()
        self.pause_event.set()
        self.tested_passwords = 0
        self.total_passwords = 0
        self.start_time = time.time()
        self.unrar_path = self.entry_unrar_path.get().strip()

        # Clear queue and threads
        with self.lock:
            while not self.password_queue.empty():
                self.password_queue.get()
        self.threads.clear()

        # Load passwords into queue
        try:
            with open(
                self.entry_dict_path.get().strip(),
                "r",
                encoding="utf-8",
                errors="ignore",
            ) as f:
                for line in f:
                    password = line.strip()
                    if password:  # Skip empty lines
                        self.password_queue.put(password)
                        self.total_passwords += 1
        except Exception as e:
            messagebox.showerror("Error", f"Failed to read dictionary file: {str(e)}")
            return

        if self.total_passwords == 0:
            messagebox.showerror(
                "Error", "Dictionary file is empty or contains no valid passwords."
            )
            return

        # Start worker threads
        num_threads = min(int(self.thread_entry.get().strip()), self.total_passwords)
        for _ in range(num_threads):
            thread = threading.Thread(target=self.worker)
            thread.daemon = True
            thread.start()
            self.threads.append(thread)

        # Update UI
        self.btn_start.config(state=tk.DISABLED)
        self.btn_pause.config(state=tk.NORMAL)
        self.btn_stop.config(state=tk.NORMAL)
        self.update_status()
        self.update_time_elapsed()

    def worker(self):
        rar_path = self.entry_file_path.get().strip()

        while (
            not self.password_queue.empty()
            and not self.password_found
            and not self.stop_event.is_set()
        ):
            self.pause_event.wait()  # Pause if event is cleared

            try:
                password = self.password_queue.get_nowait()
            except queue.Empty:
                break

            with self.lock:
                self.current_password = password
                self.tested_passwords += 1
                self.update_status()

            # Test password
            try:
                result = subprocess.run(
                    [self.unrar_path, "t", "-p" + password, rar_path],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                )

                if "All OK" in result.stdout.decode("utf-8", errors="ignore"):
                    with self.lock:
                        self.password_found = True
                        self.current_password = f"Found: {password}"
                        self.update_status()

                    winsound.Beep(1000, 500)
                    messagebox.showinfo("Success", f"Password found: {password}")
                    break

            except Exception as e:
                with self.lock:
                    self.current_password = f"Error testing password: {str(e)}"
                    self.update_status()
                continue

    def toggle_pause(self):
        if self.pause_event.is_set():
            self.pause_event.clear()
            self.btn_pause.config(text="Resume")
        else:
            self.pause_event.set()
            self.btn_pause.config(text="Pause")

    def stop_testing(self):
        self.stop_event.set()
        self.pause_event.set()  # Resume if paused to allow threads to exit

        # Wait for threads to finish
        for thread in self.threads:
            thread.join(timeout=1)

        self.threads.clear()
        self.reset_ui()

    def reset_ui(self):
        self.btn_start.config(state=tk.NORMAL)
        self.btn_pause.config(state=tk.DISABLED)
        self.btn_stop.config(state=tk.DISABLED)
        self.btn_pause.config(text="Pause")

    def update_status(self):
        if self.total_passwords > 0:
            progress = (self.tested_passwords / self.total_passwords) * 100
            remaining = 100 - progress
            self.status_label.config(
                text=f"Passwords: {self.tested_passwords}/{self.total_passwords} | "
                f"Progress: {progress:.2f}% | Remaining: {remaining:.2f}%"
            )
            self.progress_var.set(progress)
        else:
            self.status_label.config(text="Ready")
            self.progress_var.set(0)

        self.current_password_label.config(
            text=f"Current password: {self.current_password}"
        )
        self.root.update_idletasks()

    def update_time_elapsed(self):
        if not self.password_found and not self.stop_event.is_set():
            elapsed = int(time.time() - self.start_time)
            hours, remainder = divmod(elapsed, 3600)
            minutes, seconds = divmod(remainder, 60)
            self.time_label.config(
                text=f"Time elapsed: {hours:02d}:{minutes:02d}:{seconds:02d}"
            )
            self.root.after(1000, self.update_time_elapsed)


if __name__ == "__main__":
    root = TkinterDnD.Tk()
    app = RARPasswordTester(root)
    root.mainloop()
