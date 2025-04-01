import tkinter as tk
from tkinter import filedialog, messagebox, ttk, StringVar, IntVar, BooleanVar, LEFT
import os
import subprocess
import threading
import queue
import winsound
from tkinterdnd2 import DND_FILES, TkinterDnD
import time
import json
import string
import itertools
from typing import List, Dict, Any, Optional
import sys
import webbrowser


class ToolTip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tip_window = None
        self.widget.bind("<Enter>", self.showtip)
        self.widget.bind("<Leave>", self.hidetip)

    def showtip(self, event=None):
        if self.tip_window or not self.text:
            return
        x, y, _, _ = self.widget.bbox("insert")
        x += self.widget.winfo_rootx() + 25
        y += self.widget.winfo_rooty() + 25
        self.tip_window = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")
        label = tk.Label(
            tw,
            text=self.text,
            justify=tk.LEFT,
            background="#ffffe0",
            relief=tk.SOLID,
            borderwidth=1,
            font=("tahoma", "8", "normal"),
        )
        label.pack(ipadx=1)

    def hidetip(self, event=None):
        tw = self.tip_window
        self.tip_window = None
        if tw:
            tw.destroy()


class RARPasswordTester:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced RAR Password Cracker")
        self.root.geometry("650x650")
        self.root.resizable(False, False)

        # State variables
        self.password_queue = queue.Queue()
        self.tested_passwords = 0
        self.total_passwords = 0
        self.password_found = False
        self.pause_event = threading.Event()
        self.pause_event.set()
        self.stop_event = threading.Event()
        self.threads: List[threading.Thread] = []
        self.lock = threading.Lock()
        self.start_time = 0
        self.unrar_path = ""
        self.current_password = ""
        self.batch_files = []
        self.current_batch_index = 0
        self.progress_file = os.path.join(
            os.path.dirname(sys.argv[0]), "cracker_progress.json"
        )

        # Mode variables
        self.mode_var = StringVar(value="dictionary")
        self.batch_mode_var = BooleanVar(value=False)
        self.brute_force_config = {
            "min_len": IntVar(value=4),
            "max_len": IntVar(value=6),
            "use_lower": BooleanVar(value=True),
            "use_upper": BooleanVar(value=False),
            "use_digits": BooleanVar(value=True),
            "use_special": BooleanVar(value=False),
        }

        self.setup_gui()
        self.setup_styles()

    def setup_styles(self):
        self.style = ttk.Style()
        self.style.configure("TButton", padding=6)
        self.style.configure("TEntry", padding=5)
        self.style.configure("TLabel", padding=5)
        self.style.configure("TLabelframe", padding=10)

    def setup_gui(self):
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Mode Selection
        mode_frame = ttk.LabelFrame(main_frame, text="Attack Mode")
        mode_frame.pack(fill=tk.X, pady=5)

        ttk.Radiobutton(
            mode_frame,
            text="Dictionary Attack",
            variable=self.mode_var,
            value="dictionary",
            command=self.toggle_attack_mode,
        ).pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(
            mode_frame,
            text="Brute Force",
            variable=self.mode_var,
            value="bruteforce",
            command=self.toggle_attack_mode,
        ).pack(side=tk.LEFT, padx=5)

        # File Selection
        file_frame = ttk.LabelFrame(main_frame, text="File Selection")
        file_frame.pack(fill=tk.X, pady=5)

        # RAR File Path
        ttk.Label(file_frame, text="RAR File:").grid(
            row=0, column=0, padx=5, pady=5, sticky="e"
        )
        self.entry_file_path = ttk.Entry(file_frame, width=50)
        self.entry_file_path.grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(file_frame, text="Browse", command=self.browse_file).grid(
            row=0, column=2, padx=5
        )

        # Batch Mode
        ttk.Checkbutton(
            file_frame,
            text="Batch Mode",
            variable=self.batch_mode_var,
            command=self.toggle_batch_mode,
        ).grid(row=0, column=3, padx=10)

        # Dictionary Path (visible in dictionary mode)
        self.dict_frame = ttk.Frame(file_frame)
        self.dict_frame.grid(row=1, column=0, columnspan=4, sticky="ew")
        ttk.Label(self.dict_frame, text="Dictionary:").grid(
            row=0, column=0, padx=5, pady=5, sticky="e"
        )
        self.entry_dict_path = ttk.Entry(self.dict_frame, width=50)
        self.entry_dict_path.grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(self.dict_frame, text="Browse", command=self.browse_dictionary).grid(
            row=0, column=2, padx=5
        )

        # Brute Force Settings (hidden by default)
        self.brute_frame = ttk.LabelFrame(file_frame, text="Brute Force Settings")
        self.brute_frame.grid(row=1, column=0, columnspan=4, sticky="ew", pady=5)

        # Length range
        ttk.Label(self.brute_frame, text="Min Length:").grid(
            row=0, column=0, padx=5, sticky="e"
        )
        ttk.Spinbox(
            self.brute_frame,
            from_=1,
            to=12,
            textvariable=self.brute_force_config["min_len"],
            width=5,
        ).grid(row=0, column=1, padx=5, sticky="w")
        ttk.Label(self.brute_frame, text="Max Length:").grid(
            row=0, column=2, padx=5, sticky="e"
        )
        ttk.Spinbox(
            self.brute_frame,
            from_=1,
            to=12,
            textvariable=self.brute_force_config["max_len"],
            width=5,
        ).grid(row=0, column=3, padx=5, sticky="w")

        # Character sets
        ttk.Checkbutton(
            self.brute_frame,
            text="Lowercase (a-z)",
            variable=self.brute_force_config["use_lower"],
        ).grid(row=1, column=0, columnspan=2, sticky="w")
        ttk.Checkbutton(
            self.brute_frame,
            text="Uppercase (A-Z)",
            variable=self.brute_force_config["use_upper"],
        ).grid(row=1, column=2, columnspan=2, sticky="w")
        ttk.Checkbutton(
            self.brute_frame,
            text="Digits (0-9)",
            variable=self.brute_force_config["use_digits"],
        ).grid(row=2, column=0, columnspan=2, sticky="w")
        ttk.Checkbutton(
            self.brute_frame,
            text="Special (!@#...)",
            variable=self.brute_force_config["use_special"],
        ).grid(row=2, column=2, columnspan=2, sticky="w")

        self.brute_frame.grid_remove()  # Hide by default

        # UnRAR Path
        ttk.Label(file_frame, text="UnRAR Path:").grid(
            row=2, column=0, padx=5, pady=5, sticky="e"
        )
        self.entry_unrar_path = ttk.Entry(file_frame, width=50)
        self.entry_unrar_path.grid(row=2, column=1, padx=5, pady=5)
        ttk.Button(file_frame, text="Auto-Detect", command=self.auto_detect_unrar).grid(
            row=2, column=2, padx=5
        )

        # Settings
        settings_frame = ttk.LabelFrame(main_frame, text="Settings")
        settings_frame.pack(fill=tk.X, pady=5)

        # Threads
        ttk.Label(settings_frame, text="Threads:").grid(
            row=0, column=0, padx=5, pady=5, sticky="e"
        )
        self.thread_entry = ttk.Entry(settings_frame, width=5)
        self.thread_entry.insert(0, "4")
        self.thread_entry.grid(row=0, column=1, padx=5, pady=5, sticky="w")

        # Save/Load
        ttk.Button(
            settings_frame, text="Save Progress", command=self.save_progress
        ).grid(row=0, column=2, padx=5)
        ttk.Button(
            settings_frame, text="Load Progress", command=self.load_progress
        ).grid(row=0, column=3, padx=5)

        # Controls
        control_frame = ttk.Frame(main_frame)
        control_frame.pack(pady=10)

        self.btn_start = ttk.Button(
            control_frame, text="Start", command=self.start_testing
        )
        self.btn_start.pack(side=tk.LEFT, padx=5)

        self.btn_pause = ttk.Button(
            control_frame, text="Pause", command=self.toggle_pause, state=tk.DISABLED
        )
        self.btn_pause.pack(side=tk.LEFT, padx=5)

        self.btn_stop = ttk.Button(
            control_frame, text="Stop", command=self.stop_testing, state=tk.DISABLED
        )
        self.btn_stop.pack(side=tk.LEFT, padx=5)

        self.btn_batch = ttk.Button(
            control_frame,
            text="Add Batch Files",
            command=self.add_batch_files,
            state=tk.NORMAL,
        )
        self.btn_batch.pack(side=tk.LEFT, padx=5)

        # Progress
        progress_frame = ttk.LabelFrame(main_frame, text="Progress")
        progress_frame.pack(fill=tk.X, pady=5)

        self.status_label = ttk.Label(progress_frame, text="Ready")
        self.status_label.pack(anchor=tk.W)

        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(
            progress_frame, variable=self.progress_var, length=550, mode="determinate"
        )
        self.progress_bar.pack(fill=tk.X, pady=5)

        self.current_password_label = ttk.Label(
            progress_frame, text="Current password: None", wraplength=550
        )
        self.current_password_label.pack(anchor=tk.W)

        self.time_label = ttk.Label(progress_frame, text="Time elapsed: 00:00:00")
        self.time_label.pack(anchor=tk.W)

        self.batch_status_label = ttk.Label(progress_frame, text="Batch progress: 0/0")
        self.batch_status_label.pack(anchor=tk.W)

        # Estimated time
        self.eta_label = ttk.Label(progress_frame, text="ETA: Calculating...")
        self.eta_label.pack(anchor=tk.W)

        # Info
        info_frame = ttk.Frame(main_frame)
        info_frame.pack(pady=10)

        info_label = ttk.Label(
            info_frame, text="Advanced RAR Password Cracker", justify=tk.CENTER
        )
        info_label.pack()

        contact_label = ttk.Label(
            info_frame, text="Email: dev.ashrafee@gmail.com", justify=tk.CENTER
        )
        contact_label.pack()

        # Tooltips
        self.setup_tooltips()
        # Drag and Drop
        self.setup_drag_drop()

    def setup_tooltips(self):
        ToolTip(self.entry_file_path, "Drag and drop RAR file or click Browse")
        ToolTip(self.entry_dict_path, "Text file containing password list")
        ToolTip(self.entry_unrar_path, "Path to unrar.exe executable")
        ToolTip(self.thread_entry, "Number of parallel threads (1-16 recommended)")
        ToolTip(self.btn_batch, "Add multiple RAR files for batch processing")
        ToolTip(self.brute_frame, "Configure character sets for brute force attack")

    def setup_drag_drop(self):
        self.entry_file_path.drop_target_register(DND_FILES)
        self.entry_file_path.dnd_bind(
            "<<Drop>>", lambda e: self.drop_file(e, self.entry_file_path)
        )
        self.entry_dict_path.drop_target_register(DND_FILES)
        self.entry_dict_path.dnd_bind(
            "<<Drop>>", lambda e: self.drop_file(e, self.entry_dict_path)
        )

    def toggle_attack_mode(self):
        if self.mode_var.get() == "dictionary":
            self.dict_frame.grid()
            self.brute_frame.grid_remove()
        else:
            self.dict_frame.grid_remove()
            self.brute_frame.grid()

    def toggle_batch_mode(self):
        if self.batch_mode_var.get():
            self.btn_batch.config(state=tk.NORMAL)
            self.entry_file_path.config(state=tk.DISABLED)
        else:
            self.btn_batch.config(state=tk.DISABLED)
            self.entry_file_path.config(state=tk.NORMAL)
        self.batch_files = []
        self.current_batch_index = 0
        self.update_batch_status()

    def drop_file(self, event, entry):
        file_path = event.data.strip().strip("{}")
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

    def add_batch_files(self):
        files = filedialog.askopenfilenames(filetypes=[("RAR files", "*.rar")])
        if files:
            self.batch_files = list(files)
            self.current_batch_index = 0
            self.update_batch_status()

    def update_batch_status(self):
        total = len(self.batch_files)
        self.batch_status_label.config(
            text=f"Batch progress: {self.current_batch_index}/{total}"
        )
        if total > 0 and self.current_batch_index < total:
            self.entry_file_path.delete(0, tk.END)
            self.entry_file_path.insert(0, self.batch_files[self.current_batch_index])

    def auto_detect_unrar(self):
        possible_paths = [
            os.path.join(os.getcwd(), "unrar.exe"),
            os.path.join(os.path.dirname(sys.argv[0]), "unrar.exe"),
            "C:\\Program Files\\WinRAR\\unrar.exe",
            "C:\\Program Files (x86)\\WinRAR\\unrar.exe",
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
        unrar_path = self.entry_unrar_path.get().strip()
        threads = self.thread_entry.get().strip()

        if not rar_path:
            messagebox.showerror("Error", "Please select a RAR file.")
            return False
        if not os.path.isfile(rar_path):
            messagebox.showerror("Error", "Invalid RAR file path.")
            return False

        if not unrar_path:
            messagebox.showerror("Error", "Please specify the path to unrar.exe.")
            return False
        if not os.path.isfile(unrar_path):
            messagebox.showerror("Error", "unrar.exe not found at the specified path.")
            return False

        if not threads.isdigit() or not (1 <= int(threads) <= 16):
            messagebox.showerror(
                "Error", "Please enter a valid number of threads (1-16)."
            )
            return False

        if self.mode_var.get() == "dictionary":
            dict_path = self.entry_dict_path.get().strip()
            if not dict_path:
                messagebox.showerror("Error", "Please select a dictionary file.")
                return False
            if not os.path.isfile(dict_path):
                messagebox.showerror("Error", "Invalid dictionary file path.")
                return False
        else:  # Brute force
            min_len = self.brute_force_config["min_len"].get()
            max_len = self.brute_force_config["max_len"].get()
            if min_len > max_len:
                messagebox.showerror(
                    "Error", "Minimum length cannot be greater than maximum length."
                )
                return False
            if not any(
                [
                    var.get()
                    for var in self.brute_force_config.values()
                    if isinstance(var, BooleanVar)
                ]
            ):
                messagebox.showerror(
                    "Error", "Select at least one character set for brute force."
                )
                return False

        return True

    def start_testing(self):
        if self.batch_mode_var.get() and not self.batch_files:
            messagebox.showwarning("Warning", "No batch files added!")
            return

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
        for thread in self.threads:
            thread.join(timeout=0.1)
        self.threads.clear()

        # Load passwords based on mode
        if self.mode_var.get() == "dictionary":
            try:
                with open(
                    self.entry_dict_path.get().strip(),
                    "r",
                    encoding="utf-8",
                    errors="ignore",
                ) as f:
                    passwords = [line.strip() for line in f if line.strip()]
                    self.total_passwords = len(passwords)
                    for pwd in passwords:
                        self.password_queue.put(pwd)
            except Exception as e:
                messagebox.showerror(
                    "Error", f"Failed to read dictionary file: {str(e)}"
                )
                return
        else:  # Brute force
            charset = ""
            if self.brute_force_config["use_lower"].get():
                charset += string.ascii_lowercase
            if self.brute_force_config["use_upper"].get():
                charset += string.ascii_uppercase
            if self.brute_force_config["use_digits"].get():
                charset += string.digits
            if self.brute_force_config["use_special"].get():
                charset += string.punctuation

            min_len = self.brute_force_config["min_len"].get()
            max_len = self.brute_force_config["max_len"].get()

            # Calculate total combinations for progress tracking
            self.total_passwords = sum(
                len(charset) ** i for i in range(min_len, max_len + 1)
            )

            # Start brute force generator in a separate thread
            brute_thread = threading.Thread(
                target=self.fill_brute_force_queue,
                args=(charset, min_len, max_len),
                daemon=True,
            )
            brute_thread.start()

        if self.total_passwords == 0:
            messagebox.showerror(
                "Error",
                "No passwords to test (empty dictionary or invalid brute force config).",
            )
            return

        # Start worker threads
        num_threads = min(int(self.thread_entry.get()), self.total_passwords)
        for _ in range(num_threads):
            thread = threading.Thread(target=self.worker, daemon=True)
            thread.start()
            self.threads.append(thread)

        # Update UI
        self.btn_start.config(state=tk.DISABLED)
        self.btn_pause.config(state=tk.NORMAL)
        self.btn_stop.config(state=tk.NORMAL)
        self.update_status()
        self.update_time_elapsed()
        self.update_eta()

    def fill_brute_force_queue(self, charset, min_len, max_len):
        for length in range(min_len, max_len + 1):
            for pwd_tuple in itertools.product(charset, repeat=length):
                if self.stop_event.is_set():
                    return
                self.password_queue.put("".join(pwd_tuple))

    def worker(self):
        rar_path = self.entry_file_path.get().strip()

        while not self.password_found and not self.stop_event.is_set():
            self.pause_event.wait()

            try:
                password = self.password_queue.get_nowait()
            except queue.Empty:
                time.sleep(0.1)  # Wait briefly if queue is empty (brute force)
                continue

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
                    if not self.batch_mode_var.get():
                        messagebox.showinfo("Success", f"Password found: {password}")
                    else:
                        self.handle_batch_success(password)
                    break

            except Exception as e:
                with self.lock:
                    self.current_password = f"Error: {str(e)}"
                    self.update_status()
                continue

    def handle_batch_success(self, password):
        messagebox.showinfo(
            "Success",
            f"Password found for {os.path.basename(self.entry_file_path.get())}:\n{password}",
        )

        self.current_batch_index += 1
        if self.current_batch_index < len(self.batch_files):
            self.password_found = False
            self.stop_testing()
            self.update_batch_status()
            self.start_testing()
        else:
            self.stop_testing()

    def update_eta(self):
        if (
            not self.password_found
            and not self.stop_event.is_set()
            and self.tested_passwords > 0
        ):
            elapsed = time.time() - self.start_time
            rate = self.tested_passwords / elapsed
            remaining = self.total_passwords - self.tested_passwords
            if rate > 0:
                eta_seconds = remaining / rate
                hours, remainder = divmod(eta_seconds, 3600)
                minutes, seconds = divmod(remainder, 60)
                self.eta_label.config(
                    text=f"ETA: {int(hours):02d}:{int(minutes):02d}:{int(seconds):02d}"
                )
            self.root.after(5000, self.update_eta)

    def toggle_pause(self):
        if self.pause_event.is_set():
            self.pause_event.clear()
            self.btn_pause.config(text="Resume")
        else:
            self.pause_event.set()
            self.btn_pause.config(text="Pause")

    def stop_testing(self):
        self.stop_event.set()
        self.pause_event.set()

        for thread in self.threads:
            thread.join(timeout=0.5)
        self.threads.clear()

        self.reset_ui()

    def reset_ui(self):
        self.btn_start.config(state=tk.NORMAL)
        self.btn_pause.config(state=tk.DISABLED, text="Pause")
        self.btn_stop.config(state=tk.DISABLED)
        self.eta_label.config(text="ETA: N/A")

    def update_status(self):
        if self.total_passwords > 0:
            progress = (self.tested_passwords / self.total_passwords) * 100
            self.status_label.config(
                text=f"Progress: {self.tested_passwords}/{self.total_passwords} ({progress:.1f}%)"
            )
            self.progress_var.set(progress)
        else:
            self.status_label.config(text="Ready")
            self.progress_var.set(0)

        self.current_password_label.config(text=f"Current: {self.current_password}")
        self.root.update_idletasks()

    def update_time_elapsed(self):
        if not self.password_found and not self.stop_event.is_set():
            elapsed = int(time.time() - self.start_time)
            hours, remainder = divmod(elapsed, 3600)
            minutes, seconds = divmod(remainder, 60)
            self.time_label.config(
                text=f"Time: {hours:02d}:{minutes:02d}:{seconds:02d}"
            )
            self.root.after(1000, self.update_time_elapsed)

    def save_progress(self):
        if not self.password_queue.empty() and not self.password_found:
            progress = {
                "mode": self.mode_var.get(),
                "rar_path": self.entry_file_path.get().strip(),
                "dict_path": self.entry_dict_path.get().strip(),
                "unrar_path": self.entry_unrar_path.get().strip(),
                "tested_passwords": self.tested_passwords,
                "total_passwords": self.total_passwords,
                "queue_contents": list(self.password_queue.queue),
                "batch_mode": self.batch_mode_var.get(),
                "batch_files": self.batch_files,
                "current_batch_index": self.current_batch_index,
                "brute_force_config": {
                    "min_len": self.brute_force_config["min_len"].get(),
                    "max_len": self.brute_force_config["max_len"].get(),
                    "use_lower": self.brute_force_config["use_lower"].get(),
                    "use_upper": self.brute_force_config["use_upper"].get(),
                    "use_digits": self.brute_force_config["use_digits"].get(),
                    "use_special": self.brute_force_config["use_special"].get(),
                },
                "timestamp": time.time(),
            }
            try:
                with open(self.progress_file, "w") as f:
                    json.dump(progress, f)
                messagebox.showinfo("Success", "Progress saved successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save progress: {str(e)}")
        else:
            messagebox.showwarning(
                "Warning", "No active session to save or password already found"
            )

    def load_progress(self):
        try:
            with open(self.progress_file, "r") as f:
                progress = json.load(f)

            # Restore mode
            self.mode_var.set(progress.get("mode", "dictionary"))
            self.toggle_attack_mode()

            # Restore file paths
            self.entry_file_path.delete(0, tk.END)
            self.entry_file_path.insert(0, progress.get("rar_path", ""))

            self.entry_dict_path.delete(0, tk.END)
            self.entry_dict_path.insert(0, progress.get("dict_path", ""))

            self.entry_unrar_path.delete(0, tk.END)
            self.entry_unrar_path.insert(0, progress.get("unrar_path", ""))

            # Restore batch mode
            self.batch_mode_var.set(progress.get("batch_mode", False))
            if self.batch_mode_var.get():
                self.batch_files = progress.get("batch_files", [])
                self.current_batch_index = progress.get("current_batch_index", 0)
                self.update_batch_status()
                self.entry_file_path.config(state=tk.DISABLED)
            else:
                self.entry_file_path.config(state=tk.NORMAL)

            # Restore brute force config
            brute_config = progress.get("brute_force_config", {})
            for key in self.brute_force_config:
                if key in brute_config:
                    self.brute_force_config[key].set(brute_config[key])

            # Restore progress
            self.tested_passwords = progress.get("tested_passwords", 0)
            self.total_passwords = progress.get("total_passwords", 0)

            # Rebuild queue
            with self.lock:
                while not self.password_queue.empty():
                    self.password_queue.get()
                for pwd in progress.get("queue_contents", []):
                    self.password_queue.put(pwd)

            messagebox.showinfo("Success", "Progress loaded! Click Start to resume.")
        except FileNotFoundError:
            messagebox.showerror("Error", "No saved progress file found")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load progress: {str(e)}")


if __name__ == "__main__":
    root = TkinterDnD.Tk()
    app = RARPasswordTester(root)
    root.mainloop()