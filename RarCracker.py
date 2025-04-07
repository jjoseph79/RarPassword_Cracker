# library imports
import os
import subprocess
import threading
import queue
import time
import json
import string
import itertools
import sys
import traceback
import tkinter as tk
from tkinter import filedialog, messagebox, ttk, StringVar, IntVar, BooleanVar, LEFT
from tkinterdnd2 import DND_FILES, TkinterDnD  # For drag and drop functionality
import winsound  
import webbrowser  # For opening web links


class ToolTip:

    def __init__(self, widget, text):

        self.widget = widget
        self.text = text
        self.tip_window = None  # Reference to tooltip window
        
        # Bind mouse events to show/hide tooltip
        self.widget.bind("<Enter>", self.showtip)
        self.widget.bind("<Leave>", self.hidetip)

    def showtip(self, event=None):
        """Display tooltip window when mouse enters widget"""
        # Return if tooltip already exists or no text to display
        if self.tip_window or not self.text:
            return
            
        # Calculate position relative to widget
        x, y, _, _ = self.widget.bbox("insert")
        x += self.widget.winfo_rootx() + 25  # Offset from widget
        y += self.widget.winfo_rooty() + 25
        
        # Create tooltip window
        self.tip_window = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)  
        tw.wm_geometry(f"+{x}+{y}")  
        
        # Configure tooltip appearance
        label = tk.Label(
            tw, 
            text=self.text, 
            justify=tk.LEFT,
            background="#ffffe0",  # Light yellow background
            relief=tk.SOLID, 
            borderwidth=1,
            font=("tahoma", "8", "normal")
        )
        label.pack(ipadx=1)

    def hidetip(self, event=None):
        tw = self.tip_window
        self.tip_window = None
        if tw:
            tw.destroy()


class RARPasswordTester:
    """
    Main application class for Advanced RAR Password Cracker.
    Provides both dictionary and brute force attack methods with multi-threading.
    """
    def __init__(self, root):

        # Configure main window
        self.root = root
        self.root.title("Advanced RAR Password Cracker")
        self.root.geometry("650x780")  # Fixed window size
        self.root.resizable(False, False)  # Disable resizing
        
        # Threading and queue variables
        self.password_queue = queue.Queue()  # Thread-safe password queue
        self.tested_passwords = 0  # Successfully tested passwords counter
        self.total_passwords = 0  # Total passwords to test
        self.password_found = False  # Password found flag
        self.pause_event = threading.Event()  # Pause control event
        self.pause_event.set()  # Start in unpaused state
        self.stop_event = threading.Event()  # Stop control event
        self.threads = []  # Worker thread references
        self.lock = threading.Lock()  # Thread synchronization lock
        
        # Operation tracking variables
        self.start_time = 0  
        self.unrar_path = ""  
        self.current_password = ""  
        self.batch_files = []  
        self.current_batch_index = 0  
        
        # Progress file path (handles both frozen and script modes)
        self.progress_file = os.path.join(
            os.path.dirname(os.path.abspath(sys.argv[0])) if getattr(sys, 'frozen', False) 
            else os.path.dirname(__file__), 
            "cracker_progress.json"
        )
        
        # Attack mode configuration
        self.mode_var = StringVar(value="dictionary")  # Default to dictionary attack
        self.batch_mode_var = BooleanVar(value=False)  
        
        # Brute force configuration with default values
        self.brute_force_config = {
            "min_len": IntVar(value=4), 
            "max_len": IntVar(value=6),  
            "use_lower": BooleanVar(value=True), 
            "use_upper": BooleanVar(value=False),  
            "use_digits": BooleanVar(value=True),  
            "use_special": BooleanVar(value=False)  
        }
        
        # Initialize UI components
        self.setup_gui()
        self.setup_styles()
        
    def setup_styles(self):
        self.style = ttk.Style()
        # Consistent padding across widgets
        self.style.configure("TButton", padding=6)
        self.style.configure("TEntry", padding=5)
        self.style.configure("TLabel", padding=5)
        self.style.configure("TLabelframe", padding=10)
        
    def setup_gui(self):
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Mode selection frame
        mode_frame = ttk.LabelFrame(main_frame, text="Attack Mode")
        mode_frame.pack(fill=tk.X, pady=5)
        
        # Attack mode radio buttons
        ttk.Radiobutton(
            mode_frame, 
            text="Dictionary Attack", 
            variable=self.mode_var, 
            value="dictionary", 
            command=self.toggle_attack_mode
        ).pack(side=LEFT, padx=5)
        
        ttk.Radiobutton(
            mode_frame, 
            text="Brute Force", 
            variable=self.mode_var, 
            value="bruteforce", 
            command=self.toggle_attack_mode
        ).pack(side=LEFT, padx=5)
        
        # File selection frame
        file_frame = ttk.LabelFrame(main_frame, text="File Selection")
        file_frame.pack(fill=tk.X, pady=5)
        
        # RAR file path components
        ttk.Label(file_frame, text="Targeted RAR File:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
        self.entry_file_path = ttk.Entry(file_frame, width=50)
        self.entry_file_path.grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(file_frame, text="Browse", command=self.browse_file).grid(row=0, column=2, padx=5)
        
        # Batch mode checkbox
        self.batch_check = ttk.Checkbutton(
            file_frame, 
            text="Batch Mode", 
            variable=self.batch_mode_var, 
            command=self.toggle_batch_mode
        )
        self.batch_check.grid(row=0, column=3, padx=10)
        
        # Dictionary frame (shown in dictionary mode)
        self.dict_frame = ttk.Frame(file_frame)
        self.dict_frame.grid(row=1, column=0, columnspan=4, sticky="ew")
        ttk.Label(self.dict_frame, text="Dictionary:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
        self.entry_dict_path = ttk.Entry(self.dict_frame, width=50)
        self.entry_dict_path.grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(self.dict_frame, text="Browse", command=self.browse_dictionary).grid(row=0, column=2, padx=5)
        
        # Brute force frame (hidden by default)
        self.brute_frame = ttk.LabelFrame(file_frame, text="Brute Force Settings")
        self.brute_frame.grid(row=1, column=0, columnspan=4, sticky="ew", pady=5)
        
        # Password length controls
        ttk.Label(self.brute_frame, text="Min Length:").grid(row=0, column=0, padx=5, sticky="e")
        ttk.Spinbox(
            self.brute_frame, 
            from_=1, 
            to=12, 
            textvariable=self.brute_force_config["min_len"], 
            width=5
        ).grid(row=0, column=1, padx=5, sticky="w")
        
        ttk.Label(self.brute_frame, text="Max Length:").grid(row=0, column=2, padx=5, sticky="e")
        ttk.Spinbox(
            self.brute_frame, 
            from_=1, 
            to=12, 
            textvariable=self.brute_force_config["max_len"], 
            width=5
        ).grid(row=0, column=3, padx=5, sticky="w")
        
        # Character set checkboxes
        ttk.Checkbutton(
            self.brute_frame, 
            text="Lowercase (a-z)", 
            variable=self.brute_force_config["use_lower"]
        ).grid(row=1, column=0, columnspan=2, sticky="w")
        
        ttk.Checkbutton(
            self.brute_frame, 
            text="Uppercase (A-Z)", 
            variable=self.brute_force_config["use_upper"]
        ).grid(row=1, column=2, columnspan=2, sticky="w")
        
        ttk.Checkbutton(
            self.brute_frame, 
            text="Digits (0-9)", 
            variable=self.brute_force_config["use_digits"]
        ).grid(row=2, column=0, columnspan=2, sticky="w")
        
        ttk.Checkbutton(
            self.brute_frame, 
            text="Special (!@#...)", 
            variable=self.brute_force_config["use_special"]
        ).grid(row=2, column=2, columnspan=2, sticky="w")
        
        self.brute_frame.grid_remove()  # Initially hidden
        
        # UnRAR path components
        ttk.Label(file_frame, text="UnRAR Path:").grid(row=2, column=0, padx=5, pady=5, sticky="e")
        self.entry_unrar_path = ttk.Entry(file_frame, width=50)
        self.entry_unrar_path.grid(row=2, column=1, padx=5, pady=5)
        ttk.Button(file_frame, text="Auto-Detect", command=self.auto_detect_unrar).grid(row=2, column=2, padx=5)
        
        # Settings frame
        settings_frame = ttk.LabelFrame(main_frame, text="Settings")
        settings_frame.pack(fill=tk.X, pady=5)
        
        # Thread count control
        ttk.Label(settings_frame, text="Threads:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
        self.thread_entry = ttk.Spinbox(settings_frame, from_=1, to=16, width=5)
        self.thread_entry.set(4)  # Default to 4 threads
        self.thread_entry.grid(row=0, column=1, padx=5, pady=5, sticky="w")
        
        # Progress management buttons
        ttk.Button(settings_frame, text="Save Progress", command=self.save_progress).grid(row=0, column=2, padx=5)
        ttk.Button(settings_frame, text="Load Progress", command=self.load_progress).grid(row=0, column=3, padx=5)
        
        # Control buttons frame
        control_frame = ttk.Frame(main_frame)
        control_frame.pack(pady=10)
        
        # Main action buttons
        self.btn_start = ttk.Button(control_frame, text="Start", command=self.start_testing)
        self.btn_start.pack(side=LEFT, padx=5)
        
        self.btn_pause = ttk.Button(
            control_frame, 
            text="Pause", 
            command=self.toggle_pause, 
            state=tk.DISABLED
        )
        self.btn_pause.pack(side=LEFT, padx=5)
        
        self.btn_stop = ttk.Button(
            control_frame, 
            text="Stop", 
            command=self.stop_testing, 
            state=tk.DISABLED
        )
        self.btn_stop.pack(side=LEFT, padx=5)
        
        self.btn_batch = ttk.Button(
            control_frame, 
            text="Add Batch Files", 
            command=self.add_batch_files, 
            state=tk.DISABLED
        )
        self.btn_batch.pack(side=LEFT, padx=5)
        
        # Progress display frame
        progress_frame = ttk.LabelFrame(main_frame, text="Progress")
        progress_frame.pack(fill=tk.X, pady=5)
        
        # Status labels and progress bar
        self.status_label = ttk.Label(progress_frame, text="Ready")
        self.status_label.pack(anchor=tk.W)
        
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(
            progress_frame, 
            variable=self.progress_var, 
            length=550, 
            mode="determinate"
        )
        self.progress_bar.pack(fill=tk.X, pady=5)
        
        self.current_password_label = ttk.Label(
            progress_frame, 
            text="Current password: None", 
            wraplength=550
        )
        self.current_password_label.pack(anchor=tk.W)
        
        self.time_label = ttk.Label(progress_frame, text="Time elapsed: 00:00:00")
        self.time_label.pack(anchor=tk.W)
        
        self.batch_status_label = ttk.Label(progress_frame, text="Batch progress: 0/0")
        self.batch_status_label.pack(anchor=tk.W)
        
        self.eta_label = ttk.Label(progress_frame, text="ETA: N/A")
        self.eta_label.pack(anchor=tk.W)
        
        # Information/credit frame
        info_frame = ttk.Frame(main_frame)
        info_frame.pack(pady=10)

        info_label = ttk.Label(
            info_frame,
            text="Advance RAR Password Cracker Pro with Brute Force\nDeveloped by Dev Ashrafee",
            justify=tk.CENTER,
        )
        info_label.pack()

        contact_label = ttk.Label(
            info_frame,
            text="Email: dev.ashrafee@gmail.com | WhatsApp: +8801612381085",
            justify=tk.CENTER,
        )
        contact_label.pack()

        # Clickable LinkedIn link
        linkedin_label = ttk.Label(
            info_frame, 
            text="LinkedIn: Click here", 
            foreground="blue", 
            cursor="hand2"
        )
        linkedin_label.pack()
        linkedin_label.bind(
            "<Button-1>",
            lambda e: self.open_url("https://www.linkedin.com/in/abdullahalashrafee/"),
        )
        
        # Initialize additional UI features
        self.setup_tooltips()
        self.setup_drag_drop()
        self.toggle_batch_mode()

    def setup_tooltips(self):
        """Attach tooltips to important UI elements"""
        ToolTip(self.entry_file_path, "Drag and drop RAR file or click Browse")
        ToolTip(self.entry_dict_path, "Text file containing password list")
        ToolTip(self.entry_unrar_path, "Path to unrar.exe executable")
        ToolTip(self.thread_entry, "Number of parallel threads (1-16 recommended)")
        ToolTip(self.btn_batch, "Add multiple RAR files for batch processing")
        ToolTip(self.brute_frame, "Configure character sets for brute force attack")

    def setup_drag_drop(self):
        """Initialize drag and drop functionality for file inputs"""
        try:
            self.entry_file_path.drop_target_register(DND_FILES)
            self.entry_file_path.dnd_bind("<<Drop>>", lambda e: self.drop_file(e, self.entry_file_path))
            self.entry_dict_path.drop_target_register(DND_FILES)
            self.entry_dict_path.dnd_bind("<<Drop>>", lambda e: self.drop_file(e, self.entry_dict_path))
        except Exception as e:
            print(f"Drag and drop initialization failed: {e}")

    def toggle_attack_mode(self):
        """Switch between dictionary and brute force attack UI"""
        if self.mode_var.get() == "dictionary":
            self.dict_frame.grid()
            self.brute_frame.grid_remove()
        else:
            self.dict_frame.grid_remove()
            self.brute_frame.grid()

    def toggle_batch_mode(self):
        """Enable/disable batch file processing mode"""
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
        """Handle files dropped onto entry fields"""
        try:
            # Clean up path (handle platform differences)
            file_path = event.data.strip().strip("{}")
            if sys.platform == 'darwin':  # macOS path handling
                file_path = file_path.replace('\\', '')
            
            # Update entry field with dropped file path
            entry.delete(0, tk.END)
            entry.insert(0, file_path)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to handle dropped file: {str(e)}")

    def browse_file(self):
        """Open file dialog to select RAR archive"""
        file_path = filedialog.askopenfilename(filetypes=[("RAR files", "*.rar")])
        if file_path:
            self.entry_file_path.delete(0, tk.END)
            self.entry_file_path.insert(0, os.path.normpath(file_path))

    def browse_dictionary(self):
        """Open file dialog to select password dictionary"""
        dict_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if dict_path:
            self.entry_dict_path.delete(0, tk.END)
            self.entry_dict_path.insert(0, os.path.normpath(dict_path))

    def add_batch_files(self):
        """Add multiple RAR files for batch processing"""
        files = filedialog.askopenfilenames(filetypes=[("RAR files", "*.rar")])
        if files:
            self.batch_files = [os.path.normpath(f) for f in files]
            self.current_batch_index = 0
            self.update_batch_status()

    def update_batch_status(self):
        """Update batch progress display"""
        total = len(self.batch_files)
        self.batch_status_label.config(text=f"Batch progress: {self.current_batch_index}/{total}")
        if total > 0 and self.current_batch_index < total:
            self.entry_file_path.delete(0, tk.END)
            self.entry_file_path.insert(0, self.batch_files[self.current_batch_index])

    def auto_detect_unrar(self):
        """Attempt to locate unrar executable automatically"""
        # Common possible locations for unrar executable
        possible_paths = [
            os.path.join(os.getcwd(), "unrar.exe"),
            os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])), "unrar.exe"),
            "C:\\Program Files\\WinRAR\\unrar.exe",
            "C:\\Program Files (x86)\\WinRAR\\unrar.exe",
            "/usr/bin/unrar",
            "/usr/local/bin/unrar"
        ]
        
        # Check each possible location
        for path in possible_paths:
            if os.path.isfile(path):
                self.entry_unrar_path.delete(0, tk.END)
                self.entry_unrar_path.insert(0, os.path.normpath(path))
                return
        
        # Show warning if not found
        messagebox.showwarning("Not Found", "Could not auto-detect unrar.exe. Please specify manually.")


    def validate_inputs(self):
        """
        Validate all user inputs before starting the password testing process.
        Returns True if all inputs are valid, False otherwise with error messages.
        """
        try:
            # Get and clean input values
            rar_path = self.entry_file_path.get().strip()
            unrar_path = self.entry_unrar_path.get().strip()
            threads = self.thread_entry.get().strip()

            # Validate RAR file path
            if not rar_path:
                messagebox.showerror("Error", "Please select your targeted RAR file.")
                return False
            if not os.path.isfile(rar_path):
                messagebox.showerror("Error", "Invalid RAR file path.")
                return False

            # Validate unrar executable path
            if not unrar_path:
                messagebox.showerror("Error", "Please specify the path to unrar executable.")
                return False
            if not os.path.isfile(unrar_path):
                messagebox.showerror("Error", "unrar executable not found at the specified path.")
                return False

            # Validate thread count
            try:
                threads = int(threads)
                if not (1 <= threads <= 16):
                    raise ValueError
            except ValueError:
                messagebox.showerror("Error", "Please enter a valid number of threads (1-16).")
                return False

            # Mode-specific validations
            if self.mode_var.get() == "dictionary":
                # Dictionary attack validations
                dict_path = self.entry_dict_path.get().strip()
                if not dict_path:
                    messagebox.showerror("Error", "Please select a dictionary file.")
                    return False
                if not os.path.isfile(dict_path):
                    messagebox.showerror("Error", "Invalid dictionary file path.")
                    return False
            else:  # Brute force validations
                min_len = self.brute_force_config["min_len"].get()
                max_len = self.brute_force_config["max_len"].get()
                
                # Validate length parameters
                if min_len > max_len:
                    messagebox.showerror("Error", "Minimum length cannot be greater than maximum length.")
                    return False
                
                # Validate at least one character set is selected
                if not any([var.get() for var in self.brute_force_config.values() if isinstance(var, BooleanVar)]):
                    messagebox.showerror("Error", "Select at least one character set for brute force.")
                    return False

            return True  # All validations passed
        except Exception as e:
            messagebox.showerror("Error", f"Validation error: {str(e)}")
            return False

    def start_testing(self):
        """Initialize and start the password testing process based on selected mode."""
        try:
            # Check batch mode requirements
            if self.batch_mode_var.get() and not self.batch_files:
                messagebox.showwarning("Warning", "No batch files added!")
                return
            
            # Validate inputs before proceeding
            if not self.validate_inputs():
                return

            # Reset testing state
            self.password_found = False
            self.stop_event.clear()  # Allow threads to run
            self.pause_event.set()  # Start unpaused
            self.tested_passwords = 0
            self.total_passwords = 0
            self.start_time = time.time()
            self.unrar_path = self.entry_unrar_path.get().strip()

            # Clear existing queue and threads
            with self.lock:
                while not self.password_queue.empty():
                    self.password_queue.get()
            for thread in self.threads:
                if thread.is_alive():
                    thread.join(timeout=0.1)
            self.threads.clear()

            # Load passwords based on selected mode
            if self.mode_var.get() == "dictionary":
                try:
                    # Read dictionary file and populate queue
                    with open(self.entry_dict_path.get().strip(), "r", encoding="utf-8", errors="ignore") as f:
                        passwords = [line.strip() for line in f if line.strip()]
                        self.total_passwords = len(passwords)
                        for pwd in passwords:
                            self.password_queue.put(pwd)
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to read dictionary file: {str(e)}")
                    return
            else:  # Brute force mode
                # Build character set based on user selections
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
                try:
                    self.total_passwords = sum(len(charset)**i for i in range(min_len, max_len + 1))
                except OverflowError:
                    messagebox.showerror("Error", "The selected brute force parameters would generate too many combinations to handle.")
                    return
                
                # Start brute force generator in separate thread
                brute_thread = threading.Thread(
                    target=self.fill_brute_force_queue,
                    args=(charset, min_len, max_len),
                    daemon=True
                )
                brute_thread.start()
                self.threads.append(brute_thread)

            # Final validation before starting
            if self.total_passwords == 0:
                messagebox.showerror("Error", "No passwords to test (empty dictionary or invalid brute force config).")
                return

            # Start worker threads
            num_threads = min(int(self.thread_entry.get()), self.total_passwords)
            for _ in range(num_threads):
                thread = threading.Thread(target=self.worker, daemon=True)
                thread.start()
                self.threads.append(thread)

            # Update UI controls
            self.btn_start.config(state=tk.DISABLED)
            self.btn_pause.config(state=tk.NORMAL)
            self.btn_stop.config(state=tk.NORMAL)
            self.update_status()
            self.update_time_elapsed()
            self.update_eta()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start testing: {str(e)}")
            traceback.print_exc()

    def fill_brute_force_queue(self, charset, min_len, max_len):
        """
        Generate password combinations and fill the queue for brute force attack.
        
        Args:
            charset: String containing characters to use in combinations
            min_len: Minimum password length to generate
            max_len: Maximum password length to generate
        """
        try:
            # Generate passwords of increasing length
            for length in range(min_len, max_len + 1):
                # Create all possible combinations for current length
                for pwd_tuple in itertools.product(charset, repeat=length):
                    # Stop if password got cracked
                    if self.stop_event.is_set() or self.password_found:
                        return
                    # Add generated password to queue
                    self.password_queue.put("".join(pwd_tuple))
        except Exception as e:
            print(f"Brute force generator error: {e}")

    def worker(self):
        """Worker thread function that tests passwords from the queue."""
        rar_path = self.entry_file_path.get().strip()
        
        while not self.password_found and not self.stop_event.is_set():
            # Pause if pause event is not set
            self.pause_event.wait()
            
            try:
                # Get next password to test
                password = self.password_queue.get_nowait()
            except queue.Empty:
                time.sleep(0.1)  # Brief wait if queue is empty
                continue

            # Update status with current password
            with self.lock:
                self.current_password = password
                self.tested_passwords += 1
                self.update_status()

            # Test password using unrar
            try:
                if sys.platform == 'win32':
                    # Windows-specific subprocess setup to hide console window
                    startupinfo = subprocess.STARTUPINFO()
                    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                    startupinfo.wShowWindow = subprocess.SW_HIDE
                    result = subprocess.run(
                        [self.unrar_path, "t", "-p" + password, rar_path],
                        stdout=subprocess.PIPE, 
                        stderr=subprocess.PIPE,
                        startupinfo=startupinfo
                    )
                else:
                    # Non-Windows subprocess call
                    result = subprocess.run(
                        [self.unrar_path, "t", "-p" + password, rar_path],
                        stdout=subprocess.PIPE, 
                        stderr=subprocess.PIPE
                    )
                
                # Check output for success
                output = result.stdout.decode("utf-8", errors="ignore")
                if "All OK" in output or "All OK" in result.stderr.decode("utf-8", errors="ignore"):
                    with self.lock:
                        self.password_found = True
                        self.current_password = f"Found: {password}"
                        self.update_status()
                    
                    # Play sound on Windows
                    winsound.Beep(1000, 500) if sys.platform == 'win32' else None
                    
                    # Show success message
                    if not self.batch_mode_var.get():
                        self.root.after(0, lambda: messagebox.showinfo("Success", f"Password found: {password}"))
                    else:
                        self.root.after(0, self.handle_batch_success, password)
                    break
                    
            except Exception as e:
                with self.lock:
                    self.current_password = f"Error: {str(e)}"
                    self.update_status()
                continue

    def handle_batch_success(self, password):
        """Handle successful password find in batch mode."""
        try:
            # Show success message for current file
            messagebox.showinfo("Success", 
                             f"Password found for {os.path.basename(self.entry_file_path.get())}:\n{password}")
            
            # Move to next file in batch if available
            self.current_batch_index += 1
            if self.current_batch_index < len(self.batch_files):
                self.password_found = False
                self.stop_testing()
                self.update_batch_status()
                self.start_testing()
            else:
                self.stop_testing()  # All files processed
        except Exception as e:
            messagebox.showerror("Error", f"Failed to handle batch success: {str(e)}")

    def update_eta(self):
        """Calculate and display estimated time remaining."""
        if not self.password_found and not self.stop_event.is_set() and self.tested_passwords > 0:
            try:
                elapsed = time.time() - self.start_time
                rate = self.tested_passwords / elapsed
                remaining = self.total_passwords - self.tested_passwords
                if rate > 0:
                    eta_seconds = remaining / rate
                    hours, remainder = divmod(eta_seconds, 3600)
                    minutes, seconds = divmod(remainder, 60)
                    self.eta_label.config(text=f"ETA: {int(hours):02d}:{int(minutes):02d}:{int(seconds):02d}")
                self.root.after(5000, self.update_eta)  # Update every 5 seconds
            except Exception:
                self.eta_label.config(text="ETA: Calculating...")

    def toggle_pause(self):
        """Toggle pause/resume state of password testing."""
        if self.pause_event.is_set():
            self.pause_event.clear()
            self.btn_pause.config(text="Resume")
        else:
            self.pause_event.set()
            self.btn_pause.config(text="Pause")

    def stop_testing(self):
        """Stop all password testing activities."""
        self.stop_event.set()
        self.pause_event.set()
        
        # Clean up threads
        for thread in self.threads:
            if thread.is_alive():
                thread.join(timeout=0.5)
        self.threads.clear()
        
        self.reset_ui()

    def reset_ui(self):
        """Reset UI controls to initial state."""
        self.btn_start.config(state=tk.NORMAL)
        self.btn_pause.config(state=tk.DISABLED, text="Pause")
        self.btn_stop.config(state=tk.DISABLED)
        self.eta_label.config(text="ETA: N/A")

    def update_status(self):
        """Update progress bar and status labels."""
        try:
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
        except Exception as e:
            print(f"Status update error: {e}")

    def update_time_elapsed(self):
        """Update the elapsed time display."""
        if not self.password_found and not self.stop_event.is_set():
            try:
                elapsed = int(time.time() - self.start_time)
                hours, remainder = divmod(elapsed, 3600)
                minutes, seconds = divmod(remainder, 60)
                self.time_label.config(text=f"Time: {hours:02d}:{minutes:02d}:{seconds:02d}")
                self.root.after(1000, self.update_time_elapsed)  # Update every second
            except Exception:
                self.time_label.config(text="Time: Error")

    def save_progress(self):
        """Save current testing progress to a JSON file."""
        try:
            if not self.password_queue.empty() and not self.password_found:
                # Prepare progress data dictionary
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
                        "use_special": self.brute_force_config["use_special"].get()
                    },
                    "timestamp": time.time()
                }
                
                try:
                    with open(self.progress_file, "w") as f:
                        json.dump(progress, f)
                    messagebox.showinfo("Success", "Progress saved successfully!")
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to save progress: {str(e)}")
            else:
                messagebox.showwarning("Warning", "No active session to save or password already found")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to prepare progress data: {str(e)}")

    def load_progress(self):
        """Load saved progress from JSON file."""
        try:
            if not os.path.exists(self.progress_file):
                messagebox.showerror("Error", "No saved progress file found")
                return
                
            with open(self.progress_file, "r") as f:
                progress = json.load(f)
            
            # Restore mode and UI state
            self.mode_var.set(progress.get("mode", "dictionary"))
            self.toggle_attack_mode()
            
            # Restore file paths
            self.entry_file_path.delete(0, tk.END)
            self.entry_file_path.insert(0, progress.get("rar_path", ""))
            
            self.entry_dict_path.delete(0, tk.END)
            self.entry_dict_path.insert(0, progress.get("dict_path", ""))
            
            self.entry_unrar_path.delete(0, tk.END)
            self.entry_unrar_path.insert(0, progress.get("unrar_path", ""))
            
            # Restore batch mode state
            self.batch_mode_var.set(progress.get("batch_mode", False))
            if self.batch_mode_var.get():
                self.batch_files = progress.get("batch_files", [])
                self.current_batch_index = progress.get("current_batch_index", 0)
                self.update_batch_status()
                self.entry_file_path.config(state=tk.DISABLED)
            else:
                self.entry_file_path.config(state=tk.NORMAL)
            
            # Restore brute force configuration
            brute_config = progress.get("brute_force_config", {})
            for key in self.brute_force_config:
                if key in brute_config:
                    self.brute_force_config[key].set(brute_config[key])
            
            # Restore progress counters
            self.tested_passwords = progress.get("tested_passwords", 0)
            self.total_passwords = progress.get("total_passwords", 0)
            
            # Rebuild password queue
            with self.lock:
                while not self.password_queue.empty():
                    self.password_queue.get()
                for pwd in progress.get("queue_contents", []):
                    self.password_queue.put(pwd)
            
            messagebox.showinfo("Success", "Progress loaded! Click Start to resume.")
        except json.JSONDecodeError:
            messagebox.showerror("Error", "The progress file is corrupted")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load progress: {str(e)}")
            traceback.print_exc()

    def open_url(self, url):
        """Open a URL in the default web browser."""
        try:
            webbrowser.open_new(url)
        except Exception:
            messagebox.showerror("Error", "Failed to open web browser")

if __name__ == "__main__":
    """Main entry point for the application."""
    try:
        root = TkinterDnD.Tk()  
        app = RARPasswordTester(root)
        root.mainloop() 
    except Exception as e:
        messagebox.showerror("Fatal Error", f"Application crashed: {str(e)}\n{traceback.format_exc()}")
