import tkinter as tk  # GUI
from tkinter import filedialog, messagebox, ttk
import os
import subprocess
import threading
import winsound  # For sound notifications
from tkinterdnd2 import DND_FILES, TkinterDnD  # Drag and Drop support
from threading import Lock, Event

# Global variables
lock = Lock()
password_found = Event()

def browse_file():
    file_path = filedialog.askopenfilename(filetypes=[("RAR files", "*.rar")])
    if file_path:
        entry_file_path.delete(0, tk.END)
        entry_file_path.insert(0, file_path)

def browse_dictionary():
    dict_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
    if dict_path:
        entry_dict_path.delete(0, tk.END)
        entry_dict_path.insert(0, dict_path)

def drop(event, entry):
    file_path = event.data.strip()
    if file_path.startswith("{") and file_path.endswith("}"):
        file_path = file_path[1:-1]
    entry.delete(0, tk.END)
    entry.insert(0, file_path)

def update_status(loaded, tested, remaining):
    status_label.config(text=f"Loaded: {loaded} | Tested: {tested} | Left: {remaining:.2f}%")
    progress_var.set(100 - remaining)
    root.update_idletasks()

def test_passwords():
    global total_passwords, tested_passwords
    rar_path = entry_file_path.get().strip()
    dict_path = entry_dict_path.get().strip()
    threads = int(thread_entry.get().strip()) if thread_entry.get().strip().isdigit() else 1

    if not os.path.isfile(rar_path):
        messagebox.showerror("Error", "Invalid RAR file path. Please select a valid RAR file.")
        return
    if not os.path.isfile(dict_path):
        messagebox.showerror("Error", "Invalid dictionary file path. Please select a valid text file.")
        return

    unrar_path = os.path.join(os.getcwd(), "unrar.exe")
    if not os.path.isfile(unrar_path):
        messagebox.showerror("Error", "UnRAR.exe not found! Please place unrar.exe in the same folder as this program.")
        return

    log_file = "password_attempts.log"
    with open(log_file, "w") as log:
        log.write(f"Testing passwords for: {os.path.basename(rar_path)}\n\n")

    with open(dict_path, "r", encoding="utf-8", errors="ignore") as df:
        password_list = [line.strip() for line in df if line.strip()]
    
    total_passwords = len(password_list)
    tested_passwords = 0
    password_found.clear()
    update_status(total_passwords, 0, 100)

    chunk_size = max(1, len(password_list) // threads)
    password_chunks = [password_list[i:i + chunk_size] for i in range(0, len(password_list), chunk_size)]

    def worker(passwords):
        global tested_passwords
        for password in passwords:
            if password_found.is_set():
                return  # Stop other threads if a password is found

            result = subprocess.run(
                [unrar_path, "t", "-p" + password, rar_path],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )

            with lock:
                tested_passwords += 1
                update_status(total_passwords, tested_passwords, (1 - (tested_passwords / total_passwords)) * 100)

            with open(log_file, "a") as log:
                log.write(f"Tested: {password}\n")

            if "All OK" in result.stdout.decode("utf-8", errors="ignore"):
                password_found.set()
                winsound.Beep(1000, 500)
                messagebox.showinfo("Success", f"Password found: {password}")
                return

    for chunk in password_chunks:
        thread = threading.Thread(target=worker, args=(chunk,))
        thread.start()

# Create main application window
root = TkinterDnD.Tk()
root.title("WinRAR Password Tester")
root.geometry("500x350")

tk.Label(root, text="RAR File Path:").grid(row=0, column=0, padx=10, pady=5, sticky="e")
entry_file_path = tk.Entry(root, width=45)
entry_file_path.grid(row=0, column=1, padx=10, pady=5)
tk.Button(root, text="Browse", command=browse_file).grid(row=0, column=2, padx=5)

entry_file_path.drop_target_register(DND_FILES)
entry_file_path.dnd_bind("<<Drop>>", lambda e: drop(e, entry_file_path))

tk.Label(root, text="Dictionary File Path:").grid(row=1, column=0, padx=10, pady=5, sticky="e")
entry_dict_path = tk.Entry(root, width=45)
entry_dict_path.grid(row=1, column=1, padx=10, pady=5)
tk.Button(root, text="Browse", command=browse_dictionary).grid(row=1, column=2, padx=5)

entry_dict_path.drop_target_register(DND_FILES)
entry_dict_path.dnd_bind("<<Drop>>", lambda e: drop(e, entry_dict_path))

tk.Label(root, text="Threads:").grid(row=2, column=0, padx=10, pady=5, sticky="e")
thread_entry = tk.Entry(root, width=5)
thread_entry.insert(0, "4")
thread_entry.grid(row=2, column=1, padx=10, pady=5, sticky="w")

tk.Button(root, text="Test Passwords", command=test_passwords).grid(row=3, column=1, pady=10)

status_label = tk.Label(root, text="Loaded: 0 | Tested: 0 | Left: 100%")
status_label.grid(row=4, column=0, columnspan=3, pady=5)

progress_var = tk.DoubleVar()
progress_bar = ttk.Progressbar(root, variable=progress_var, length=400, mode="determinate")
progress_bar.grid(row=5, column=0, columnspan=3, pady=10)

info_label = tk.Label(root, text="RAR Password Cracker - Developed by Dev Ashrafee\n"
                                 "Email: dev.ashrafee@gmail.com\n"
                                 "WhatsApp: +8801612381085\n"
                                 "LinkedIn: Click here", fg="blue", cursor="hand2")
info_label.grid(row=6, column=0, columnspan=3, pady=10)
info_label.bind("<Button-1>", lambda e: os.system("start https://www.linkedin.com/in/abdullahalashrafee/"))

root.mainloop()
