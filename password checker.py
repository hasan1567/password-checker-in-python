import tkinter as tk
from tkinter import messagebox, filedialog, scrolledtext
import math, hashlib, string, random, requests
from datetime import datetime
import matplotlib.pyplot as plt
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from PIL import Image, ImageTk

# === Global Variables ===
HIBP_API_PREFIX = "https://api.pwnedpasswords.com/range/"
COMMON_PASSWORDS = {"123456", "password", "123456789", "qwerty", "abc123", "letmein"}
KEYBOARD_PATTERNS = ["qwerty", "asdf", "zxcv", "1234", "abcd", "pass", "admin"]
user_settings = {
    "min_length": 8,
    "check_leak": True,
    "check_sequence": True,
    "check_keyboard_patterns": True
}
last_analysis = ""
last_entropy = 0
dark_mode = False

# === THEME TOGGLING ===
def toggle_theme():
    global dark_mode
    dark_mode = not dark_mode
    bg_color = "#2e2e2e" if dark_mode else "white"
    fg_color = "white" if dark_mode else "black"
    entry.config(bg=bg_color, fg=fg_color, insertbackground=fg_color)
    status_label.config(bg=bg_color, fg=fg_color)
    result_box.config(bg=bg_color, fg=fg_color)
    root.config(bg=bg_color)
    for widget in root.winfo_children():
        if isinstance(widget, tk.Button) or isinstance(widget, tk.Label):
            widget.config(bg=bg_color, fg=fg_color)

# === CLIPBOARD CHECKER ===
def check_clipboard_password():
    try:
        clipboard_text = root.clipboard_get()
        if clipboard_text and len(clipboard_text) >= 4:
            entry.delete(0, tk.END)
            entry.insert(0, clipboard_text)
            update_analysis()
    except:
        pass

# === DICTIONARY ATTACK SIMULATOR ===
def simulate_dictionary_attack():
    if not entry.get():
        messagebox.showwarning("No Password", "Please enter a password to simulate the attack.")
        return
    password = entry.get()
    wordlist = ["123456", "admin", "qwerty", "letmein", "password", "hasan123", "welcome123"]
    found = password in wordlist
    messagebox.showinfo("Attack Result", f"Password {'found' if found else 'not found'} in wordlist.")

# === Core Logic ===
def calculate_entropy(pw):
    charset = sum([
        26 if any(c.islower() for c in pw) else 0,
        26 if any(c.isupper() for c in pw) else 0,
        10 if any(c.isdigit() for c in pw) else 0,
        len(string.punctuation) if any(c in string.punctuation for c in pw) else 0
    ])
    return round(len(pw) * math.log2(charset)) if charset else 0

def strength_color_and_label(entropy, length):
    if length < user_settings["min_length"] or entropy < 28: return "Very Weak", "red"
    if entropy < 36: return "Weak", "orange"
    if entropy < 60: return "Moderate", "yellow"
    if entropy < 80: return "Strong", "lightgreen"
    return "Very Strong", "green"

def breached_k_anonymity(pwd):
    try:
        sha1 = hashlib.sha1(pwd.encode()).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        resp = requests.get(HIBP_API_PREFIX + prefix)
        if resp.status_code != 200:
            return None
        return any(line.split(':')[0] == suffix for line in resp.text.splitlines())
    except Exception:
        return None

def log_analysis(data):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open("audit_log.txt", "a") as log:
        log.write(f"[{timestamp}]\n{data}\n{'-'*40}\n")

def analyze_password(pwd):
    entropy = calculate_entropy(pwd)
    strength, _ = strength_color_and_label(entropy, len(pwd))
    common = pwd.lower() in COMMON_PASSWORDS
    pattern = any(p in pwd.lower() for p in KEYBOARD_PATTERNS) if user_settings["check_keyboard_patterns"] else False
    seq = any(pwd.lower()[i:i+3] in string.ascii_lowercase+string.digits for i in range(len(pwd)-2)) if user_settings["check_sequence"] else False
    leak = breached_k_anonymity(pwd) if user_settings["check_leak"] and len(pwd) >= 6 else None

    result = (
        f"Password: {'*' * len(pwd)}\n"
        f"Entropy: {entropy} bits\n"
        f"Common: {'Yes' if common else 'No'}\n"
        f"Keyboard Pattern: {'Yes' if pattern else 'No'}\n"
        f"Sequential Pattern: {'Yes' if seq else 'No'}\n"
        f"HIBP Breached: {('Yes' if leak else 'No') if leak is not None else 'Skipped'}\n"
        f"Strength: {strength}"
    )
    return result, entropy

# === GUI Logic ===
def update_analysis(event=None):
    global last_analysis, last_entropy
    pwd = entry.get()
    if not pwd:
        status_label.config(text="Enter a password", bg="white")
        result_box.config(state="normal")
        result_box.delete("1.0", tk.END)
        result_box.config(state="disabled")
        return

    last_analysis, last_entropy = analyze_password(pwd)
    log_analysis(last_analysis)

    strength = last_analysis.splitlines()[-1].split(": ")[-1]
    color = strength_color_and_label(last_entropy, len(pwd))[1]
    status_label.config(text=strength, bg=color)

    result_box.config(state='normal')
    result_box.delete('1.0', tk.END)
    result_box.insert(tk.END, last_analysis)
    result_box.config(state='disabled')

def suggest_password():
    new_pwd = ''.join(random.choices(string.ascii_letters + string.digits + string.punctuation, k=12))
    entry.delete(0, tk.END)
    entry.insert(0, new_pwd)
    update_analysis()

def export_pdf():
    if not last_analysis:
        messagebox.showinfo("No Data", "Please analyze a password first.")
        return
    filepath = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF files", "*.pdf")])
    if filepath:
        c = canvas.Canvas(filepath, pagesize=A4)
        text_obj = c.beginText(40, 800)
        text_obj.setFont("Helvetica", 12)
        for line in last_analysis.splitlines():
            text_obj.textLine(line)
        c.drawText(text_obj)
        c.save()
        messagebox.showinfo("Saved", f"PDF saved to:\n{filepath}")

def plot_entropy():
    if last_entropy <= 0:
        messagebox.showinfo("No Entropy", "Please analyze a password first.")
        return
    plt.figure(figsize=(6,4))
    plt.bar(["Entropy"], [last_entropy], color='skyblue')
    plt.axhline(y=28, color='red', linestyle='--', label="Weak Threshold")
    plt.title("Password Entropy")
    plt.ylabel("Bits")
    plt.ylim(0, 100)
    plt.legend()
    plt.tight_layout()
    plt.show()

def open_settings():
    settings_window = tk.Toplevel(root)
    settings_window.title("Customize Rules")
    settings_window.geometry("300x200")

    def apply_settings():
        try:
            user_settings["min_length"] = int(min_len_var.get())
            user_settings["check_leak"] = leak_var.get()
            user_settings["check_sequence"] = seq_var.get()
            user_settings["check_keyboard_patterns"] = pattern_var.get()
            settings_window.destroy()
        except ValueError:
            messagebox.showerror("Invalid Input", "Minimum length must be an integer.")

    min_len_var = tk.StringVar(value=str(user_settings["min_length"]))
    leak_var = tk.BooleanVar(value=user_settings["check_leak"])
    seq_var = tk.BooleanVar(value=user_settings["check_sequence"])
    pattern_var = tk.BooleanVar(value=user_settings["check_keyboard_patterns"])

    tk.Label(settings_window, text="Minimum Password Length:").pack()
    tk.Entry(settings_window, textvariable=min_len_var).pack()
    tk.Checkbutton(settings_window, text="Check for Leak (HIBP)", variable=leak_var).pack()
    tk.Checkbutton(settings_window, text="Check for Sequential Patterns", variable=seq_var).pack()
    tk.Checkbutton(settings_window, text="Check for Keyboard Patterns", variable=pattern_var).pack()
    tk.Button(settings_window, text="Apply", command=apply_settings).pack(pady=10)

def view_logs():
    try:
        with open("audit_log.txt", "r") as f:
            data = f.read()
        log_window = tk.Toplevel(root)
        log_window.title("Audit Log Viewer")
        log_window.geometry("500x400")
        log_text = scrolledtext.ScrolledText(log_window, wrap=tk.WORD)
        log_text.pack(expand=True, fill='both')
        log_text.insert(tk.END, data)
        log_text.config(state='disabled')
    except FileNotFoundError:
        messagebox.showinfo("Log Not Found", "No log file found yet.")

# === GUI Setup ===
root = tk.Tk()
root.title("Advanced Password Checker")
root.geometry("550x700")

# === Icon and Logo ===
try:
    root.iconbitmap("icon.ico")
except Exception as e:
    print("icon.ico not found. Please ensure it's in the same folder.")

try:
    logo_img = Image.open("logo.png").resize((500, 100))
    logo_tk = ImageTk.PhotoImage(logo_img)
    logo_label = tk.Label(root, image=logo_tk)
    logo_label.image = logo_tk
    logo_label.pack(pady=5)
except:
    print("logo.png not found.")

# === Widgets ===
tk.Label(root, text="Enter Password:", font=("Arial", 12)).pack(pady=5)
entry = tk.Entry(root, show="*", font=("Arial", 14), width=30)
entry.pack()
entry.bind("<KeyRelease>", update_analysis)

status_label = tk.Label(root, text="", font=("Arial", 12), width=20)
status_label.pack(pady=5)

result_box = tk.Text(root, state='disabled', wrap='word', height=12, width=60)
result_box.pack(pady=10)

# Buttons
tk.Button(root, text="Suggest Strong Password", command=suggest_password).pack(pady=5)
tk.Button(root, text="Export as PDF", command=export_pdf).pack(pady=5)
tk.Button(root, text="Customize Rules", command=open_settings).pack(pady=5)
tk.Button(root, text="Plot Entropy", command=plot_entropy).pack(pady=5)
tk.Button(root, text="View Audit Logs", command=view_logs).pack(pady=5)
tk.Button(root, text="Toggle Dark Mode", command=toggle_theme).pack(pady=5)
tk.Button(root, text="Check Clipboard", command=check_clipboard_password).pack(pady=5)
tk.Button(root, text="Simulate Dictionary Attack", command=simulate_dictionary_attack).pack(pady=5)

tk.Label(root, text="Developed by Hasan", font=("Arial", 10), fg="gray").pack(pady=5)

root.mainloop()
