# 🔐 Advanced Password Strength Checker

This is a feature-rich password analysis tool built with Python and Tkinter. It evaluates password strength using entropy calculations, detects common and weak patterns, simulates dictionary attacks, checks leaks via the Have I Been Pwned API, and more — all within an interactive GUI.

---

## 🚀 Features

- Entropy-based strength calculation (Very Weak to Very Strong)
- Detects:
  - Common passwords
  - Keyboard patterns (`qwerty`, `asdf`, etc.)
  - Sequential characters (`abc`, `123`)
- Dark mode support
- Clipboard password checker
- Random strong password generator
- Simulates dictionary attack
- View audit log of past checks
- Exports password analysis as PDF
- Plots entropy using Matplotlib
- User settings for custom rules

---

## 🛠️ Tech Stack

- Python 3
- Tkinter GUI
- Matplotlib
- ReportLab (PDF generation)
- HaveIBeenPwned API
- Pillow (for image display)

---

## 📦 How to Run

```bash
python "password checker.py"
