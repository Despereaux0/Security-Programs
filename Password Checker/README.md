# 🔐 Password Strength Checker

A simple yet effective Python program that checks how strong your password is based on various security criteria.  
It works both in **IDLE** and **terminal/command prompt**, automatically choosing the best input method.

---

## 🚀 Features

- Checks for:
  - Password length (≥ 12 characters)
  - Uppercase and lowercase letters
  - Numbers
  - Special characters
- Gives a clear **strength rating** (Very Weak → Very Strong)
- Provides **security tips** for stronger passwords
- Automatically switches between secure `getpass()` and normal `input()` for compatibility

---

## 🧠 How It Works

The program uses regular expressions (`re` module) to test your password against key criteria.  
Each satisfied condition increases the score, which determines the final strength level.

| Criteria | Description |
|-----------|--------------|
| ✅ Length | At least 12 characters |
| 🔠 Uppercase | Contains at least one uppercase letter |
| 🔡 Lowercase | Contains at least one lowercase letter |
| 🔢 Number | Contains at least one digit |
| 💥 Special | Contains at least one special symbol |

---

## 🖥️ Usage

1. Make sure Python 3 is installed on your system.
2. Save the script as `password_strength_checker.py`.
3. Run it in your terminal or IDLE:

```bash
python password_strength_checker.py
