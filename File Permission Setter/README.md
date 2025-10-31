# 🛠️ File Permission Setter (Python)

This is a simple Python script that allows you to **change file permissions** directly from the terminal.  
It provides a quick way to control who can **read, write, or execute** a file — similar to the Linux `chmod` command.

---

## 🚀 Features
- Change file permissions easily using octal notation (e.g., `755`, `644`, etc.)
- Handles invalid file paths and errors gracefully
- Works on **Windows, macOS, and Linux**

---

## 🧩 How It Works
1. The script prompts you to enter:
   - The **file path** (e.g., `C:\Users\example\test.txt` or `/home/user/test.txt`)
   - The **permissions** in octal format (e.g., `755`)
2. It then applies the new permissions using Python’s built-in `os.chmod()` function.

---

## 🧠 Permission Breakdown
| Octal | Description              | Owner | Group | Others |
|:------|:--------------------------|:------:|:------:|:-------:|
| `777` | Read, write, execute all | rwx | rwx | rwx |
| `755` | Owner full, others execute & read | rwx | r-x | r-x |
| `644` | Owner read & write, others read | rw- | r-- | r-- |
| `600` | Owner read & write only | rw- | --- | --- |

---

## 💻 Example Usage

```bash
Enter File Path: test.py
Enter File permissions: 755
File permissions for 'test.py' have been set.
