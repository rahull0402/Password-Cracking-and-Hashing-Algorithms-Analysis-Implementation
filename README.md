# Password Cracking and Hashing Algorithms – Analysis & Implementation

---

## 📌 Description

This project is a **hands-on cybersecurity lab** demonstrating password hashing, salting, and cracking using **Python** alongside popular tools **John the Ripper** and **Hashcat**.

Designed for beginners and learners, it explains:

- How common hash algorithms (MD5, SHA-256, bcrypt) work
- The importance of salting to enhance password security
- Fundamentals of brute-force and dictionary attacks
- How to use John the Ripper and Hashcat for password cracking

The repository contains Python scripts for hashing and cracking demos, example hashes, and instructions for setup and usage with detailed code comments.

⚠️ **Ethical Use:** Use this project responsibly and legally. Only run password cracking on systems/data you own or have explicit permission to test.

---

## 📦 Project Structure

password-cracking-lab/

│


├── scripts/


│ ├── password_demo.py # Hashing & salting demo + brute-force simulation


│ ├── john_demo.py # John the Ripper demonstration


│ ├── hashcat_demo.py # Hashcat demonstration


│


├── install_lab.sh # Installs dependencies and environment setup


├── README.md # This file


└── (wordlists, example hashes, etc.)


Key components:

install_lab.sh – one-step setup for Kali/Ubuntu (Python 3, Hashcat, John, bcrypt, sample data).

scripts/password_demo.py – hashing & salting tutorial (MD5, SHA-256, bcrypt) with timing and cracking demos.

scripts/john_demo.py – Python-driven John-the-Ripper dictionary/brute-force showcase.

scripts/hashcat_demo.py – Python-driven Hashcat benchmark, dictionary, brute-force, and hybrid attacks.

wordlists/common_passwords.txt + rockyou extraction helper.

COMMANDS TO RUN THE PROJECT


chmod +x install_lab.sh


./install_lab.sh        # install & build lab


cd ~/password-cracking-lab


source venv/bin/activate


python3 scripts/password_demo.py   # hashing walkthrough


python3 scripts/john_demo.py       # John demo


python3 scripts/hashcat_demo.py    # Hashcat demo


