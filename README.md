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

```bash
password-cracking-lab/
│
├── scripts/
│   ├── password_demo.py
│   ├── john_demo.py        
│   ├── hashcat_demo.py     
│
├── wordlists/
│   └── common_passwords.txt  # Example wordlist (with rockyou.txt helper)
│
├── install_lab.sh          
├── README.md               
└── example_hashes.txt      
```

⚙️ Installation & Setup

Run the following commands in Kali Linux / Ubuntu:

```bash
# Make installer executable
chmod +x install_lab.sh  

# Run setup
./install_lab.sh  

# Navigate to project
cd ~/password-cracking-lab  

# Activate virtual environment
source venv/bin/activate
```






## 📘 Learning Outcomes

By completing this lab, you will:

✔ Understand password hashing & salting techniques

✔ Learn brute-force and dictionary attack fundamentals

✔ Use Python to implement simple cracking simulations

✔ Run real-world cracking tools (John the Ripper, Hashcat)

## ✅ Requirements

- Python 3.8+
- Kali Linux / Ubuntu
- Hashcat
- John the Ripper 
- bcrypt library 


---



## 📄 License

MIT License. Free to use and extend with credit.

---






















