#!/bin/bash
# Password Cracking Lab Setup Script
# For Ubuntu 20.04+ and Kali Linux
# Author: Cybersecurity Instructor

echo "=================================================="
echo "PASSWORD CRACKING LAB SETUP"
echo "=================================================="
echo ""
echo "⚠️  LEGAL NOTICE ⚠️"
echo "This setup is for educational purposes only."
echo "Only use on systems you own or have explicit permission to test."
echo "Unauthorized access to computer systems is illegal."
echo ""
read -p "Do you agree to use this for educational purposes only? (y/n): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Setup cancelled."
    exit 1
fi

echo ""
echo "Starting installation..."
echo ""

# Update system
echo "1. Updating system packages..."
sudo apt update && sudo apt upgrade -y

# Install Python 3 and pip
echo ""
echo "2. Installing Python 3 and pip..."
sudo apt install -y python3 python3-pip python3-venv

# Install development tools
echo ""
echo "3. Installing development tools..."
sudo apt install -y build-essential git curl wget

# Install password cracking tools
echo ""
echo "4. Installing password cracking tools..."
sudo apt install -y hashcat john

# Install hashcat utilities (if available)
echo ""
echo "5. Installing additional utilities..."
sudo apt install -y hashcat-utils 2>/dev/null || echo "hashcat-utils not available, skipping..."

# Create project directory
echo ""
echo "6. Setting up project directory..."
PROJECT_DIR="$HOME/password-cracking-lab"
mkdir -p "$PROJECT_DIR"
cd "$PROJECT_DIR"

# Create Python virtual environment
echo ""
echo "7. Creating Python virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
echo ""
echo "8. Installing Python dependencies..."
cat > requirements.txt << EOF
bcrypt>=4.0.1
hashlib
secrets
colorama>=0.4.6
tabulate>=0.9.0
click>=8.1.0
EOF

pip install -r requirements.txt

# Download wordlists
echo ""
echo "9. Setting up wordlists..."
mkdir -p wordlists

# Extract rockyou.txt if available
if [ -f "/usr/share/wordlists/rockyou.txt.gz" ]; then
    echo "Extracting rockyou.txt..."
    sudo gunzip -k /usr/share/wordlists/rockyou.txt.gz 2>/dev/null || echo "rockyou.txt already extracted"
    cp /usr/share/wordlists/rockyou.txt wordlists/ 2>/dev/null || echo "Could not copy rockyou.txt"
fi

# Create sample wordlists
echo ""
echo "10. Creating sample wordlists..."
cat > wordlists/common_passwords.txt << EOF
password
123456
password123
admin
qwerty
letmein
welcome
monkey
1234567890
abc123
Password1
password1
root
toor
pass
login
guest
test
user
administrator
secret
changeme
dragon
master
hello
access
superman
sunshine
shadow
EOF

cat > wordlists/years.txt << EOF
2024
2023
2022
2021
2020
2019
2018
EOF

# Create project structure
echo ""
echo "11. Creating project structure..."
mkdir -p scripts examples hash_files cracked_passwords logs

# Create example hash files
echo ""
echo "12. Creating example hash files..."
cat > hash_files/example_md5.txt << EOF
5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
098f6bcd4621d373cade4e832627b4f6
482c811da5d5b4bc6d497ffa98491e38
EOF

cat > hash_files/example_sha256.txt << EOF
ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f
a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3
5994471abb01112afcc18159f6cc74b4f511b99806da59b3caf5a9c173cacfc5
EOF

# Create README
echo ""
echo "13. Creating documentation..."
cat > README.md << 'EOF'
# Password Cracking and Hashing Lab

This is an educational cybersecurity lab for learning about password hashing and cracking techniques.

## ⚠️ LEGAL NOTICE
This lab is for educational purposes only. Only use on systems you own or have explicit written permission to test. Unauthorized access to computer systems is illegal and may result in criminal charges.

## Lab Structure
```
password-cracking-lab/
├── venv/                    # Python virtual environment
├── scripts/                 # Python demonstration scripts
├── wordlists/              # Password wordlists
├── hash_files/             # Example hash files for testing
├── examples/               # Example attack scenarios
├── cracked_passwords/      # Results storage
├── logs/                   # Operation logs
└── requirements.txt        # Python dependencies
```

## Quick Start
1. Activate virtual environment: `source venv/bin/activate`
2. Run main demo: `python3 scripts/password_demo.py`
3. Try hash cracking: `python3 scripts/crack_demo.py`

## Tools Installed
- Hashcat: GPU-accelerated password cracking
- John the Ripper: CPU-based password cracking
- Python bcrypt: Secure password hashing
- Custom scripts: Educational demonstrations

## Learning Objectives
1. Understand different hashing algorithms
2. Learn about password salting
3. Experience brute-force and dictionary attacks
4. Recognize the importance of strong passwords
5. Practice ethical hacking methodologies

## Usage Examples
See the `examples/` directory for specific scenarios and tutorials.

Remember: With great power comes great responsibility!
EOF

# Set permissions
chmod +x *.sh 2>/dev/null || true

echo ""
echo "=================================================="
echo "INSTALLATION COMPLETE!"
echo "=================================================="
echo ""
echo "Lab directory: $PROJECT_DIR"
echo ""
echo "To get started:"
echo "1. cd $PROJECT_DIR"
echo "2. source venv/bin/activate"
echo "3. python3 scripts/password_demo.py"
echo ""
echo "Installed tools:"
echo "- Hashcat: $(hashcat --version 2>/dev/null || echo 'Not found')"
echo "- John the Ripper: $(john --list=build-info 2>/dev/null | head -1 || echo 'Not found')"
echo "- Python: $(python3 --version)"
echo ""
echo "Happy (ethical) hacking! 🔐"
