# Create practical password cracking demonstration scripts

# John the Ripper integration script
john_demo = """#!/usr/bin/env python3
\"\"\"
John the Ripper Integration Demo
Demonstrates how to use John the Ripper from Python

LEGAL NOTICE: Educational use only. Test only on systems you own.
\"\"\"

import subprocess
import os
import sys
import time
from pathlib import Path

class JohnTheRipperDemo:
    def __init__(self, project_dir="/home/kali/password-cracking-lab"):
        self.project_dir = Path(project_dir)
        self.john_path = self.find_john()
        self.wordlist_dir = self.project_dir / "wordlists"
        self.hash_dir = self.project_dir / "hash_files"
        
    def find_john(self):
        \"\"\"Find John the Ripper executable\"\"\"
        possible_paths = [
            "/usr/bin/john",
            "/usr/sbin/john", 
            "/opt/john/run/john",
            "john"  # In PATH
        ]
        
        for path in possible_paths:
            try:
                result = subprocess.run([path, "--version"], 
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    return path
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue
        
        return None
    
    def check_installation(self):
        \"\"\"Check if John the Ripper is properly installed\"\"\"
        if not self.john_path:
            print("❌ John the Ripper not found!")
            print("\\nInstallation commands:")
            print("  Ubuntu/Debian: sudo apt install john")
            print("  Kali Linux: john (pre-installed)")
            return False
        
        try:
            result = subprocess.run([self.john_path, "--version"], 
                                  capture_output=True, text=True, timeout=5)
            print(f"✅ John the Ripper found: {self.john_path}")
            print(f"Version info: {result.stdout.strip().split()[0]}")
            return True
        except Exception as e:
            print(f"❌ Error checking John the Ripper: {e}")
            return False
    
    def list_formats(self):
        \"\"\"List supported hash formats\"\"\"
        try:
            result = subprocess.run([self.john_path, "--list=formats"], 
                                  capture_output=True, text=True, timeout=10)
            formats = result.stdout.strip().split(',')
            
            print("\\n📋 Supported hash formats (first 20):")
            for i, fmt in enumerate(formats[:20]):
                print(f"  {i+1:2}. {fmt.strip()}")
            
            if len(formats) > 20:
                print(f"  ... and {len(formats) - 20} more formats")
            
            return formats
        except Exception as e:
            print(f"❌ Error listing formats: {e}")
            return []
    
    def create_test_hashes(self):
        \"\"\"Create test hash files for demonstration\"\"\"
        print("\\n🔧 Creating test hash files...")
        
        # Create shadow-style hash file
        shadow_content = \"\"\"testuser:$6$salt123456$IxDD3jeSOb5eB1CX5LBsqZFVkJdido3OUILO5Ifz5iwMuTS4XMS130MTSuDDl3aCI6WouIL9AjRbLCelDCy.g.:18849:0:99999:7:::
admin:$1$salt789$7qvF2fX0mGJjOWNfgcRaj/:18849:0:99999:7:::
guest:password123
\"\"\"
        
        shadow_file = self.hash_dir / "shadow_test.txt"
        with open(shadow_file, 'w') as f:
            f.write(shadow_content)
        
        # Create simple password hash file
        simple_content = \"\"\"user1:5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
user2:098f6bcd4621d373cade4e832627b4f6
user3:482c811da5d5b4bc6d497ffa98491e38
\"\"\"
        
        simple_file = self.hash_dir / "simple_hashes.txt"
        with open(simple_file, 'w') as f:
            f.write(simple_content)
        
        print(f"✅ Created {shadow_file}")
        print(f"✅ Created {simple_file}")
        
        return str(shadow_file), str(simple_file)
    
    def run_dictionary_attack(self, hash_file, wordlist=None, hash_format=None):
        \"\"\"Run dictionary attack with John the Ripper\"\"\"
        if not wordlist:
            wordlist = self.wordlist_dir / "common_passwords.txt"
        
        print(f"\\n🔍 Starting dictionary attack...")
        print(f"Hash file: {hash_file}")
        print(f"Wordlist: {wordlist}")
        
        cmd = [self.john_path, "--wordlist=" + str(wordlist)]
        
        if hash_format:
            cmd.extend(["--format=" + hash_format])
        
        cmd.append(str(hash_file))
        
        try:
            print(f"\\n🚀 Command: {' '.join(cmd)}")
            
            # Run the attack
            start_time = time.time()
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            elapsed = time.time() - start_time
            
            print(f"\\n📊 Attack completed in {elapsed:.2f} seconds")
            
            if result.stdout:
                print("\\n📝 Output:")
                print(result.stdout)
            
            if result.stderr:
                print("\\n⚠️  Warnings/Errors:")
                print(result.stderr)
            
            # Show cracked passwords
            self.show_cracked_passwords(hash_file)
            
        except subprocess.TimeoutExpired:
            print("\\n⏱️  Attack timed out (60 seconds)")
        except Exception as e:
            print(f"\\n❌ Attack failed: {e}")
    
    def show_cracked_passwords(self, hash_file):
        \"\"\"Show cracked passwords from john.pot\"\"\"
        try:
            result = subprocess.run([self.john_path, "--show", str(hash_file)], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.stdout.strip():
                print("\\n🎉 CRACKED PASSWORDS:")
                lines = result.stdout.strip().split('\\n')
                for line in lines:
                    if ':' in line and not line.startswith('password'):
                        print(f"  ✅ {line}")
            else:
                print("\\n😞 No passwords cracked yet")
                
        except Exception as e:
            print(f"\\n❌ Error showing cracked passwords: {e}")
    
    def run_brute_force_demo(self, hash_file, max_length=4):
        \"\"\"Run incremental (brute force) attack demo\"\"\"
        print(f"\\n🔥 Starting brute force attack (max length: {max_length})...")
        print(f"⚠️  This may take a while!")
        
        cmd = [
            self.john_path,
            "--incremental=alpha",
            f"--max-len={max_length}",
            str(hash_file)
        ]
        
        try:
            print(f"\\n🚀 Command: {' '.join(cmd)}")
            
            start_time = time.time()
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            elapsed = time.time() - start_time
            
            print(f"\\n📊 Brute force completed in {elapsed:.2f} seconds")
            
            if result.stdout:
                print("\\n📝 Output:")
                print(result.stdout)
            
            self.show_cracked_passwords(hash_file)
            
        except subprocess.TimeoutExpired:
            print("\\n⏱️  Brute force timed out (2 minutes)")
            self.show_cracked_passwords(hash_file)
        except Exception as e:
            print(f"\\n❌ Brute force failed: {e}")

def main():
    print("=" * 60)
    print("JOHN THE RIPPER INTEGRATION DEMO")
    print("=" * 60)
    print("\\n⚠️  EDUCATIONAL PURPOSE ONLY ⚠️")
    print("Only use on systems you own or have explicit permission to test.")
    print()
    
    # Initialize demo
    demo = JohnTheRipperDemo()
    
    # Check installation
    if not demo.check_installation():
        return 1
    
    # List supported formats
    demo.list_formats()
    
    # Create test files
    shadow_file, simple_file = demo.create_test_hashes()
    
    print("\\n" + "=" * 50)
    print("DEMONSTRATION 1: DICTIONARY ATTACK")
    print("=" * 50)
    
    # Dictionary attack on simple hashes
    demo.run_dictionary_attack(simple_file, hash_format="Raw-MD5")
    
    print("\\n" + "=" * 50)  
    print("DEMONSTRATION 2: SHADOW FILE ATTACK")
    print("=" * 50)
    
    # Dictionary attack on shadow file
    demo.run_dictionary_attack(shadow_file)
    
    print("\\n" + "=" * 50)
    print("DEMONSTRATION 3: BRUTE FORCE ATTACK")
    print("=" * 50)
    
    # Brute force attack (limited)
    demo.run_brute_force_demo(simple_file, max_length=3)
    
    print("\\n" + "=" * 60)
    print("JOHN THE RIPPER DEMO COMPLETE")
    print("=" * 60)
    print("\\nKey Commands to Remember:")
    print("1. john --wordlist=wordlist.txt hashfile.txt")
    print("2. john --incremental hashfile.txt")
    print("3. john --show hashfile.txt")
    print("4. john --list=formats")
    print()
    print("Remember: Use responsibly and ethically!")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
"""

with open('john_demo.py', 'w') as f:
    f.write(john_demo)

print("Created John the Ripper demo script: john_demo.py")
print(f"Script length: {len(john_demo.splitlines())} lines")