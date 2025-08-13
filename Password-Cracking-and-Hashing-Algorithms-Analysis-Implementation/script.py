# Let's create the complete Python project structure and code files

# First, let's create a comprehensive password hashing implementation with multiple algorithms
password_hash_demo = """#!/usr/bin/env python3
\"\"\"
Password Hashing and Cracking Demonstration
Author: Cybersecurity Instructor
Purpose: Educational demonstration of password hashing techniques and security

LEGAL NOTICE:
This code is for educational purposes only. Only use on systems you own 
or have explicit written permission to test. Unauthorized access to 
computer systems is illegal and may result in criminal charges.
\"\"\"

import hashlib
import bcrypt
import secrets
import base64
import os
import time
from typing import List, Tuple, Dict
import json

class PasswordHasher:
    \"\"\"
    Comprehensive password hashing demonstration class
    Implements multiple hashing algorithms for educational comparison
    \"\"\"
    
    def __init__(self):
        self.algorithms = ['md5', 'sha1', 'sha256', 'sha512', 'bcrypt']
        self.results = {}
    
    def generate_salt(self, length: int = 32) -> str:
        \"\"\"
        Generate a cryptographically secure random salt
        
        Args:
            length (int): Length of salt in bytes
            
        Returns:
            str: Hex encoded salt
        \"\"\"
        return secrets.token_hex(length)
    
    def hash_md5(self, password: str, salt: str = None) -> Dict[str, str]:
        \"\"\"
        Hash password using MD5 (WEAK - for demonstration only)
        
        Args:
            password (str): Plain text password
            salt (str): Optional salt
            
        Returns:
            dict: Hash details
        \"\"\"
        if not salt:
            salt = self.generate_salt(16)
        
        salted_password = password + salt
        hash_obj = hashlib.md5(salted_password.encode('utf-8'))
        
        return {
            'algorithm': 'MD5',
            'salt': salt,
            'hash': hash_obj.hexdigest(),
            'salted_input': salted_password
        }
    
    def hash_sha256(self, password: str, salt: str = None) -> Dict[str, str]:
        \"\"\"
        Hash password using SHA-256
        
        Args:
            password (str): Plain text password
            salt (str): Optional salt
            
        Returns:
            dict: Hash details
        \"\"\"
        if not salt:
            salt = self.generate_salt(32)
        
        salted_password = password + salt
        hash_obj = hashlib.sha256(salted_password.encode('utf-8'))
        
        return {
            'algorithm': 'SHA-256',
            'salt': salt,
            'hash': hash_obj.hexdigest(),
            'salted_input': salted_password
        }
    
    def hash_bcrypt(self, password: str, rounds: int = 12) -> Dict[str, str]:
        \"\"\"
        Hash password using bcrypt (RECOMMENDED)
        
        Args:
            password (str): Plain text password
            rounds (int): Cost parameter (work factor)
            
        Returns:
            dict: Hash details
        \"\"\"
        # Generate salt with specified rounds
        salt = bcrypt.gensalt(rounds=rounds)
        
        # Hash the password
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        
        return {
            'algorithm': 'bcrypt',
            'rounds': rounds,
            'salt': salt.decode('utf-8'),
            'hash': hashed.decode('utf-8'),
            'full_hash': hashed.decode('utf-8')  # bcrypt includes salt in output
        }
    
    def verify_bcrypt(self, password: str, stored_hash: str) -> bool:
        \"\"\"
        Verify password against bcrypt hash
        
        Args:
            password (str): Plain text password to verify
            stored_hash (str): Stored bcrypt hash
            
        Returns:
            bool: True if password matches
        \"\"\"
        return bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8'))
    
    def demonstrate_timing_attack(self, password: str, iterations: int = 1000):
        \"\"\"
        Demonstrate timing differences between algorithms
        
        Args:
            password (str): Test password
            iterations (int): Number of iterations to average
        \"\"\"
        results = {}
        
        print(f"\\n=== TIMING ANALYSIS ({iterations} iterations) ===")
        print(f"Password: '{password}'\\n")
        
        # Test MD5
        start_time = time.time()
        for _ in range(iterations):
            self.hash_md5(password)
        md5_time = (time.time() - start_time) / iterations
        results['MD5'] = md5_time
        
        # Test SHA-256
        start_time = time.time()
        for _ in range(iterations):
            self.hash_sha256(password)
        sha256_time = (time.time() - start_time) / iterations
        results['SHA-256'] = sha256_time
        
        # Test bcrypt (fewer iterations due to intentional slowness)
        bcrypt_iterations = min(10, iterations // 100)  # Much fewer iterations
        start_time = time.time()
        for _ in range(bcrypt_iterations):
            self.hash_bcrypt(password, rounds=10)
        bcrypt_time = (time.time() - start_time) / bcrypt_iterations
        results['bcrypt'] = bcrypt_time
        
        # Display results
        for algo, avg_time in results.items():
            print(f"{algo:>10}: {avg_time:.6f} seconds per hash")
        
        print(f"\\nbcrypt is {bcrypt_time/md5_time:.1f}x slower than MD5 (by design!)")
        print("This makes brute force attacks much more expensive.")
        
        return results

class PasswordCracker:
    \"\"\"
    Simple password cracking demonstration for educational purposes
    \"\"\"
    
    def __init__(self):
        self.hasher = PasswordHasher()
        self.common_passwords = [
            "password", "123456", "password123", "admin", "qwerty",
            "letmein", "welcome", "monkey", "1234567890", "abc123",
            "Password1", "password1", "root", "toor", "pass"
        ]
    
    def brute_force_demo(self, target_hash: str, algorithm: str, salt: str = None, max_attempts: int = 1000):
        \"\"\"
        Demonstrate simple brute force attack
        
        Args:
            target_hash (str): Hash to crack
            algorithm (str): Hashing algorithm used
            salt (str): Salt used (if any)
            max_attempts (int): Maximum attempts before giving up
        \"\"\"
        print(f"\\n=== BRUTE FORCE DEMONSTRATION ===")
        print(f"Target hash: {target_hash}")
        print(f"Algorithm: {algorithm}")
        print(f"Salt: {salt if salt else 'None'}")
        print(f"Max attempts: {max_attempts}\\n")
        
        attempts = 0
        start_time = time.time()
        
        # Try common passwords first
        for password in self.common_passwords:
            attempts += 1
            
            if algorithm.upper() == 'MD5':
                computed = self.hasher.hash_md5(password, salt)['hash']
            elif algorithm.upper() == 'SHA-256':
                computed = self.hasher.hash_sha256(password, salt)['hash']
            else:
                print(f"Algorithm {algorithm} not supported in this demo")
                return None
            
            if computed == target_hash:
                elapsed = time.time() - start_time
                print(f"✓ PASSWORD FOUND: '{password}'")
                print(f"✓ Attempts: {attempts}")
                print(f"✓ Time: {elapsed:.2f} seconds")
                print(f"✓ Rate: {attempts/elapsed:.1f} attempts/second")
                return password
            
            if attempts >= max_attempts:
                break
        
        elapsed = time.time() - start_time
        print(f"✗ Password not found in {attempts} attempts")
        print(f"✗ Time elapsed: {elapsed:.2f} seconds")
        print(f"✗ Rate: {attempts/elapsed:.1f} attempts/second")
        return None
    
    def dictionary_attack_demo(self, target_hash: str, algorithm: str, wordlist: List[str], salt: str = None):
        \"\"\"
        Demonstrate dictionary attack
        
        Args:
            target_hash (str): Hash to crack
            algorithm (str): Hashing algorithm
            wordlist (list): List of passwords to try
            salt (str): Salt used (if any)
        \"\"\"
        print(f"\\n=== DICTIONARY ATTACK DEMONSTRATION ===")
        print(f"Target hash: {target_hash}")
        print(f"Algorithm: {algorithm}")
        print(f"Wordlist size: {len(wordlist)} passwords")
        print(f"Salt: {salt if salt else 'None'}\\n")
        
        attempts = 0
        start_time = time.time()
        
        for password in wordlist:
            attempts += 1
            
            if algorithm.upper() == 'MD5':
                computed = self.hasher.hash_md5(password, salt)['hash']
            elif algorithm.upper() == 'SHA-256':
                computed = self.hasher.hash_sha256(password, salt)['hash']
            else:
                print(f"Algorithm {algorithm} not supported in this demo")
                return None
            
            if computed == target_hash:
                elapsed = time.time() - start_time
                print(f"✓ PASSWORD FOUND: '{password}'")
                print(f"✓ Attempts: {attempts}")
                print(f"✓ Time: {elapsed:.2f} seconds")
                return password
            
            # Show progress every 1000 attempts
            if attempts % 1000 == 0:
                print(f"Tried {attempts} passwords...")
        
        elapsed = time.time() - start_time
        print(f"✗ Password not found in {attempts} attempts")
        print(f"✗ Time elapsed: {elapsed:.2f} seconds")
        return None

def generate_sample_wordlist(size: int = 100) -> List[str]:
    \"\"\"
    Generate a sample wordlist for demonstration
    
    Args:
        size (int): Number of passwords to generate
        
    Returns:
        list: Sample passwords
    \"\"\"
    common = ["password", "123456", "password123", "admin", "qwerty", "letmein"]
    
    # Add variations
    wordlist = common[:]
    
    # Add year variations
    for base in ["password", "admin", "test"]:
        for year in range(2020, 2025):
            wordlist.append(f"{base}{year}")
            wordlist.append(f"{base}@{year}")
    
    # Add simple patterns
    for i in range(1, 21):
        wordlist.append(f"password{i}")
        wordlist.append(f"{i}password")
        wordlist.append(f"test{i}")
    
    # Ensure we have enough entries
    while len(wordlist) < size:
        wordlist.append(f"password{len(wordlist)}")
    
    return wordlist[:size]

def main():
    \"\"\"
    Main demonstration function
    \"\"\"
    print("="*60)
    print("PASSWORD HASHING AND CRACKING DEMONSTRATION")
    print("="*60)
    print()
    print("⚠️  EDUCATIONAL PURPOSE ONLY ⚠️")
    print("This demonstration is for learning cybersecurity concepts.")
    print("Only use on systems you own or have explicit permission to test.")
    print()
    
    # Initialize classes
    hasher = PasswordHasher()
    cracker = PasswordCracker()
    
    # Demonstration password
    demo_password = "MySecret123"
    
    print(f"Demo password: '{demo_password}'")
    print()
    
    # === HASHING DEMONSTRATION ===
    print("="*50)
    print("PART 1: HASHING ALGORITHMS COMPARISON")
    print("="*50)
    
    # Hash with different algorithms
    md5_result = hasher.hash_md5(demo_password)
    sha256_result = hasher.hash_sha256(demo_password)
    bcrypt_result = hasher.hash_bcrypt(demo_password)
    
    print("\\nMD5 (WEAK - DO NOT USE):")
    print(f"  Salt: {md5_result['salt']}")
    print(f"  Hash: {md5_result['hash']}")
    
    print("\\nSHA-256 (Better, but still vulnerable to rainbow tables):")
    print(f"  Salt: {sha256_result['salt']}")
    print(f"  Hash: {sha256_result['hash']}")
    
    print("\\nbcrypt (RECOMMENDED):")
    print(f"  Full hash: {bcrypt_result['full_hash']}")
    print(f"  Rounds: {bcrypt_result['rounds']}")
    
    # === TIMING DEMONSTRATION ===
    hasher.demonstrate_timing_attack(demo_password, 100)
    
    # === CRACKING DEMONSTRATION ===
    print("\\n" + "="*50)
    print("PART 2: PASSWORD CRACKING DEMONSTRATION")
    print("="*50)
    
    # Create a target to crack (using a common password)
    weak_password = "password123"
    weak_hash_result = hasher.hash_md5(weak_password)
    
    print(f"\\nTarget password (hidden): '{weak_password}'")
    print("Now attempting to crack the hash...")
    
    # Demonstrate brute force
    cracked = cracker.brute_force_demo(
        weak_hash_result['hash'], 
        'MD5', 
        weak_hash_result['salt']
    )
    
    # === SECURITY DEMONSTRATION ===
    print("\\n" + "="*50)
    print("PART 3: WHY BCRYPT IS BETTER")
    print("="*50)
    
    print("\\n1. bcrypt includes salt automatically")
    print("2. bcrypt is intentionally slow (adjustable work factor)")
    print("3. bcrypt is resistant to rainbow table attacks")
    print("4. bcrypt has been battle-tested for decades")
    
    # Verify bcrypt password
    print("\\nTesting bcrypt password verification:")
    is_correct = hasher.verify_bcrypt(demo_password, bcrypt_result['full_hash'])
    print(f"Password '{demo_password}' verification: {is_correct}")
    
    is_wrong = hasher.verify_bcrypt("wrongpassword", bcrypt_result['full_hash'])
    print(f"Password 'wrongpassword' verification: {is_wrong}")
    
    print("\\n" + "="*60)
    print("DEMONSTRATION COMPLETE")
    print("="*60)
    print()
    print("KEY TAKEAWAYS:")
    print("1. Never use MD5 or SHA1 for passwords")
    print("2. Always use a proper salt")
    print("3. bcrypt is currently the gold standard")
    print("4. Consider scrypt or Argon2 for new projects")
    print("5. Increase bcrypt rounds as hardware gets faster")
    print()
    print("Remember: This is for educational purposes only!")

if __name__ == "__main__":
    main()
"""

print("Created comprehensive password hashing demonstration script:")
print(f"Total lines: {len(password_hash_demo.splitlines())}")