#!/usr/bin/env python3
"""
Hashcat Integration Demo
Demonstrates how to use Hashcat from Python for educational purposes

LEGAL NOTICE: Educational use only. Test only on systems you own.
"""

import subprocess
import os
import sys
import time
from pathlib import Path
import re

class HashcatDemo:
    def __init__(self, project_dir="/home/kali/password-cracking-lab"):
        self.project_dir = Path(project_dir)
        self.hashcat_path = self.find_hashcat()
        self.wordlist_dir = self.project_dir / "wordlists"
        self.hash_dir = self.project_dir / "hash_files"

    def find_hashcat(self):
        """Find Hashcat executable"""
        possible_paths = [
            "/usr/bin/hashcat",
            "/usr/local/bin/hashcat",
            "hashcat"  # In PATH
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
        """Check if Hashcat is properly installed"""
        if not self.hashcat_path:
            print("❌ Hashcat not found!")
            print("\nInstallation commands:")
            print("  Ubuntu/Debian: sudo apt install hashcat")
            print("  Kali Linux: hashcat (pre-installed)")
            return False

        try:
            result = subprocess.run([self.hashcat_path, "--version"], 
                                  capture_output=True, text=True, timeout=5)
            print(f"✅ Hashcat found: {self.hashcat_path}")

            # Extract version from output
            version_match = re.search(r'v([\d.]+)', result.stdout)
            if version_match:
                print(f"Version: {version_match.group(1)}")

            return True
        except Exception as e:
            print(f"❌ Error checking Hashcat: {e}")
            return False

    def benchmark_test(self):
        """Run Hashcat benchmark"""
        print("\n🏃 Running Hashcat benchmark...")
        print("This will test your system's hash cracking performance.\n")

        try:
            cmd = [self.hashcat_path, "-b", "-m", "0"]  # MD5 benchmark
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            if result.stdout:
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'MD5' in line or 'H/s' in line:
                        print(f"📊 {line.strip()}")

            if result.stderr:
                print("\n⚠️  Benchmark warnings:")
                print(result.stderr[:500] + "..." if len(result.stderr) > 500 else result.stderr)

        except subprocess.TimeoutExpired:
            print("⏱️  Benchmark timed out")
        except Exception as e:
            print(f"❌ Benchmark failed: {e}")

    def list_hash_modes(self):
        """List common hash modes"""
        common_modes = {
            0: "MD5",
            100: "SHA1", 
            1400: "SHA2-256",
            1700: "SHA2-512",
            3200: "bcrypt",
            1800: "sha512crypt",
            500: "md5crypt",
            1000: "NTLM",
            3000: "LM",
            5500: "NetNTLMv1",
            5600: "NetNTLMv2"
        }

        print("\n📋 Common Hashcat modes:")
        for mode, name in common_modes.items():
            print(f"  {mode:>4}: {name}")

        return common_modes

    def create_test_hashes(self):
        """Create test hash files for demonstration"""
        print("\n🔧 Creating test hash files...")

        # MD5 hashes (known passwords: password, test, 123456)
        md5_content = """5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
098f6bcd4621d373cade4e832627b4f6
e10adc3949ba59abbe56e057f20f883e
"""

        md5_file = self.hash_dir / "md5_hashes.txt"
        with open(md5_file, 'w') as f:
            f.write(md5_content)

        # SHA-256 hashes
        sha256_content = """ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f
a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3
5994471abb01112afcc18159f6cc74b4f511b99806da59b3caf5a9c173cacfc5
"""

        sha256_file = self.hash_dir / "sha256_hashes.txt"
        with open(sha256_file, 'w') as f:
            f.write(sha256_content)

        print(f"✅ Created {md5_file}")
        print(f"✅ Created {sha256_file}")

        return str(md5_file), str(sha256_file)

    def dictionary_attack(self, hash_file, hash_mode, wordlist=None):
        """Run dictionary attack with Hashcat"""
        if not wordlist:
            wordlist = self.wordlist_dir / "common_passwords.txt"

        print(f"\n🔍 Starting dictionary attack...")
        print(f"Hash file: {hash_file}")
        print(f"Hash mode: {hash_mode}")
        print(f"Wordlist: {wordlist}")

        # Create output file
        output_file = self.project_dir / "cracked_passwords" / f"cracked_{hash_mode}_{int(time.time())}.txt"
        output_file.parent.mkdir(exist_ok=True)

        cmd = [
            self.hashcat_path,
            "-m", str(hash_mode),
            "-a", "0",  # Dictionary attack
            str(hash_file),
            str(wordlist),
            "-o", str(output_file),
            "--force"  # Ignore warnings for demo
        ]

        try:
            print(f"\n🚀 Command: {' '.join(cmd)}")

            start_time = time.time()
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            elapsed = time.time() - start_time

            print(f"\n📊 Attack completed in {elapsed:.2f} seconds")

            # Parse output for cracked hashes
            if result.stdout:
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'Recovered' in line or 'Cracked' in line:
                        print(f"✅ {line.strip()}")

            # Show cracked passwords
            if output_file.exists() and output_file.stat().st_size > 0:
                print(f"\n🎉 Cracked passwords saved to: {output_file}")
                with open(output_file, 'r') as f:
                    cracked = f.read().strip()
                    if cracked:
                        print("\n🔓 CRACKED PASSWORDS:")
                        for line in cracked.split('\n'):
                            print(f"  ✅ {line}")
            else:
                print("\n😞 No passwords cracked")

        except subprocess.TimeoutExpired:
            print("\n⏱️  Attack timed out (2 minutes)")
        except Exception as e:
            print(f"\n❌ Attack failed: {e}")

    def brute_force_attack(self, hash_file, hash_mode, min_len=1, max_len=4):
        """Run brute force attack with Hashcat"""
        print(f"\n🔥 Starting brute force attack...")
        print(f"Hash file: {hash_file}")
        print(f"Hash mode: {hash_mode}")
        print(f"Length: {min_len}-{max_len} characters")
        print("⚠️  This may take a while!")

        # Create output file
        output_file = self.project_dir / "cracked_passwords" / f"brute_force_{hash_mode}_{int(time.time())}.txt"
        output_file.parent.mkdir(exist_ok=True)

        # Use mask attack for brute force (all lowercase letters)
        mask = "?l" * max_len  # lowercase letters only for demo

        cmd = [
            self.hashcat_path,
            "-m", str(hash_mode),
            "-a", "3",  # Mask attack (brute force)
            str(hash_file),
            mask,
            f"--increment-min={min_len}",
            f"--increment-max={max_len}",
            "--increment",
            "-o", str(output_file),
            "--force"
        ]

        try:
            print(f"\n🚀 Command: {' '.join(cmd)}")

            start_time = time.time()
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)  # 5 minutes max
            elapsed = time.time() - start_time

            print(f"\n📊 Brute force completed in {elapsed:.2f} seconds")

            # Show results
            if output_file.exists() and output_file.stat().st_size > 0:
                print(f"\n🎉 Results saved to: {output_file}")
                with open(output_file, 'r') as f:
                    cracked = f.read().strip()
                    if cracked:
                        print("\n🔓 CRACKED PASSWORDS:")
                        for line in cracked.split('\n')[:10]:  # Show first 10
                            print(f"  ✅ {line}")
            else:
                print("\n😞 No passwords cracked in time limit")

        except subprocess.TimeoutExpired:
            print("\n⏱️  Brute force timed out (5 minutes)")
        except Exception as e:
            print(f"\n❌ Brute force failed: {e}")

    def hybrid_attack(self, hash_file, hash_mode, wordlist=None):
        """Run hybrid attack (wordlist + rules)"""
        if not wordlist:
            wordlist = self.wordlist_dir / "common_passwords.txt"

        print(f"\n🎯 Starting hybrid attack...")
        print(f"Hash file: {hash_file}")
        print(f"Wordlist: {wordlist}")
        print("This combines dictionary words with common patterns")

        # Create output file
        output_file = self.project_dir / "cracked_passwords" / f"hybrid_{hash_mode}_{int(time.time())}.txt"
        output_file.parent.mkdir(exist_ok=True)

        # Hybrid attack: wordlist + append digits
        cmd = [
            self.hashcat_path,
            "-m", str(hash_mode),
            "-a", "6",  # Hybrid wordlist + mask
            str(hash_file),
            str(wordlist),
            "?d?d",  # Append 2 digits
            "-o", str(output_file),
            "--force"
        ]

        try:
            print(f"\n🚀 Command: {' '.join(cmd)}")

            start_time = time.time()
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            elapsed = time.time() - start_time

            print(f"\n📊 Hybrid attack completed in {elapsed:.2f} seconds")

            # Show results
            if output_file.exists() and output_file.stat().st_size > 0:
                with open(output_file, 'r') as f:
                    cracked = f.read().strip()
                    if cracked:
                        print("\n🔓 CRACKED PASSWORDS:")
                        for line in cracked.split('\n'):
                            print(f"  ✅ {line}")
            else:
                print("\n😞 No passwords cracked")

        except subprocess.TimeoutExpired:
            print("\n⏱️  Hybrid attack timed out")
        except Exception as e:
            print(f"\n❌ Hybrid attack failed: {e}")

def main():
    print("=" * 60)
    print("HASHCAT INTEGRATION DEMO")
    print("=" * 60)
    print("\n⚠️  EDUCATIONAL PURPOSE ONLY ⚠️")
    print("Only use on systems you own or have explicit permission to test.")
    print()

    # Initialize demo
    demo = HashcatDemo()

    # Check installation
    if not demo.check_installation():
        return 1

    # Show benchmark
    demo.benchmark_test()

    # List hash modes
    demo.list_hash_modes()

    # Create test files
    md5_file, sha256_file = demo.create_test_hashes()

    print("\n" + "=" * 50)
    print("DEMONSTRATION 1: MD5 DICTIONARY ATTACK")
    print("=" * 50)

    demo.dictionary_attack(md5_file, 0)  # MD5 mode

    print("\n" + "=" * 50)
    print("DEMONSTRATION 2: SHA-256 DICTIONARY ATTACK")  
    print("=" * 50)

    demo.dictionary_attack(sha256_file, 1400)  # SHA-256 mode

    print("\n" + "=" * 50)
    print("DEMONSTRATION 3: MD5 BRUTE FORCE ATTACK")
    print("=" * 50)

    demo.brute_force_attack(md5_file, 0, min_len=1, max_len=3)

    print("\n" + "=" * 50)
    print("DEMONSTRATION 4: HYBRID ATTACK")
    print("=" * 50)

    demo.hybrid_attack(md5_file, 0)

    print("\n" + "=" * 60)
    print("HASHCAT DEMO COMPLETE")
    print("=" * 60)
    print("\nKey Hashcat Commands:")
    print("1. hashcat -m 0 -a 0 hashes.txt wordlist.txt")
    print("2. hashcat -m 0 -a 3 hashes.txt ?l?l?l?l")
    print("3. hashcat -m 0 -a 6 hashes.txt wordlist.txt ?d?d")
    print("4. hashcat --benchmark")
    print()
    print("Attack modes:")
    print("  0 = Dictionary")
    print("  1 = Combinator")  
    print("  3 = Brute-force")
    print("  6 = Hybrid wordlist + mask")
    print("  7 = Hybrid mask + wordlist")
    print()
    print("Remember: Use responsibly and ethically!")

    return 0

if __name__ == "__main__":
    sys.exit(main())
