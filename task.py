import os
import hashlib
import json
import time
from datetime import datetime

# Configuration
db_file = "hashes.json"
scan_directory = "C:\\Users\\Hp\\OneDrive\\Desktop\\internshiptask"  # Directory to monitor
delay = 60  # Time delay between scans (in seconds)

def calculate_hash(file_path):
    """Calculate the SHA-256 hash of a file."""
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        print(f"⚠️ Error reading {file_path}: {e}")
        return None

def scan_files(directory):
    """Scan all files in a directory and compute their hashes."""
    file_hashes = {}
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            file_hash = calculate_hash(file_path)
            if file_hash:
                file_hashes[file_path] = file_hash
    return file_hashes

def save_hashes(file_hashes):
    """Save the computed hashes to a JSON file."""
    with open(db_file, "w") as f:
        json.dump(file_hashes, f, indent=4)

def load_hashes():
    """Load existing hashes from the JSON file."""
    if os.path.exists(db_file):
        with open(db_file, "r") as f:
            return json.load(f)
    return {}

def check_integrity():
    """Compare current file hashes with stored hashes and log discrepancies."""
    print("\nRunning integrity check...")
    print("=" * 50)
    print(f"[SCAN STARTED] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 50)
    
    known_hashes = load_hashes()
    current_hashes = scan_files(scan_directory)
    
    modified_files = []
    new_files = []
    deleted_files = []
    
    # Check for new and modified files
    for file, hash_value in current_hashes.items():
        if file in known_hashes:
            if known_hashes[file] != hash_value:
                modified_files.append(file)
        else:
            new_files.append(file)
    
    # Check for deleted files
    for file in known_hashes:
        if file not in current_hashes:
            deleted_files.append(file)
    
    # Log results
    if new_files:
        for file in new_files:
            print(f"🟢 [NEW FILE] {file}")
    
    if modified_files:
        for file in modified_files:
            print(f"🟡 [MODIFIED] {file}")
    
    if deleted_files:
        for file in deleted_files:
            print(f"🔴 [DELETED] {file}")
    
    if not (new_files or modified_files or deleted_files):
        print("✅ No changes detected.")
    
    save_hashes(current_hashes)
    print("\nScan complete. Hash database updated.")
    print("=" * 50)

if __name__ == "__main__":
    print("🔍 Integrity Checker Started...")
    while True:
        check_integrity()
        time.sleep(delay)
