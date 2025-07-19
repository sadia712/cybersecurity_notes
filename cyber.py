import hashlib 
import os
import subprocess

def calculate_hashes(file_path):
    hashes = {'MD5': '', 'SHA1': '', 'SHA256': ''}
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
            hashes['MD5'] = hashlib.md5(data).hexdigest()
            hashes['SHA1'] = hashlib.sha1(data).hexdigest()
            hashes['SHA256'] = hashlib.sha256(data).hexdigest()
    except Exception as e:
        print(f"Error reading file: {e}") 
    return hashes

def extract_strings(file_path):
    try:
        # Try using 'strings' command
        result = subprocess.run(['strings', file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode == 0:
            return result.stdout.splitlines()
        else:
            raise Exception("strings command failed")
    except:
        # Fallback to manual string extraction
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            strings = []
            current = ""
            for b in data:
                if 32 <= b <= 126:
                    current += chr(b)
                else:
                    if len(current) >= 4:
                        strings.append(current)
                    current = ""
            if len(current) >= 4:
                strings.append(current)
            return strings
        except Exception as e:
            print(f"Error extracting strings: {e}")
            return []

def check_malicious(hash_value, malicious_db):
    return hash_value in malicious_db

if __name__ == "__main__":
    file_path = input("Enter path to file for analysis: ").strip()
    
    if not os.path.isfile(file_path):
        print("Invalid file path.")
        exit()

    print("\nCalculating hashes...")
    hashes = calculate_hashes(file_path)
    for algo, hash_value in hashes.items():
        print(f"{algo}: {hash_value}")

    print("\nChecking against known malicious hashes...")
    malicious_hashes = [
        "44d88612fea8a8f36de82e1278abb02f",  # EICAR test file
        "eicarsha1hashhere",
        "eicarsha256hashhere"
    ]

    if check_malicious(hashes['MD5'], malicious_hashes):
        print("WARNING: File is malicious (MD5 match).")
    else:
        print("No match found in local malicious DB.")

    print("\nExtracting printable ASCII strings (top 20 shown)...")
    strings = extract_strings(file_path)
    for s in strings[:20]:
        print(s)
