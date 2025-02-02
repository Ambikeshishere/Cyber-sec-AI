import hashlib
import os
import requests

API_KEY = "56584c26719dce2989aa59f5fad08329bce96bdabc926b1ca3c90fce4593b577"
API_URL = "https://www.virustotal.com/api/v3/files/"

KNOWN_MALWARE_HASHES = {
    "44d88612fea8a8f36de82e1278abb02f",
    "e99a18c428cb38d5f260853678922e03",
}

def calculate_file_hash(file_path, hash_type="md5"):
    hash_func = None
    if hash_type == "md5":
        hash_func = hashlib.md5()
    elif hash_type == "sha1":
        hash_func = hashlib.sha1()
    elif hash_type == "sha256":
        hash_func = hashlib.sha256()

    if not hash_func:
        print(f"Unsupported hash type: {hash_type}")
        return None

    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_func.update(chunk)
        return hash_func.hexdigest()
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
        return None

def scan_with_virustotal(file_hash):
    headers = {
        "x-apikey": API_KEY
    }
    response = requests.get(API_URL + file_hash, headers=headers)

    if response.status_code == 200:
        json_response = response.json()
        if json_response.get("data"):
            attributes = json_response["data"]["attributes"]
            total_votes = attributes["last_analysis_stats"]
            malicious = total_votes["malicious"]
            if malicious > 0:
                print(f"Malware detected in file hash: {file_hash}")
            else:
                print(f"File hash {file_hash} is safe.")
        else:
            print(f"Error: No data returned for hash {file_hash}.")
    else:
        print(f"Error contacting VirusTotal: {response.status_code}")

def scan_file(file_path):
    for hash_type in ["md5", "sha1", "sha256"]:
        file_hash = calculate_file_hash(file_path, hash_type)
        if file_hash:
            if file_hash in KNOWN_MALWARE_HASHES:
                print(f"Malware detected: {file_path} (Hash: {file_hash})")
            else:
                print(f"Checking {file_path} on VirusTotal...")
                scan_with_virustotal(file_hash)

def scan_directory(directory):
    print(f"Scanning directory: {directory}")
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            scan_file(file_path)

if __name__ == "__main__":
    directory_to_scan = input("Enter directory to scan: ")
    scan_directory(directory_to_scan)
