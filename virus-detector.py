import os
import hashlib
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

# Define the directory to scan and file types to check
SCAN_EXTENSIONS = ['.exe', '.dll', '.sys', '.doc', '.docx', '.xls', '.xlsx', '.py', '.xml', '.cfg', '.txt', '.ppt', '.pptx', '.hwp']
DOWNLOADS_DIR = os.path.join(os.path.expanduser('~'), 'Downloads')
ENGINE_FILE = os.path.join(os.path.expanduser('~'), 'engine.db')
SCAN_RESULTS_FILE = os.path.join(os.path.expanduser('~'), 'scan_results.log')
EICAR_STRING = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'

def download_engine():
    url = 'https://bazaar.abuse.ch/export/txt/sha256/full/'
    response = requests.get(url, stream=True)
    with open(ENGINE_FILE, 'wb') as file:
        for chunk in response.iter_content(chunk_size=8192):
            file.write(chunk)
    print("Malware hash database downloaded successfully.")

def load_malware_hashes():
    with open(ENGINE_FILE, 'r', encoding='utf-8', errors='ignore') as file:
        return set(line.strip() for line in file if not line.startswith('#'))

def hash_file(file_path):
    hasher = hashlib.sha256()
    try:
        with open(file_path, 'rb') as f:
            buf = f.read()
            hasher.update(buf)
        return hasher.hexdigest()
    except (FileNotFoundError, PermissionError):
        return None

def file_extension_valid(file_path):
    return file_path.endswith(tuple(SCAN_EXTENSIONS))

def file_size_valid(file_path):
    try:
        return os.path.getsize(file_path) <= 10 * 1024 * 1024  # 10 MB
    except (FileNotFoundError, PermissionError):
        return False

def is_file_infected(file_path, malware_hashes):
    file_hash = hash_file(file_path)
    if file_hash is None:
        return False
    if file_hash in malware_hashes:
        return True
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
        content = file.read()
        if EICAR_STRING in content:
            return True
    return False

def scan_directory(scan_path, malware_hashes):
    infected_files = []
    total_files = 0
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = []
        for subdir, _, files in os.walk(scan_path):
            for file in files:
                file_path = os.path.join(subdir, file)
                if file_extension_valid(file_path) and file_size_valid(file_path):
                    futures.append(executor.submit(is_file_infected, file_path, malware_hashes))
                    total_files += 1

        for future in as_completed(futures):
            if future.result():
                infected_files.append(future.result())

    return infected_files, total_files

def main():
    print("Starting malware scan...")

    if not os.path.exists(ENGINE_FILE):
        print("Downloading malware hash database...")
        download_engine()

    malware_hashes = load_malware_hashes()
    print("Malware hash database loaded. Starting scan...")

    infected_files, total_files = scan_directory(DOWNLOADS_DIR, malware_hashes)
    print(f"Scan complete. {total_files} files scanned.")

    if infected_files:
        print(f"Infected files found: {len(infected_files)}")
        with open(SCAN_RESULTS_FILE, 'w') as log:
            for file in infected_files:
                log.write(f"{file}\n")
        print(f"Infected files logged to {SCAN_RESULTS_FILE}")
    else:
        print("No infected files found.")

if __name__ == "__main__":
    main()