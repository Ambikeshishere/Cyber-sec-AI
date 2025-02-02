import psutil


SUSPICIOUS_PROCESSES = {
    "keylogger.exe",
    "ransomware.exe",
}

def monitor_processes():
    """Monitor running processes and detect suspicious activity."""
    print("Monitoring processes...")
    while True:
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                process_name = proc.info['name']
                if process_name and process_name.lower() in SUSPICIOUS_PROCESSES:
                    print(f"Alert: Suspicious process detected: {process_name} (PID: {proc.info['pid']})")
            except Exception as e:
                print(f"Error reading process info: {e}")

if __name__ == "__main__":
    monitor_processes()
