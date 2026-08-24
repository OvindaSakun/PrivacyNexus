import os
import time
import threading

def run_malicious_workload():
    print("[*] Thread 1: Starting simulated anomalous syscall workload (15 seconds)...")
    # This keeps the process alive and spamming syscalls so strace catches it
    end_time = time.time() + 15
    while time.time() < end_time:
        os.system("whoami > /dev/null 2>&1")
        os.system("id > /dev/null 2>&1")
        os.system("uname -a > /dev/null 2>&1")
        time.sleep(0.05)
    print("[*] Thread 1: Anomalous workload finished.")

def trigger_dlp_file():
    print("[*] Thread 2: Waiting 3 seconds for HIDS to detect the anomaly...")
    time.sleep(3)
    
    doc_path = os.path.expanduser("~/Documents/automated_invoice.txt")
    print(f"[*] Thread 2: Creating sensitive financial document at {doc_path}...")
    
    file_content = """TAX INVOICE & PAYMENT RECEIPT
Invoice Number: INV-2026-98421
Client: Enterprise Global Corp
IBAN: GB29NWBK60161331926819
Swift / BIC: NWBKGB2L
Account Balance Due: $5,347.50
Status: Pending Wire Transfer"""
    
    # Ensure directory exists
    os.makedirs(os.path.dirname(doc_path), exist_ok=True)
    
    with open(doc_path, "w") as f:
        f.write(file_content)
        
    print("[+] TRIGGER COMPLETE!")
    print("\n=======================================================")
    print("👉 CHECK YOUR SECURITY AGENT GUI NOW:")
    print(" 1. Tab 2: You should see 'python3' flagged as a Threat.")
    print(" 2. Tab 1: You should see 'automated_invoice.txt' as Financial.")
    print(" 3. Tab 3: Click 'Fetch Logs' to see the CRITICAL_ESCALATION!")
    print("=======================================================\n")

if __name__ == "__main__":
    print("--- Automated SIEM Escalation Tester ---")
    # Run both simultaneously using threads
    t1 = threading.Thread(target=run_malicious_workload)
    t2 = threading.Thread(target=trigger_dlp_file)
    
    t1.start()
    t2.start()
    
    t1.join()
    t2.join()
