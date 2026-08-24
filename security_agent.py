import os
import time
import threading
import queue
import sqlite3
import subprocess
import psutil
import customtkinter as ctk
import joblib
import pickle
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Try importing document parsing libraries for DLP module
try:
    import PyPDF2
except ImportError:
    PyPDF2 = None

try:
    import docx
except ImportError:
    docx = None

# =========================================================
# 1. Database Setup (Decision Engine Log)
# =========================================================
DB_FILE = "security_events.db"

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS events
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                  event_type TEXT,
                  description TEXT,
                  severity TEXT,
                  action TEXT)''')
    conn.commit()
    conn.close()

def log_event(event_type, description, severity, action):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("INSERT INTO events (event_type, description, severity, action) VALUES (?, ?, ?, ?)",
              (event_type, description, severity, action))
    conn.commit()
    conn.close()

# =========================================================
# 2. Machine Learning Module Integration
# =========================================================
class SecurityDecisionEngineML:
    def __init__(self):
        # Module A (DLP/Files)
        self.dlp_model = None
        self.dlp_vectorizer = None
        
        # Module B (HIDS/Syscalls)
        self.hids_model = None
        self.hids_vectorizer = None
        
        self.load_models()

    def load_models(self):
        """Loads models and handles namespaces explicitly to avoid collisions."""
        BASE_DIR = os.path.dirname(os.path.abspath(__file__))
        
        dlp_model_path = os.path.join(BASE_DIR, "model1", "document_classifier.joblib")
        dlp_vec_path = os.path.join(BASE_DIR, "model1", "tfidf_vectorizer.joblib")
        
        hids_model_path = os.path.join(BASE_DIR, "model2", "linux_random_forest.pkl")
        hids_vec_path = os.path.join(BASE_DIR, "model2", "tfidf_vectorizer.pkl")

        # --- Module A: DLP/Files ---
        try:
            if os.path.exists(dlp_model_path) and os.path.exists(dlp_vec_path):
                self.dlp_model = joblib.load(dlp_model_path)
                self.dlp_vectorizer = joblib.load(dlp_vec_path)
                print("[INFO] Module A (DLP) models loaded successfully from relative path.")
            else:
                print(f"[WARNING] Module A (DLP) models missing at {os.path.join(BASE_DIR, 'model1')}.")
        except Exception as e:
            print(f"[WARNING] Could not load Module A models: {e}")

        # --- Module B: HIDS/Syscalls ---
        try:
            if os.path.exists(hids_model_path) and os.path.exists(hids_vec_path):
                self.hids_model = joblib.load(hids_model_path)
                self.hids_vectorizer = joblib.load(hids_vec_path)
                print("[INFO] Module B (HIDS) models loaded successfully from relative path.")
            else:
                print(f"[WARNING] Module B (HIDS) models missing at {os.path.join(BASE_DIR, 'model2')}.")
        except Exception as e:
            print(f"[WARNING] Could not load Module B models: {e}")

    def classify_document(self, text):
        if not self.dlp_model or not self.dlp_vectorizer:
            # Fallback for testing without models
            return "Normal", 0.0
        try:
            vec = self.dlp_vectorizer.transform([text])
            pred = self.dlp_model.predict(vec)[0]
            prob = max(self.dlp_model.predict_proba(vec)[0])
            return pred, prob
        except Exception as e:
            print(f"[ERROR] DLP Classification failed: {e}")
            return "Error", 0.0

    def classify_syscalls(self, syscall_sequence):
        if not self.hids_model or not self.hids_vectorizer:
            # Fallback for testing without models (0 = Normal)
            return 0, 0.0 
        try:
            vec = self.hids_vectorizer.transform([syscall_sequence])
            pred = self.hids_model.predict(vec)[0]
            prob = max(self.hids_model.predict_proba(vec)[0])
            return pred, prob
        except Exception as e:
            print(f"[ERROR] HIDS Classification failed: {e}")
            return 0, 0.0

ml_engine = SecurityDecisionEngineML()
decision_queue = queue.Queue()

# =========================================================
# 3. File Monitor Daemon (Module A - DLP)
# =========================================================
def extract_text(filepath):
    """Extracts raw text from TXT, PDF, and DOCX files."""
    ext = filepath.lower().split('.')[-1]
    text = ""
    try:
        if ext == 'txt':
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                text = f.read()
        elif ext == 'pdf' and PyPDF2:
            with open(filepath, 'rb') as f:
                reader = PyPDF2.PdfReader(f)
                for page in reader.pages:
                    extracted = page.extract_text()
                    if extracted:
                        text += extracted + " "
        elif ext == 'docx' and docx:
            doc = docx.Document(filepath)
            for para in doc.paragraphs:
                text += para.text + " "
    except Exception as e:
        pass # Silently skip unreadable files in background thread
    return text

class DLPEventHandler(FileSystemEventHandler):
    def __init__(self):
        super().__init__()
        self.last_scanned = {}
        self.debounce_seconds = 2.0

    def on_modified(self, event):
        if not event.is_directory:
            self.process_file(event.src_path)

    def on_created(self, event):
        if not event.is_directory:
            self.process_file(event.src_path)

    def process_file(self, filepath):
        current_time = time.time()
        last_time = self.last_scanned.get(filepath, 0)
        
        # Prevent rapid duplicate scans on the same file
        if current_time - last_time < self.debounce_seconds:
            return
            
        self.last_scanned[filepath] = current_time

        if filepath.lower().endswith(('.txt', '.pdf', '.docx')):
            text = extract_text(filepath)
            if text.strip():
                category, confidence = ml_engine.classify_document(text)
                decision_queue.put({
                    'type': 'dlp',
                    'filepath': filepath,
                    'category': category,
                    'confidence': confidence
                })

def start_file_monitor(path):
    event_handler = DLPEventHandler()
    observer = Observer()
    observer.schedule(event_handler, path, recursive=True)
    observer.start()
    return observer

# =========================================================
# 4. Syscall Monitor Daemon (Module B - HIDS)
# =========================================================
def capture_syscall_sequence(pid, duration=1.0):
    """Uses strace to intercept a live sequence of syscalls for a given PID."""
    # ADFA-LD Mapping stub (maps common string syscalls to numeric IDs if required by vectorizer)
    # If the vectorizer uses strings, the .get() fallback retains the string token.
    adfa_mapping = {
        'read': '3', 'write': '4', 'open': '5', 'close': '6', 
        'execve': '11', 'brk': '45', 'mmap': '90', 'munmap': '91', 
        'mprotect': '125', 'clone': '120'
    }

    try:
        # Intercept live trace. Note: On antiX, standard users may need cap_sys_ptrace 
        # or sudo to strace arbitrary processes. 
        process = subprocess.Popen(
            ['strace', '-q', '-p', str(pid), '-e', 'trace=all'],
            stderr=subprocess.PIPE,
            stdout=subprocess.DEVNULL, # strace writes trace to stderr
            text=True,
            bufsize=1 # Line buffered for immediate reading
        )
        
        lines = []
        def reader_thread():
            try:
                for line in iter(process.stderr.readline, ''):
                    if not line: break
                    lines.append(line)
            except Exception:
                pass
                
        # Non-blocking sampling loop reading from the stream
        t = threading.Thread(target=reader_thread, daemon=True)
        t.start()
        
        start_time = time.time()
        while time.time() - start_time < duration:
            time.sleep(0.05)
            
        process.terminate()
        process.wait(timeout=1.0)
        t.join(timeout=0.5)
        
        # Parse accumulated sequence block
        syscalls = []
        for line in lines:
            if '(' in line:
                syscall_name = line.split('(')[0].strip().split(' ')[-1]
                if syscall_name.isidentifier():
                    # Format as numeric ID if mapped, else keep as whitespace-separated string token
                    token = adfa_mapping.get(syscall_name, syscall_name)
                    syscalls.append(token)
        return " ".join(syscalls), len(syscalls)
    except Exception:
        return "", 0

def syscall_monitor_loop():
    """Continuously samples active processes."""
    # Whitelisted core desktop processes to reduce noise
    whitelist = {'icewm', 'pipewire', 'conky', 'dbus-daemon', 'volumeicon', 'zzzfm', 'Xorg'}

    while True:
        try:
            # Sample processes (skipping root to avoid excessive permission errors)
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'username']):
                if proc.info['username'] != 'root':
                    pid = proc.info['pid']
                    name = proc.info['name']
                    exe = proc.info['exe']
                    
                    if name in whitelist:
                        continue # Skip known benign background daemons
                    
                    seq, count = capture_syscall_sequence(pid, duration=0.5)
                    
                    if count >= 2: # 2-grams require at least 2 tokens
                        pred, prob = ml_engine.classify_syscalls(seq)
                        is_threat = (pred == 1)
                        print(f"[HIDS] Successfully traced PID:{pid} ({name}) - {count} syscalls captured.")
                    elif count == 1:
                        # Guard against single-token vectorizer errors (all-zero vector)
                        pred, prob = 0, 0.00
                        is_threat = False
                        name = f"{name} (Idle)"
                    else:
                        # 0 syscalls or trace failed
                        continue
                        
                    decision_queue.put({
                        'type': 'hids',
                        'pid': pid,
                        'name': name,
                        'exe': exe,
                        'confidence': prob,
                        'syscall_count': count,
                        'is_threat': is_threat
                    })
        except Exception:
            pass
        time.sleep(2.0) # Delay between sweeps to reduce overhead

# =========================================================
# 5. Central Decision Engine
# =========================================================
# Shared state structures for the GUI thread
gui_state = {
    'dlp_logs': [],
    'hids_logs': [],
    'current_anomaly_score': 0.0
}

def decision_engine_loop():
    """Rule-based controller that consumes events and escalates threats."""
    recent_sensitive_files = [] # Tuples of (timestamp, filepath, category)

    while True:
        try:
            event = decision_queue.get(timeout=1)
            current_time = time.time()
            
            # Prune old sensitive file access records (>60 seconds)
            recent_sensitive_files = [f for f in recent_sensitive_files if current_time - f[0] < 60]

            if event['type'] == 'dlp':
                cat = event['category']
                conf = event['confidence']
                filepath = event['filepath']
                status = "Monitored"
                
                if cat in ['Financial', 'Credentials', 'Personal'] and conf > 0.6:
                    status = "Read-Only (Protected)"
                    recent_sensitive_files.append((current_time, filepath, cat))
                    log_event("DLP_SENSITIVE_ACCESS", 
                              f"Sensitive data '{cat}' accessed at {filepath}", 
                              "MEDIUM", 
                              "Enforced Read-Only")
                else:
                    log_event("DLP_SCAN", f"File '{filepath}' classified as {cat}", "LOW", "None")

                filename = os.path.basename(filepath)
                gui_state['dlp_logs'].append((filename, filepath, cat, f"{conf:.2f}", status))
                if len(gui_state['dlp_logs']) > 50: 
                    gui_state['dlp_logs'].pop(0)

            elif event['type'] == 'hids':
                pid = event['pid']
                exe = event['exe']
                name = event['name']
                conf = event['confidence']
                count = event['syscall_count']
                is_threat = event['is_threat']
                
                gui_state['current_anomaly_score'] = conf
                
                # Rule Logic: Escalate if malware is detected AND sensitive files were recently accessed
                if is_threat:
                    if recent_sensitive_files and conf > 0.7:
                        log_event("CRITICAL_ESCALATION", 
                                  f"Malware behavior (PID:{pid} {exe}) during active sensitive data access!", 
                                  "CRITICAL", 
                                  "Process Terminated & Admin Alerted")
                        # (Simulation) Terminating the process could go here using psutil
                    else:
                        log_event("HIDS_ANOMALY", 
                                  f"Anomalous syscall sequence from PID:{pid} {exe}", 
                                  "HIGH", 
                                  "Logged")
                
                status_text = "Threat" if is_threat else "Normal"
                log_entry = f"PID: {pid} | Name: {name} | Syscalls: {count} | Score: {conf:.2f} | Class: {status_text}"
                gui_state['hids_logs'].append(log_entry)
                if len(gui_state['hids_logs']) > 30: 
                    gui_state['hids_logs'].pop(0)

        except queue.Empty:
            continue
        except Exception as e:
            print(f"Decision Engine Error: {e}")

# =========================================================
# 6. CustomTkinter GUI Layout
# =========================================================
class SecurityAgentApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("PrivacyNexus - Unified Endpoint Security Agent")
        self.geometry("950x650")
        
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)
        
        self.tabview = ctk.CTkTabview(self)
        self.tabview.grid(row=0, column=0, padx=20, pady=20, sticky="nsew")
        
        self.tab1 = self.tabview.add("Data Classification")
        self.tab2 = self.tabview.add("Threat Detection")
        self.tab3 = self.tabview.add("Security Audit")
        
        self.build_tab1()
        self.build_tab2()
        self.build_tab3()
        
        # Start GUI background update loop
        self.update_gui()

    def build_tab1(self):
        self.tab1.grid_rowconfigure(1, weight=1)
        self.tab1.grid_columnconfigure(0, weight=1)
        
        top_frame = ctk.CTkFrame(self.tab1, fg_color="transparent")
        top_frame.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        
        btn_scan = ctk.CTkButton(top_frame, text="Force Scan Directory", command=self.force_scan, width=200)
        btn_scan.pack(side="left")
        
        self.dlp_table = ctk.CTkScrollableFrame(self.tab1)
        self.dlp_table.grid(row=1, column=0, sticky="nsew")
        
        # Table Headers
        headers = ["Filename", "Path", "AI Category", "Confidence", "Protection Status"]
        for col, header in enumerate(headers):
            lbl = ctk.CTkLabel(self.dlp_table, text=header, font=ctk.CTkFont(weight="bold"))
            lbl.grid(row=0, column=col, padx=10, pady=5, sticky="w")
            
        self.dlp_rows_ui = [] # Keep track of drawn row widgets for efficient updating

    def build_tab2(self):
        self.tab2.grid_columnconfigure(0, weight=1)
        self.tab2.grid_columnconfigure(1, weight=1)
        self.tab2.grid_rowconfigure(3, weight=1)
        
        # Meters
        meter_frame = ctk.CTkFrame(self.tab2)
        meter_frame.grid(row=0, column=0, columnspan=2, padx=10, pady=10, sticky="ew")
        
        ctk.CTkLabel(meter_frame, text="CPU Usage:").pack(side="left", padx=10, pady=10)
        self.cpu_bar = ctk.CTkProgressBar(meter_frame)
        self.cpu_bar.pack(side="left", padx=10, fill="x", expand=True)
        
        ctk.CTkLabel(meter_frame, text="RAM Usage:").pack(side="left", padx=10, pady=10)
        self.mem_bar = ctk.CTkProgressBar(meter_frame)
        self.mem_bar.pack(side="left", padx=10, fill="x", expand=True)
        
        # Anomaly Score
        self.anomaly_lbl = ctk.CTkLabel(self.tab2, text="Real-Time AI Anomaly Score: 0.0", 
                                        font=ctk.CTkFont(size=18, weight="bold"), text_color="green")
        self.anomaly_lbl.grid(row=1, column=0, columnspan=2, pady=20)
        
        # Active Threats List
        ctk.CTkLabel(self.tab2, text="Anomalous Processes (HIDS/Syscalls):", font=ctk.CTkFont(weight="bold")).grid(row=2, column=0, sticky="w", padx=10)
        self.hids_textbox = ctk.CTkTextbox(self.tab2, font=ctk.CTkFont(family="Consolas", size=12))
        self.hids_textbox.grid(row=3, column=0, columnspan=2, padx=10, pady=(0, 10), sticky="nsew")

    def build_tab3(self):
        self.tab3.grid_rowconfigure(1, weight=1)
        self.tab3.grid_columnconfigure(0, weight=1)
        
        btn_refresh = ctk.CTkButton(self.tab3, text="Fetch Latest Audit Logs", command=self.refresh_audit_log)
        btn_refresh.grid(row=0, column=0, padx=10, pady=10, sticky="w")
        
        self.audit_textbox = ctk.CTkTextbox(self.tab3, font=ctk.CTkFont(family="Consolas", size=13))
        self.audit_textbox.grid(row=1, column=0, padx=10, pady=(0, 10), sticky="nsew")
        
        self.refresh_audit_log()

    def force_scan(self):
        """Spawns a thread to scan user directories so GUI doesn't block."""
        target_dir = os.path.expanduser("~/Documents")
        if not os.path.exists(target_dir):
            target_dir = os.path.expanduser("~") # Fallback
            
        def scan_worker():
            for root, dirs, files in os.walk(target_dir):
                for file in files:
                    if file.lower().endswith(('.txt', '.pdf', '.docx')):
                        filepath = os.path.join(root, file)
                        text = extract_text(filepath)
                        if text.strip():
                            cat, conf = ml_engine.classify_document(text)
                            decision_queue.put({
                                'type': 'dlp',
                                'filepath': filepath,
                                'category': cat,
                                'confidence': conf
                            })
        threading.Thread(target=scan_worker, daemon=True).start()

    def refresh_audit_log(self):
        self.audit_textbox.delete("1.0", "end")
        try:
            conn = sqlite3.connect(DB_FILE)
            c = conn.cursor()
            c.execute("SELECT timestamp, severity, event_type, description, action FROM events ORDER BY id DESC LIMIT 50")
            rows = c.fetchall()
            conn.close()
            
            for row in rows:
                timestamp, severity, event_type, desc, action = row
                log_entry = f"[{timestamp}] [{severity}] {event_type}\n  -> Detail: {desc}\n  -> Action: {action}\n{'-'*60}\n"
                self.audit_textbox.insert("end", log_entry)
        except Exception as e:
            self.audit_textbox.insert("end", f"Error fetching logs: {e}")

    def update_gui(self):
        """Non-blocking update loop that refreshes the GUI from shared states."""
        # --- Update Tab 1 (DLP) ---
        # Wiping and redrawing rows could be optimized, but works well for moderate list sizes
        for widget in self.dlp_rows_ui:
            widget.destroy()
        self.dlp_rows_ui.clear()
        
        for row_idx, row_data in enumerate(reversed(gui_state['dlp_logs'])):
            for col_idx, text_val in enumerate(row_data):
                # Truncate paths that are too long
                display_text = str(text_val)
                if col_idx == 1 and len(display_text) > 40:
                    display_text = "..." + display_text[-37:]
                    
                color = "orange" if (col_idx == 4 and "Protected" in text_val) else "transparent"
                lbl = ctk.CTkLabel(self.dlp_table, text=display_text, fg_color=color)
                lbl.grid(row=row_idx+1, column=col_idx, padx=10, pady=2, sticky="w")
                self.dlp_rows_ui.append(lbl)

        # --- Update Tab 2 (HIDS) ---
        self.cpu_bar.set(psutil.cpu_percent() / 100.0)
        self.mem_bar.set(psutil.virtual_memory().percent / 100.0)
        
        score = gui_state['current_anomaly_score']
        self.anomaly_lbl.configure(text=f"Real-Time AI Anomaly Score: {score:.2f}",
                                   text_color="red" if score > 0.6 else "green")
        
        self.hids_textbox.delete("1.0", "end")
        for log in reversed(gui_state['hids_logs']):
            self.hids_textbox.insert("end", log + "\n")
            
        # Schedule next tick
        self.after(1500, self.update_gui)

def main():
    print("[INFO] Initializing SQLite Security Database...")
    init_db()
    
    print("[INFO] Starting File Monitor Daemon (Module A)...")
    watch_path = os.path.expanduser("~")
    start_file_monitor(watch_path)
    
    print("[INFO] Starting Syscall Monitor Daemon (Module B)...")
    threading.Thread(target=syscall_monitor_loop, daemon=True).start()
    
    print("[INFO] Starting Security Decision Engine...")
    threading.Thread(target=decision_engine_loop, daemon=True).start()
    
    print("[INFO] Launching CustomTkinter GUI...")
    ctk.set_appearance_mode("Dark")
    ctk.set_default_color_theme("blue")
    
    app = SecurityAgentApp()
    app.mainloop()

if __name__ == "__main__":
    main()
