# PrivacyNexus - Unified Endpoint Security Agent 🛡️

**PrivacyNexus** is a modular, AI-driven endpoint security agent (SIEM/EDR) designed for lightweight Linux distributions. This repository contains the core local security suite developed as part of a BSc (Hons) Computer Networks dissertation focusing on biometric-authenticated, portable secure operating systems.

The agent runs completely locally with a non-blocking `CustomTkinter` graphical dashboard, utilizing multithreading to manage real-time background telemetry without interrupting the user experience.

## 🧠 Core Architecture

The system acts as a central Security Decision Engine integrating two distinct machine learning pipelines:

### 1. Module A: Data Loss Prevention (DLP)
* **Function:** Continuously monitors designated user directories for newly created or modified files using `watchdog`.
* **Processing:** Extracts raw text from `.txt`, `.pdf`, and `.docx` files. Implements a 2.0-second time-based debounce mechanism to prevent redundant OS-level file events.
* **AI Model:** Utilizes a pre-trained TF-IDF Vectorizer and Random Forest Classifier (`.joblib`) to categorize documents (e.g., Financial, Credentials, Personal) and calculate a sensitivity confidence score.

### 2. Module B: Host-Based Intrusion Detection System (HIDS)
* **Function:** Monitors active system processes in real-time using `psutil`.
* **Processing:** Dynamically attaches to non-whitelisted processes using `strace` to capture a live stream of system calls. Translates string-based system calls into numeric IDs to perfectly map to the **ADFA-LD dataset** standards.
* **AI Model:** Employs a 2-gram (bigram) TF-IDF vectorizer and a Random Forest Classifier (`.pkl`) to evaluate the sequence of system calls and detect anomalous, malware-like behavior. Safely filters out dormant/idle background threads to prevent false positives.

### 3. Security Decision Engine & Escalation
* **Function:** A central rule-based controller that aggregates telemetry from both AI modules.
* **Database:** Logs all security events locally to an SQLite database (`security_events.db`).
* **Correlation Logic:** If the DLP module detects high-confidence sensitive data (e.g., Financial records or Credentials) being accessed, and the HIDS module simultaneously detects an anomalous/malicious process executing within a 60-second sliding window, the engine triggers a `CRITICAL_ESCALATION` alert to terminate the threat and protect the data.

## 🛠️ Technology Stack
* **Language:** Python 3
* **Machine Learning:** `scikit-learn` (v1.6.1), `joblib`, `pickle`
* **System Monitoring:** `psutil`, `watchdog`, `subprocess` (`strace`)
* **GUI:** `CustomTkinter`
* **Database:** SQLite3

## 🚀 Installation & Usage

**Prerequisites:** 
Because the HIDS module relies on `strace` to hook into live processes, this agent is designed for Linux environments and requires elevated privileges.

1. Clone the repository.
2. Install system graphical dependencies (if missing):

   '''sudo apt update
   '''sudo apt install python3-tk strace

3. Install Python dependencies:

    '''pip install -r requirements.txt

4. Run the agent (preserving the GUI display environment):

    '''sudo -E python3 security_agent.py
