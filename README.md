# PrivacyNexus 🛡️

![Python](https://img.shields.io/badge/Python-3.x-blue?style=flat-square&logo=python&logoColor=white)
![PlatformIO](https://img.shields.io/badge/PlatformIO-Compatible-orange?style=flat-square&logo=platformio&logoColor=white)
![ESP32](https://img.shields.io/badge/ESP32-Firmware-red?style=flat-square&logo=espressif&logoColor=white)
![VMware](https://img.shields.io/badge/VMware-Workstation-blue?style=flat-square&logo=vmware&logoColor=white)
![CustomTkinter](https://img.shields.io/badge/UI-CustomTkinter-brightgreen?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

## Executive Summary
PrivacyNexus is a biometric-authenticated, portable secure OS architecture designed for untrusted host isolation. It bridges hardware-level biometric validation (ESP32 + AS608 optical fingerprint sensor) with host-level virtualization controls. Access to isolated Virtual Machines is strictly guarded; the system will not launch an OS environment until a cryptographically verified and AES-encrypted authentication payload is successfully transmitted from the hardware token to the host orchestrator. 

> **Companion Repository Callout:** The in-guest ML-driven DLP/HIDS monitoring agents for the isolated environments reside in the dedicated companion repository: [PrivacyNexus-Agent](https://github.com/OvindaSakun/PrivacyNexus-Agent).

## Architecture Workflow

```text
[ESP32 + AS608 Fingerprint Sensor]
         |
         | (Fingerprint Match & AES-128 Encryption)
         |
         v
[Serial / Wi-Fi SoftAP / UDP Broadcast / HTTP POST]
         |
         +-------------------------------------------------+
         |                                                 |
         v                                                 v
[Host GUI (gui_app.py)] <-----------------> [Receiver (http_receiver.py)]
 (User Enrollment & Logging)                  (Payload Decryption & Auth Token Drop)
         |                                                 |
         |                                                 | (Drops 'auth_success.enc' in C:\tmp)
         v                                                 v
[VM Orchestrator (vmware_os_loader.py)] <------------------+
         | (Verifies Token, Consumes/Deletes Token)
         v
[Encrypted Guest VM Launch via vmrun]
```

## Implementation Details & Protocols

### Firmware & Hardware Layer
- **Microcontroller**: ESP32 (`esp32doit-devkit-v1`), compiled via PlatformIO using the Arduino framework.
- **Biometric Sensor**: AS608 Optical Fingerprint Sensor.
- **Handshake & Communication**: 
  - The ESP32 hosts a SoftAP (`ESP32-Fingerprint-AP`).
  - Serial communication operates at `115200` baud. The sensor communicates over UART2 (`57600` baud).
  - Auth payloads are encrypted via **AES-128-CBC** (`MySecr3tAESKey!!` / IV: `0x00-0x0F`) and structured as JSON containing `authenticated`, `timestamp`, `user_id`, and `user_name`.
  - Transmission methods:
    1. HTTP POST to connected clients on ports `5000` and `2222` (`/upload_auth`).
    2. UDP Broadcast to `192.168.4.255` on ports `5000` and `2222`.
    3. HTTP GET endpoint polling on `http://192.168.4.1/`.

### Host Control & Virtualization Engine
- **VM Orchestrator (`vmware_os_loader.py`)**: 
  - Polls `C:\tmp` and `http://192.168.4.1/` for `auth_success.enc`.
  - Discovers `vmrun.exe` dynamically across standard VMware Workstation/Player paths.
  - VM operations (`start`, `stop`, `hard/soft` power modes) are strictly authenticated.
  - **Cleanup Hook**: Upon successful VM start execution, the token files (`auth_success.enc`, `auth_false.enc`, `auth_status.enc`) are immediately consumed and deleted from `C:\tmp` to prevent replay access.
  - Falls back to `psutil` process termination if `vmrun` soft stops fail.

### GUI & Telemetry Pipelines
- **Management Console (`gui_app.py`)**: Built with CustomTkinter, it handles template enrollment via serial commands (`e <id> <name>`, `d <id>`, `l`), device pinging (`ping`), and telemetry monitoring. Includes an emergency admin bypass (`admin123`).
- **Data Receiver (`http_receiver.py`)**: Listens on TCP ports 5000/2222 for incoming POST requests and UDP ports for broadcasts, while simultaneously polling the ESP32 gateway. Decrypts AES payloads and saves the `.enc` files into `C:\tmp`.

## Hardware Wiring Table

| ESP32 Pin | AS608 Sensor / Component | Description |
| :--- | :--- | :--- |
| **GPIO 16 (RX2)** | AS608 TX | UART Communication |
| **GPIO 17 (TX2)** | AS608 RX | UART Communication |
| **3.3V / 5V** | AS608 VCC | Power Supply |
| **GND** | AS608 GND | Common Ground |
| **GPIO 4** | Red LED | Auth Failed Indicator |
| **GPIO 2** | Green LED | Auth Success Indicator |
| **GPIO 34** | Pushbutton | Manual scan trigger (Input, Debounced) |

## Virtual Machine Directory Setup

The VM architecture is designed to be portable relative to the workspace.

1. Ensure a directory named `HDD/` exists in the project root. (Note: `HDD/` is git-ignored to prevent pushing massive VM blobs).
2. Through the **OS Loader GUI**, you can "Build VM & Initialize OS Installation".
3. This process uses `vmware-vdiskmanager.exe` to provision a `.vmdk` disk and automatically generates a matching `.vmx` configuration specifying OS type, RAM, and CPU parameters.
4. The generated Virtual Machine folder will be saved inside `HDD/<VM_Name>/` and picked up dynamically by the orchestrator.

## Setup & Execution Guide

### 1. Flashing Firmware (PlatformIO)
1. Open the project in VS Code with the PlatformIO extension installed.
2. The `platformio.ini` is pre-configured for `esp32doit-devkit-v1`.
3. Connect the ESP32 via USB and click the **Upload** button to flash `src/code.cpp`.

### 2. Python Environment Setup
1. Ensure Python 3.x is installed.
2. Install the required host dependencies:
   ```bash
   pip install -r requirements.txt
   ```
   *(Note: The Python executables also feature auto-dependency resolution on launch for standard environments).*

### 3. Running the Host Pipeline
1. Connect the ESP32 hardware to your PC.
2. Run the main orchestration GUI:
   ```bash
   python gui_app.py
   ```
3. Run the VM Loader module to manage and launch instances:
   ```bash
   python vmware_os_loader.py
   ```
4. *(Optional)* Run `python http_receiver.py` for standalone testing of the HTTP/UDP pipeline without the GUI overhead.

### 4. Build & Distribution
The repository includes a script to freeze the Python host tools into standalone Windows binaries using `py2exe`.

1. Run the build script:
   ```bash
   python build_executables.py
   ```
2. The build config (`bundle_files: 3`, `compressed: True`) compiles the code and bundles required DLLs.
3. The script automatically copies the CustomTkinter asset folders (themes, fonts) into the `dist/` folder ensuring the UI styles render correctly.
4. Standalone executables (`gui_app.exe`, `vmware_os_loader.exe`) will be generated inside the `dist/` directory.

---

**Author:** Ovinda Sakun  
*Final Year Research Project, BSc (Hons) Computer Networks*
