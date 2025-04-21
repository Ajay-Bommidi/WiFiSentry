<xaiArtifact artifact_id="README.md">
 WiFiSentry 🔐📶

**WiFiSentry** is a powerful and modular **Python-based wireless security testing tool** designed to assist ethical hackers and cybersecurity researchers in analyzing and testing Wi-Fi networks. It leverages a wireless adapter in monitor mode to perform real-time attacks, detections, and logging on wireless environments.

![Screenshot_2025-04-21_05_46_14](https://github.com/user-attachments/assets/10a9d528-6687-475c-8d8d-41b87456a359)


> ⚠️ **Legal Disclaimer:** This tool is intended for **authorized penetration testing and educational purposes only.** Unauthorized use of WiFiSentry against networks you do not own or have explicit permission to test is **illegal and unethical.**

---

## 🧠 What is WiFiSentry?

WiFiSentry is a lightweight, open-source wireless pentesting toolkit built in Python that allows you to:
- Monitor Wi-Fi activity
- Launch controlled attacks (like deauth, beacon flooding)
- Capture WPA/WPA2 handshakes
- Detect evil twin access points
- Analyze connected clients in real time

It is ideal for:
- Cybersecurity students and researchers
- Ethical hackers performing audits
- CTF competitors and red teamers
- Professionals in Wi-Fi security analysis

---

## ✨ Key Features

| Feature                         | Description                                                                 |
|-------------------------------|-----------------------------------------------------------------------------|
| 🔍 **Network Scanning**       | Detect nearby access points and clients                                     |
| 🛑 **Deauthentication Attack**| Disconnect clients from APs to capture handshakes or simulate DoS          |
| 🧠 **Evil Twin Detection**    | Identify rogue access points mimicking legitimate SSIDs                    |
| 💥 **Beacon Flooding**        | Create fake SSIDs in large numbers (SSID spam)                             |
| 📡 **Handshake Capture**      | Capture WPA2 handshakes for offline password cracking                      |
| 📊 **Client Tracking**        | Live display of connected clients, MACs, and traffic                       |
| 🔄 **Modular Design**         | Plug-and-play architecture for adding new attack modules                   |
| 🧼 **Auto Cleanup**           | Ensures all temporary files and processes are killed after execution       |
| 📁 **Organized Output**       | Logs and captures stored in separate folders for analysis                  |

---

## ⚙️ Installation

### 🔧 Requirements
- Python 3.7+
- Linux OS (Kali Linux recommended)
- Wireless adapter that supports monitor mode & packet injection

### 📦 Setup

```bash
git clone https://github.com/Ajay-Bommidi/WiFiSentry.git
cd WiFiSentry
python3 -m venv venv
source venv/bin/activate
sudo python wifisentry.py
```

External tools to install :

sudo apt install aircrack-ng macchanger

📚 Example Use Cases
Audit a company Wi-Fi to check for rogue access points

Simulate denial of service using beacon flooding or deauth

Capture WPA2 handshakes for training on brute-force or dictionary attacks

Detect Evil Twin APs during red team assessments

✅ Current Modules
 Deauthentication Attack

 Beacon Flooding

 Evil Twin Detection

 WPA Handshake Capture

 Real-time Client Tracker

 🧠 A Note on Ethics
WiFiSentry is built with ethical hacking principles in mind. Please respect privacy and only test on networks you are authorized to audit. Misusing this tool can result in legal consequences. Always stay on the right side of cybersecurity.


