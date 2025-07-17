# NetSentinel

# 🛡️ NetSentinel - Network Intrusion Alert System

NetSentinel is a lightweight Python-based real-time **Network Intrusion Alert Tool** built for **Kali Linux**. It detects suspicious network activity such as **SYN Flood attempts** and **XMAS scans** using live packet sniffing.

---

## 📌 Features

- ✅ Real-time packet sniffing using Scapy
- ✅ Detects:
  - SYN packets (common in SYN Flood attacks)
  - XMAS scans (used in stealth port scanning)
- ✅ Ignores traffic from your own IP (`192.168.29.38`)
- ✅ Logs alerts to a file (`alert_log.txt`)
- ✅ CLI-based tool with clean output

---


----------------------------------------------------------------------

USAGE:
-Clone or download the project folder.
-cd NetSentinel
-chmod +x NetSentinel.py
-sudo python3 netsentinel.py
-Enter your network interface (e.g., eth0, wlan0): wlan0 or eth0)

=====YOU NEED TO CHANGE IP IN NetSentinel.py file=====

 Sample Alert Output:
 [ALERT] 2025-07-17 11:45:23 - SYN Packet Detected | Src: 192.168.29.50 -> Dst Port: 80
[ALERT] 2025-07-17 11:46:10 - Possible XMAS Scan | Src: 192.168.29.51 -> Dst: 192.168.29.38
