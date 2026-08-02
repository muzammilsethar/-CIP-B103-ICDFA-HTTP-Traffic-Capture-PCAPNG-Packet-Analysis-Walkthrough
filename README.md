# 🌐 CIP-B103 Lab 1: HTTP Traffic Capture & PCAPNG Packet Analysis Walkthrough

## 📝 Executive Overview
This technical laboratory report documents the execution of network traffic capture, local web service deployment, HTTP protocol analysis, and forensic artifact extraction using **tshark**, **curl**, and **Apache2** on Kali Linux. The analysis verifies 3-way TCP handshakes, extracts HTTP request/response payloads, and ensures evidentiary integrity using SHA-256 cryptographic hashes.

---

## 🛠️ Toolset & Working Environment

* **OS / Environment:** Kali Linux (`kalimomi@kali`)
* **Working Directory:** `~/CIP-B103-Lab1`
* **Core Utilities:** `apache2`, `tshark`, `curl`, `sha256sum`, `ss`

---

## 🚀 Step-by-Step Execution & Technical Documentation

### Step 1: Environment Directory Setup & Tool Installation

Directory structure creation and dependency package updates for network traffic analysis.

#### Executed Commands:
```bash
mkdir -p ~/CIP-B103-Lab1/{evidence,working,exported,reports,screenshots,scripts}
cd ~/CIP-B103-Lab1
sudo apt update && sudo apt install -y apache2 curl wireshark tshark
