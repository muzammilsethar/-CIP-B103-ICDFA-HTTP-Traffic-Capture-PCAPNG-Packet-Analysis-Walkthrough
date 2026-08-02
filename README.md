# 🌐 CIP-B103 Lab 1: HTTP Traffic Capture & PCAPNG Packet Analysis Walkthrough

## 📝 Executive Overview
This technical laboratory report documents the execution of network traffic capture, local web service deployment, HTTP protocol analysis, and forensic artifact extraction using tshark, curl, and Apache2 on Kali Linux. The analysis verifies 3-way TCP handshakes, extracts HTTP request/response payloads, and ensures evidentiary integrity using SHA-256 cryptographic hashes.

---

## 🛠️ Toolset & Working Environment

* **OS / Environment:** Kali Linux (kalimomi@kali)
* **Working Directory:** ~/CIP-B103-Lab1
* **Core Utilities:** apache2, tshark, curl, sha256sum, ss

---

## 🚀 Step-by-Step Execution & Technical Documentation

### Step 1: Environment Directory Setup & Tool Installation

Directory structure creation and dependency package updates for network traffic analysis.

#### Executed Commands:
```bash
mkdir -p ~/CIP-B103-Lab1/{evidence,working,exported,reports,screenshots,scripts}
cd ~/CIP-B103-Lab1
sudo apt update && sudo apt install -y apache2 curl wireshark tshark
sudo systemctl enable --now apache2
printf '<!DOCTYPE html>\n<html><body><h1>CIP-B103 HTTP Evidence</h1><p>Name: Mohammad Muzamil</p><p>Reg No: C11/26/DFIT/17289</p></body></html>\n' | sudo tee /var/www/html/basic.html
sudo systemctl status apache2 --no-pager

sudo ss -lntp | grep ':80'
curl -v [http://127.0.0.1/basic.html](http://127.0.0.1/basic.html) 2>&1 | tee reports/curl_verbose.txt

sudo tshark -i lo -f 'tcp port 80' -w /tmp/basic.pcapng
sudo mv /tmp/basic.pcapng evidence/basic.pcapng
sudo chown $USER:$USER evidence/basic.pcapng
cp --preserve=timestamps evidence/basic.pcapng working/basic_working.pcapng

sha256sum evidence/basic.pcapng working/basic_working.pcapng | tee reports/capture_hashes.txt

tshark -r working/basic_working.pcapng -Y "tcp.port == 80"
tshark -r working/basic_working.pcapng -Y "tcp.flags.syn == 1 or (tcp.flags.syn == 1 and tcp.flags.ack == 1) or (tcp.flags.syn == 0 and tcp.flags.ack == 1 and tcp.len == 0)" -T fields -e frame.number -e _ws.col.Time -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e tcp.flags.str -e tcp.seq -e tcp.ack
tshark -r working/basic_working.pcapng -Y "tcp.port == 80" -V > reports/handshake_analysis.txt

tshark -r working/basic_working.pcapng -Y "http"
tshark -r working/basic_working.pcapng -Y "frame.number == 4" -V > reports/http_request_payload.txt
tshark -r working/basic_working.pcapng -Y "frame.number == 6" -V > reports/http_response_payload.txt
tshark -r working/basic_working.pcapng -Y "http.file_data" -T fields -e http.file_data > exported/extracted_evidence.html
sha256sum reports/http_request_payload.txt reports/http_response_payload.txt exported/extracted_evidence.html | tee -a reports/capture_hashes.txt

tshark -r working/basic_working.pcapng -Y "frame.number == 8" -V | head -n 35 > reports/encapsulation_summary.txt
cat reports/encapsulation_summary.txt
sha256sum reports/*.txt exported/* evidence/* working/*

📊 Evidence & Cryptographic Integrity Summary
File / Artifact PathPurposeSHA-256 Cryptographic Hash
