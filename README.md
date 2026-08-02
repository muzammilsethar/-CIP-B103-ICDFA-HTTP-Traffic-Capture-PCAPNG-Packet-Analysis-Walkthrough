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

mkdir -p ~/CIP-B103-Lab1/{evidence,working,exported,reports,screenshots,scripts}
cd ~/CIP-B103-Lab1
sudo apt update && sudo apt install -y apache2 curl wireshark tshark

[IMAGE 1 GOES HERE - Drag & Drop B103 Lab 1. 1.png]

---

### Step 2: Apache Web Service Configuration & Health Check

Enabling Apache2 service and generating custom HTTP evidence index page (/var/www/html/basic.html).

#### Executed Commands:

sudo systemctl enable --now apache2
printf '<!DOCTYPE html>\n<html><body><h1>CIP-B103 HTTP Evidence</h1><p>Name: Mohammad Muzamil</p><p>Reg No: C11/26/DFIT/17289</p></body></html>\n' | sudo tee /var/www/html/basic.html
sudo systemctl status apache2 --no-pager

[IMAGE 2 GOES HERE - Drag & Drop B103 Lab 1. 2.png]
[IMAGE 3 GOES HERE - Drag & Drop B103 Lab 1. 3.png]

---

### Step 3: Local Port Binding & HTTP Endpoint Verification

Validating Apache socket listener on port 80 and verifying HTTP GET response code 200 OK.

#### Executed Commands:

sudo ss -lntp | grep ':80'
curl -v http://127.0.0.1/basic.html 2>&1 | tee reports/curl_verbose.txt

#### Technical Findings:
* **Listener Status:** Active socket bound to *:80 under Apache PID (30523).
* **HTTP Protocol Output:** HTTP/1.1 200 OK (Content-Type: text/html, Content-Length: 135 bytes).

[IMAGE 4 GOES HERE - Drag & Drop B103 Lab 1. 4.png]

---

### Step 4: Network Packet Capture & File Integrity Baseline

Capturing loopback HTTP traffic with tshark, storing evidence to evidence/basic.pcapng, and creating a working copy for dynamic analysis.

#### Executed Commands:

sudo tshark -i lo -f 'tcp port 80' -w /tmp/basic.pcapng
sudo mv /tmp/basic.pcapng evidence/basic.pcapng
sudo chown $USER:$USER evidence/basic.pcapng
cp --preserve=timestamps evidence/basic.pcapng working/basic_working.pcapng

sha256sum evidence/basic.pcapng working/basic_working.pcapng | tee reports/capture_hashes.txt

[IMAGE 5 GOES HERE - Drag & Drop B103 Lab 1. 5.png]

---

### Step 5: TCP Handshake Analysis & Stream Filtering

Reconstructing TCP 3-Way Handshake (SYN -> SYN-ACK -> ACK) and stream sequence fields.

#### Executed Commands:

tshark -r working/basic_working.pcapng -Y "tcp.port == 80"
tshark -r working/basic_working.pcapng -Y "tcp.flags.syn == 1 or (tcp.flags.syn == 1 and tcp.flags.ack == 1) or (tcp.flags.syn == 0 and tcp.flags.ack == 1 and tcp.len == 0)" -T fields -e frame.number -e _ws.col.Time -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e tcp.flags.str -e tcp.seq -e tcp.ack
tshark -r working/basic_working.pcapng -Y "tcp.port == 80" -V > reports/handshake_analysis.txt

[IMAGE 6 GOES HERE - Drag & Drop B103 Lab 1. 6.png]

---

### Step 6: HTTP Payload Extraction & HTML Artifact Reconstruction

Isolating HTTP GET requests, HTTP responses, and carving original HTML data stream.

#### Executed Commands:

tshark -r working/basic_working.pcapng -Y "http"
tshark -r working/basic_working.pcapng -Y "frame.number == 4" -V > reports/http_request_payload.txt
tshark -r working/basic_working.pcapng -Y "frame.number == 6" -V > reports/http_response_payload.txt
tshark -r working/basic_working.pcapng -Y "http.file_data" -T fields -e http.file_data > exported/extracted_evidence.html

[IMAGE 7 GOES HERE - Drag & Drop B103 Lab 1. 7.png]

---

### Step 7: Ethernet Encapsulation Review & Report Verification

Analyzing Layer 2 Ethernet frame properties and verifying cryptographic SHA-256 hashes for extracted reports.

#### Executed Commands:

tshark -r working/basic_working.pcapng -Y "frame.number == 8" -V | head -n 35 > reports/encapsulation_summary.txt
cat reports/encapsulation_summary.txt
sha256sum reports/*.txt exported/* evidence/* working/*

[IMAGE 8 GOES HERE - Drag & Drop B103 Lab 1. 8.png]
[IMAGE 9 GOES HERE - Drag & Drop B103 Lab 1. 9.png]

---

## 📊 Evidence & Cryptographic Integrity Summary

| File / Artifact Path | Purpose | SHA-256 Cryptographic Hash |
| :--- | :--- | :--- |
| evidence/basic.pcapng | Original Captured Network PCAP | d327a8e44f7ce8891b93091d6006c4791152ff367dfe32e294b55da9c802c94 |
| working/basic_working.pcapng | Working Copy for Forensic Analysis | d327a8e44f7ce8891b93091d6006c4791152ff367dfe32e294b55da9c802c94 |
| reports/curl_verbose.txt | Verbose HTTP Endpoint Log | bf599c777e38e7f9983d8d234e6b0faafcef259e34dc81485c2532f0ab52fe54 |
| reports/handshake_analysis.txt | Full TCP Stream Breakdown | 40805427cc39a2afcdf0d2dff7b783a1033cf0ce8b43baf68088293e94ae99c3 |
| exported/extracted_evidence.html | Carved HTML Web Content | a707688e1f2116d3a6cd809a9f671e3324b392335794d80d7a30fd0842848c83 |

---
*Maintained for International Cybersecurity & Digital Forensics Academy (ICDFA) Portfolio.*
