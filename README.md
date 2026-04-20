# CodeAlpha - Advanced Basic Network Sniffer

## Overview
This project is an improved version of a basic network sniffer built with Python and Scapy for the CodeAlpha Cyber Security Internship.  
It captures live network packets, identifies important protocols, displays source and destination information, previews payload data, supports useful filters, and saves the capture into a PCAP file for later analysis.

## Features
- Capture live network packets using Scapy
- Show source and destination IP addresses
- Detect the following protocols:
  - TCP
  - UDP
  - ICMP
  - DNS
  - ARP
- Display source and destination ports
- Show TCP flags when available
- Optional payload preview
- Filter by protocol
- Filter by IP address
- Filter by port number
- Live statistics during capture
- Save matched packets to a `.pcap` file
- Offline analyzer for saved PCAP files

## Project Structure
- `sniffer.py` -> Main live sniffer
- `analyzer.py` -> Offline PCAP analyzer
- `requirements.txt` -> Required Python packages
- `README.md` -> Project documentation

## Technologies Used
- Python
- Scapy
- Colorama

## Installation
Install the required packages:

```bash
pip install -r requirements.txt
```

## How to Run

### 1. Basic capture
```bash
python sniffer.py
```

### 2. Capture a specific number of packets
```bash
python sniffer.py -c 50
```

### 3. Show payload preview
```bash
python sniffer.py --show-payload
```

### 4. Filter by protocol
```bash
python sniffer.py --filter-proto TCP DNS
```

### 5. Filter by IP
```bash
python sniffer.py --filter-ip 192.168.1.10
```

### 6. Filter by port
```bash
python sniffer.py --filter-port 443
```

### 7. Save to a custom PCAP file
```bash
python sniffer.py -o my_capture.pcap
```

## Offline Analysis
After generating a PCAP file, run:

```bash
python analyzer.py capture_task1.pcap
```

The analyzer shows:
- Protocol distribution
- Top source IPs
- Top destination IPs
- Most common ports
- DNS queries

## Sample Output

```bash
╔══════════════════════════════════════════════════════════════════════════════╗
║                    CodeAlpha - Advanced Network Sniffer                     ║
╚══════════════════════════════════════════════════════════════════════════════╝
[*] Interface: default | Count: ∞ | Output: capture_task1.pcap

Time         #      Proto       Source             Destination        Info
──────────────────────────────────────────────────────────────────────────────────────────────────────────────
10:15:22.143 #1     [  TCP  ]   192.168.1.10       172.217.18.14      Port 50432 -> 443 | Flags: SYN
10:15:22.201 #2     [  DNS  ]   192.168.1.10       8.8.8.8            Query: www.google.com
10:15:22.245 #3     [  UDP  ]   192.168.1.10       192.168.1.1        Port 5353 -> 5353 | Length: 42
10:15:22.310 #4     [ ICMP  ]   192.168.1.10       1.1.1.1            Echo Request
10:15:22.411 #5     [  ARP  ]   192.168.1.10       192.168.1.1        Request | MAC aa:bb:cc:dd:ee:ff -> ff:ff:ff:ff:ff:ff

──────────────────────────────────────────────────────────────────────────────────────────────────────────────
Live Stats | Total: 5 | TCP: 1 | UDP: 1 | ICMP: 1 | DNS: 1 | ARP: 1 | OTHER: 0 | Rate: 2.50 pkt/s

[+] Saved 5 packets to capture_task1.pcap

╔══════════════════════════════════════════════╗
║               Capture Summary               ║
╠══════════════════════════════════════════════╣
Matched Packets : 5
TCP             : 1
UDP             : 1
ICMP            : 1
DNS             : 1
ARP             : 1
OTHER           : 0
Duration        : 2.00 sec
Average Rate    : 2.50 pkt/s
╚══════════════════════════════════════════════╝
```

## Example of What the Sniffer Displays
- Packet number
- Source IP
- Destination IP
- Protocol type
- Ports when available
- Extra information such as DNS query or TCP flags
- Optional payload preview

## What I Learned
- Packet sniffing with Scapy
- Inspecting packets in real time
- Detecting multiple network protocols
- Filtering packets for focused analysis
- Saving captured traffic to PCAP format
- Performing offline packet analysis

## Ethical Note
This project is for educational and authorized testing purposes only.  
Do not use packet sniffing tools on networks you do not own or have permission to monitor.
