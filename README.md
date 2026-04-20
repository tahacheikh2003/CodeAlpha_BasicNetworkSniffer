# CodeAlpha - Advanced Basic Network Sniffer

## Overview
This project is an improved version of a basic network sniffer built with Python and Scapy for the CodeAlpha Cyber Security Internship.
It captures live packets, identifies important protocols, shows source and destination information, previews payload data, supports useful filters, and saves the capture into a PCAP file for later analysis.

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
- `sniffer.py` -> main live sniffer
- `analyzer.py` -> offline PCAP analyzer
- `requirements.txt` -> required Python packages
- `README.md` -> project documentation

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
- protocol distribution
- top source IPs
- top destination IPs
- most common ports
- DNS queries

## Example of What the Sniffer Displays
- packet number
- source IP
- destination IP
- protocol type
- ports when available
- extra information such as DNS query or TCP flags
- optional payload preview

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
