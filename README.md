# CodeAlpha Basic Network Sniffer

## Overview
This project is a basic network sniffer built in Python using Scapy.
It captures packets, extracts source and destination IP addresses,
identifies common protocols such as TCP, UDP, and ICMP, and displays a payload preview when available.

## Features
- Capture network packets
- Show source and destination IP addresses
- Detect TCP, UDP, and ICMP packets
- Display source and destination ports for TCP/UDP
- Show payload preview
- Save captured packets to a .pcap file

## Technologies Used
- Python
- Scapy

## How to Run
1. Install dependencies:
   pip install scapy

2. Run the script:
   python sniffer.py

## Output
The script captures 20 packets and saves them into:
capture_task1.pcap
