from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, wrpcap

captured_packets = []
packet_counter = 0

def process_packet(packet):
    global packet_counter
    packet_counter += 1

    if IP not in packet:
        return

    captured_packets.append(packet)

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    print(f"\nPacket #{packet_counter}")
    print(f"Source IP: {src_ip}")
    print(f"Destination IP: {dst_ip}")

    if TCP in packet:
        print("Protocol: TCP")
        print(f"Source Port: {packet[TCP].sport}")
        print(f"Destination Port: {packet[TCP].dport}")

    elif UDP in packet:
        print("Protocol: UDP")
        print(f"Source Port: {packet[UDP].sport}")
        print(f"Destination Port: {packet[UDP].dport}")

    elif ICMP in packet:
        print("Protocol: ICMP")

    else:
        print(f"Protocol: Other ({packet[IP].proto})")

    if Raw in packet:
        payload_bytes = bytes(packet[Raw].load)
        preview = payload_bytes[:32]

        try:
            preview_text = preview.decode("utf-8", errors="replace")
            print(f"Payload Preview: {preview_text}")
        except:
            print(f"Payload Preview (raw bytes): {preview}")

    else:
        print("Payload Preview: No raw payload")

    print("-" * 50)

print("Sniffing started... Generate some traffic and wait.")
sniff(prn=process_packet, store=False, count=20)

wrpcap("capture_task1.pcap", captured_packets)
print("\nCapture finished.")
print(f"Saved {len(captured_packets)} packets to capture_task1.pcap")