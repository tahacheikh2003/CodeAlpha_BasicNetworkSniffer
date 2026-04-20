#!/usr/bin/env python3
"""
CodeAlpha - Task 1
Advanced Network Sniffer with clean terminal output
"""

import argparse
import os
import sys
import time
import signal
import platform
from collections import Counter
from datetime import datetime

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, DNS, DNSQR, ARP, wrpcap
except ImportError:
    print("[!] Scapy is not installed. Run: pip install scapy")
    sys.exit(1)

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    class Dummy:
        def __getattr__(self, _):
            return ""
    Fore = Style = Dummy()

matched_packets = []
stats = Counter()
start_time = time.time()
packet_counter = 0


def is_admin() -> bool:
    try:
        if platform.system() == "Windows":
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        return os.geteuid() == 0
    except Exception:
        return True


def now_time() -> str:
    return datetime.now().strftime("%H:%M:%S.%f")[:-3]


def protocol_color(proto: str) -> str:
    base = proto.split("(")[0]
    return {
        "TCP": Fore.GREEN,
        "UDP": Fore.BLUE,
        "ICMP": Fore.YELLOW,
        "DNS": Fore.CYAN,
        "ARP": Fore.MAGENTA,
        "OTHER": Fore.WHITE,
    }.get(base, Fore.WHITE)


def protocol_tag(proto: str) -> str:
    return f"{protocol_color(proto)}[{proto:^7}]{Style.RESET_ALL}"


def format_flags(flags_value) -> str:
    mapping = [(0x02, "SYN"), (0x10, "ACK"), (0x01, "FIN"), (0x04, "RST"), (0x08, "PSH"), (0x20, "URG")]
    try:
        value = int(flags_value)
        active = [name for bit, name in mapping if value & bit]
        return "|".join(active) if active else str(flags_value)
    except Exception:
        return str(flags_value)


def summarize_packet(packet):
    info = {
        "protocol": "OTHER",
        "src": "-",
        "dst": "-",
        "sport": None,
        "dport": None,
        "extra": "Non-IP frame",
        "payload": "",
    }

    if ARP in packet:
        arp = packet[ARP]
        op = "Request" if arp.op == 1 else "Reply"
        info.update({
            "protocol": "ARP",
            "src": arp.psrc,
            "dst": arp.pdst,
            "extra": f"{op} | MAC {arp.hwsrc} -> {arp.hwdst}",
        })
        return info

    if IP in packet:
        ip = packet[IP]
        info["src"] = ip.src
        info["dst"] = ip.dst

        if DNS in packet and DNSQR in packet:
            qname = packet[DNSQR].qname.decode(errors="replace").rstrip(".")
            info["protocol"] = "DNS"
            info["extra"] = f"Query: {qname}"
            if UDP in packet:
                info["sport"] = packet[UDP].sport
                info["dport"] = packet[UDP].dport
            elif TCP in packet:
                info["sport"] = packet[TCP].sport
                info["dport"] = packet[TCP].dport

        elif TCP in packet:
            tcp = packet[TCP]
            flags = format_flags(tcp.flags)
            info["protocol"] = "TCP"
            info["sport"] = tcp.sport
            info["dport"] = tcp.dport
            info["extra"] = f"Port {tcp.sport} -> {tcp.dport} | Flags: {flags}"

        elif UDP in packet:
            udp = packet[UDP]
            info["protocol"] = "UDP"
            info["sport"] = udp.sport
            info["dport"] = udp.dport
            info["extra"] = f"Port {udp.sport} -> {udp.dport} | Length: {udp.len}"

        elif ICMP in packet:
            icmp = packet[ICMP]
            info["protocol"] = "ICMP"
            icmp_types = {0: "Echo Reply", 8: "Echo Request", 3: "Destination Unreachable"}
            info["extra"] = icmp_types.get(icmp.type, f"Type {icmp.type}")

        else:
            info["protocol"] = f"OTHER({ip.proto})"
            info["extra"] = f"IP Protocol Number: {ip.proto}"

    if Raw in packet:
        raw_data = bytes(packet[Raw].load)[:60]
        info["payload"] = raw_data.decode("utf-8", errors="replace").replace("\n", " ")

    return info


def packet_matches(info, args):
    if args.filter_proto:
        wanted = {p.upper() for p in args.filter_proto}
        base = info["protocol"].split("(")[0].upper()
        if base not in wanted:
            return False

    if args.filter_ip and args.filter_ip not in (info["src"], info["dst"]):
        return False

    if args.filter_port is not None:
        if args.filter_port not in (info["sport"], info["dport"]):
            return False

    return True


def print_banner(args):
    print(Fore.CYAN + "╔══════════════════════════════════════════════════════════════════════════════╗")
    print("║                    CodeAlpha - Advanced Network Sniffer                     ║")
    print("╚══════════════════════════════════════════════════════════════════════════════╝" + Style.RESET_ALL)
    print(f"{Fore.GREEN}[*] Interface: {args.interface or 'default'} | Count: {'∞' if args.count == 0 else args.count} | Output: {args.output}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'Time':<12} {'#':<6} {'Proto':<11} {'Source':<18} {'Destination':<18} Info{Style.RESET_ALL}")
    print(Fore.CYAN + "─" * 110 + Style.RESET_ALL)


def print_stats():
    elapsed = time.time() - start_time
    rate = packet_counter / elapsed if elapsed > 0 else 0
    print(Fore.CYAN + "\n" + "─" * 110)
    print(f"{Fore.YELLOW}Live Stats{Style.RESET_ALL} | Total: {packet_counter} | TCP: {stats['TCP']} | UDP: {stats['UDP']} | ICMP: {stats['ICMP']} | DNS: {stats['DNS']} | ARP: {stats['ARP']} | OTHER: {stats['OTHER']} | Rate: {rate:.2f} pkt/s")
    print(Fore.CYAN + "─" * 110 + Style.RESET_ALL)


def process_packet(packet, args):
    global packet_counter

    info = summarize_packet(packet)
    if not packet_matches(info, args):
        return

    matched_packets.append(packet)
    packet_counter += 1

    base = info["protocol"].split("(")[0]
    stats[base] += 1

    line = (
        f"{Fore.CYAN}{now_time():<12}{Style.RESET_ALL} "
        f"#{packet_counter:<5} "
        f"{protocol_tag(info['protocol']):<20} "
        f"{Fore.WHITE}{info['src']:<18}{Style.RESET_ALL} "
        f"{Fore.WHITE}{info['dst']:<18}{Style.RESET_ALL} "
        f"{protocol_color(info['protocol'])}{info['extra']}{Style.RESET_ALL}"
    )
    print(line)

    if args.show_payload and info["payload"]:
        print(f"{'':<40}{Fore.LIGHTBLACK_EX}Payload: {info['payload']}{Style.RESET_ALL}")

    if args.live_stats and packet_counter % args.stats_every == 0:
        print_stats()


def save_capture(path: str):
    if matched_packets:
        wrpcap(path, matched_packets)
        print(Fore.GREEN + f"\n[+] Saved {len(matched_packets)} packets to {path}" + Style.RESET_ALL)
    else:
        print(Fore.YELLOW + "\n[!] No packets matched the selected filters." + Style.RESET_ALL)


def final_summary():
    elapsed = time.time() - start_time
    rate = packet_counter / elapsed if elapsed > 0 else 0
    print(Fore.CYAN + "\n╔══════════════════════════════════════════════╗")
    print("║               Capture Summary               ║")
    print("╠══════════════════════════════════════════════╣" + Style.RESET_ALL)
    print(f"Matched Packets : {packet_counter}")
    print(f"TCP             : {stats['TCP']}")
    print(f"UDP             : {stats['UDP']}")
    print(f"ICMP            : {stats['ICMP']}")
    print(f"DNS             : {stats['DNS']}")
    print(f"ARP             : {stats['ARP']}")
    print(f"OTHER           : {stats['OTHER']}")
    print(f"Duration        : {elapsed:.2f} sec")
    print(f"Average Rate    : {rate:.2f} pkt/s")
    print(Fore.CYAN + "╚══════════════════════════════════════════════╝" + Style.RESET_ALL)


def build_parser():
    parser = argparse.ArgumentParser(description="Advanced network sniffer with clean output")
    parser.add_argument("-i", "--interface", default=None, help="Network interface to sniff on")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0 = infinite)")
    parser.add_argument("--filter-proto", nargs="+", help="Filter by protocol: TCP UDP ICMP DNS ARP")
    parser.add_argument("--filter-ip", help="Filter by source or destination IP")
    parser.add_argument("--filter-port", type=int, help="Filter by source or destination port")
    parser.add_argument("--show-payload", action="store_true", help="Display payload preview")
    parser.add_argument("--live-stats", action="store_true", help="Show live stats during capture")
    parser.add_argument("--stats-every", type=int, default=10, help="Show live stats every N packets")
    parser.add_argument("-o", "--output", default="capture_task1.pcap", help="Output PCAP file")
    return parser


def main():
    args = build_parser().parse_args()

    if not is_admin():
        print("[!] Administrator/root privileges are recommended for full packet sniffing.")
        print("    Windows: run terminal as Administrator.")
        print("    Linux/macOS: use sudo if needed.\n")

    print_banner(args)

    def stop_handler(sig, frame):
        print(Fore.YELLOW + "\n[!] Capture stopped by user." + Style.RESET_ALL)
        save_capture(args.output)
        final_summary()
        sys.exit(0)

    signal.signal(signal.SIGINT, stop_handler)

    sniff(
        iface=args.interface,
        prn=lambda pkt: process_packet(pkt, args),
        store=False,
        count=args.count,
    )

    print(Fore.CYAN + "\n[*] Capture finished." + Style.RESET_ALL)
    save_capture(args.output)
    final_summary()


if __name__ == "__main__":
    main()
