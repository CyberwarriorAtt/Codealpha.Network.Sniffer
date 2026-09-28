#!/usr/bin/env python3
"""
Task 1: Basic Network Sniffer
Captures packets with scapy and shows source/destination IPs, protocol,
ports, and a readable payload preview. Optionally saves a .pcap file.

Install:  pip install scapy
Run:      sudo python3 task1_network_sniffer.py            (Linux/macOS)
          python task1_network_sniffer.py                  (Windows, run as Admin, Npcap installed)

Only capture traffic on networks you own or have permission to monitor.
"""
import argparse
from collections import Counter
from datetime import datetime

from scapy.all import sniff, wrpcap, IP, IPv6, TCP, UDP, ICMP, DNS, DNSQR, Raw

stats = Counter()
captured = []


def payload_preview(pkt, limit=60):
    """Return a printable preview of the packet payload."""
    if Raw not in pkt:
        return "-"
    data = bytes(pkt[Raw].load)[:limit]
    return "".join(chr(b) if 32 <= b < 127 else "." for b in data)


def handle(pkt):
    if IP in pkt:
        src, dst, ver = pkt[IP].src, pkt[IP].dst, "IPv4"
    elif IPv6 in pkt:
        src, dst, ver = pkt[IPv6].src, pkt[IPv6].dst, "IPv6"
    else:
        stats["Other"] += 1
        return

    proto, ports = "Other", ""
    if TCP in pkt:
        proto = "TCP"
        ports = f"{pkt[TCP].sport} -> {pkt[TCP].dport}  flags={pkt[TCP].flags}"
    elif UDP in pkt:
        proto = "UDP"
        ports = f"{pkt[UDP].sport} -> {pkt[UDP].dport}"
    elif ICMP in pkt:
        proto = "ICMP"
        ports = f"type={pkt[ICMP].type} code={pkt[ICMP].code}"

    stats[proto] += 1
    captured.append(pkt)

    print(f"\n[{datetime.now():%H:%M:%S}] {ver} {proto}  {len(pkt)} bytes")
    print(f"  {src} -> {dst}")
    if ports:
        print(f"  Ports/Info : {ports}")
    if DNS in pkt and pkt.haslayer(DNSQR):
        print(f"  DNS query  : {pkt[DNSQR].qname.decode(errors='ignore')}")
    print(f"  Payload    : {payload_preview(pkt)}")


def main():
    p = argparse.ArgumentParser(description="Basic network sniffer")
    p.add_argument("-i", "--iface", help="interface (default: auto)")
    p.add_argument("-c", "--count", type=int, default=50, help="packets to capture (0 = until Ctrl+C)")
    p.add_argument("-f", "--filter", default="", help="BPF filter, e.g. 'tcp port 80'")
    p.add_argument("-w", "--write", help="save capture to a .pcap file")
    args = p.parse_args()

    print(f"Sniffing... filter='{args.filter or 'none'}'  (Ctrl+C to stop)")
    try:
        sniff(iface=args.iface, filter=args.filter, prn=handle, count=args.count, store=False)
    except PermissionError:
        print("Permission denied: run as root/Administrator.")
        return
    except KeyboardInterrupt:
        pass

    print("\n--- Summary ---")
    for proto, n in stats.most_common():
        print(f"{proto:6} {n}")
    if args.write and captured:
        wrpcap(args.write, captured)
        print(f"Saved {len(captured)} packets to {args.write}")


if __name__ == "__main__":
    main()
