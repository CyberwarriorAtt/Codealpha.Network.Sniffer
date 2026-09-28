# Task 1: Basic Network Sniffer

A command-line packet sniffer built with Python and Scapy.

## Features
- Captures live packets (IPv4/IPv6)
- Shows source/destination IPs, protocol (TCP/UDP/ICMP), ports and TCP flags
- Decodes DNS queries and shows a printable payload preview
- BPF filters, packet count, and `.pcap` export
- Protocol summary at the end

## Setup
```bash
pip install scapy
```
Windows also needs [Npcap](https://npcap.com) and an Administrator terminal.

## Usage
```bash
sudo python3 network_sniffer.py -c 30                 # capture 30 packets
sudo python3 network_sniffer.py -f "tcp port 80"      # filter
sudo python3 network_sniffer.py -i wlan0 -w out.pcap  # choose interface, save
```

| Option | Meaning |
|---|---|
| `-i` | interface |
| `-c` | packet count (0 = until Ctrl+C) |
| `-f` | BPF filter |
| `-w` | save to pcap |

## What I learned
- Packets are layered: Ethernet, IP, TCP/UDP, then the payload.
- TCP flags (SYN, ACK, FIN) show the handshake and connection state.
- Unencrypted protocols (HTTP, DNS) expose data; HTTPS payloads appear as random bytes.

## Legal note
Capture only on networks you own or are authorized to monitor.
