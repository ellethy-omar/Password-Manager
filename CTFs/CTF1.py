# python3.14 CTF1.py assets/traffic.pcapng

import sys
import base64
from scapy.all import rdpcap, TCP, Raw

def solve(pcap_path: str) -> None:
    packets = rdpcap(pcap_path)
    collected = b""
    packet_count = 0 

    for pkt in packets:
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            tcp = pkt[TCP]

            if tcp.sport == 4444 or tcp.dport == 4444:
                payload = bytes(pkt[Raw])

                # print(f"Packet seq={tcp.seq} | {len(payload)} bytes: {payload[:40]}...")
                # print(f"\n")
                collected += payload
                packet_count += 1

    if not collected:
        print("[ERROR] No payload found on port 4444. Check the pcap file.")
        return

    print(f"Total packets captured: {packet_count}")
    print(f"Total raw bytes collected: {len(collected)}")
    # print(f"Raw (base64) data: {collected.decode(errors='replace')}\n")

    cleaned = collected.decode(errors="replace").strip().replace("\n", "").replace("\r", "")

    if cleaned.startswith("MSG:") and cleaned.endswith(":EOF"):
        cleaned = cleaned[4:-4]   # [4:] skips "MSG:", [:-4] removes ":EOF"
        # print(f"Detected MSG:...:EOF framing, stripped to: {cleaned}")

    try:
        decoded = base64.b64decode(cleaned).decode()
        print(f"FLAG: {decoded}")
    except Exception as e:
        print(f"[ERROR] Base64 decode failed: {e} Try decoding the raw data manually.")



if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python ctf1_packet_analysis.py <traffic.pcapng>")
        sys.exit(1)

    solve(sys.argv[1])