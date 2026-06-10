#!/usr/bin/env python3
"""
dns_tunnel_selftest.py — Local loopback test for the DNS tunnel
Spins up server and client in-process to validate encode/decode roundtrip.

Usage:
    python3 dns_tunnel_selftest.py
"""

import threading
import time
import sys
import os
import tempfile

TEST_PORT = 15353   # unprivileged test port

# Patch DOMAIN and port in both modules before importing
os.environ["DNS_TUNNEL_DOMAIN"] = "vsphere.loca1"

# ── Inline minimal server (extracted logic) ───────────────────────────────────
import socket
import struct
import base64
from collections import defaultdict

DOMAIN     = "vsphere.loca1"
CHUNK_SIZE = 30

def parse_dns_query(data):
    if len(data) < 12: return None, None, None
    txid = struct.unpack("!H", data[0:2])[0]
    offset, labels = 12, []
    while offset < len(data):
        ln = data[offset]
        if ln == 0: offset += 1; break
        if ln & 0xC0 == 0xC0: offset += 2; break
        labels.append(data[offset+1:offset+1+ln].decode("ascii","replace"))
        offset += 1 + ln
    qtype = struct.unpack("!H", data[offset:offset+2])[0] if offset+2 <= len(data) else 0
    return txid, ".".join(labels), qtype

def build_dns_response(txid, qname, ip="10.0.0.1"):
    flags = 0x8180
    hdr   = struct.pack("!HHHHHH", txid, flags, 1, 1, 0, 0)
    q = b""
    for lbl in qname.split("."):
        enc = lbl.encode()
        q  += bytes([len(enc)]) + enc
    q += b"\x00" + struct.pack("!HH", 1, 1)
    ans  = b"\xc0\x0c" + struct.pack("!HHI", 1, 1, 0)
    ans += struct.pack("!H4B", 4, *map(int, ip.split(".")))
    return hdr + q + ans

def b32decode_chunk(s):
    s = s.upper()
    s += "=" * ((8 - len(s) % 8) % 8)
    return base64.b32decode(s)

def run_server(result_holder, ready_event, port=TEST_PORT):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", port))
    sock.settimeout(5)
    sessions = defaultdict(dict)   # sess_id → {seq: bytes}
    totals   = {}
    ready_event.set()

    while True:
        try:
            data, addr = sock.recvfrom(512)
        except socket.timeout:
            break
        txid, qname, _ = parse_dns_query(data)
        if not qname or not qname.endswith(DOMAIN):
            continue
        sub    = qname[:-(len(DOMAIN)+1)]
        labels = sub.split(".")
        if labels[0] == "ping":
            sock.sendto(build_dns_response(txid, qname), addr)
            continue
        if not labels[0].startswith("t-"):
            continue
        try:
            _, sid, seq_h, tot_h = labels[0].split("-")
            seq   = int(seq_h, 16)
            total = int(tot_h, 16)
            b32   = "".join(labels[1:])
            sessions[sid][seq] = b32decode_chunk(b32)
            totals[sid] = total
        except Exception as e:
            continue
        ack = f"10.0.{(seq>>8)&0xFF}.{seq&0xFF}"
        sock.sendto(build_dns_response(txid, qname, ip=ack), addr)

        if totals.get(sid) and len(sessions[sid]) == totals[sid]:
            result = b"".join(sessions[sid][i] for i in sorted(sessions[sid]))
            result_holder.append(result)

    sock.close()


def run_client(payload: bytes, port=TEST_PORT):
    import random, string, time
    sess  = "test01"
    chunks = [payload[i:i+CHUNK_SIZE] for i in range(0, len(payload), CHUNK_SIZE)]
    total  = len(chunks)

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # ping
    txid = 1
    hdr  = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    q    = b""
    for lbl in f"ping.{DOMAIN}".split("."):
        enc = lbl.encode(); q += bytes([len(enc)]) + enc
    q += b"\x00" + struct.pack("!HH",1,1)
    s.sendto(hdr+q, ("127.0.0.1", port))
    s.settimeout(2)
    s.recvfrom(512)

    for seq, chunk in enumerate(chunks):
        b32    = base64.b32encode(chunk).decode().rstrip("=").lower()
        labels = [b32[i:i+48] for i in range(0, len(b32), 48)]
        hdr_lbl = f"t-{sess}-{seq:04x}-{total:04x}"
        qname   = f"{hdr_lbl}.{'.'.join(labels)}.{DOMAIN}"
        txid    = seq + 10
        pkt_hdr = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
        q = b""
        for lbl in qname.split("."):
            enc = lbl.encode(); q += bytes([len(enc)]) + enc
        q += b"\x00" + struct.pack("!HH",1,1)
        s.sendto(pkt_hdr+q, ("127.0.0.1", port))
        try: s.recvfrom(512)
        except: pass
        time.sleep(0.02)

    s.close()


# ── Run test ──────────────────────────────────────────────────────────────────

def main():
    tests = [
        b"Hello from Phantom Protocol lab!",
        b"A" * 100,
        bytes(range(256)),
    ]

    all_passed = True
    for i, payload in enumerate(tests):
        result_holder = []
        ready = threading.Event()
        srv = threading.Thread(target=run_server, args=(result_holder, ready), daemon=True)
        srv.start()
        ready.wait(timeout=2)
        time.sleep(0.1)

        run_client(payload, port=TEST_PORT)
        srv.join(timeout=6)

        if result_holder and result_holder[0] == payload:
            print(f"[PASS] Test {i+1}: {len(payload)} bytes roundtrip OK")
        else:
            got = result_holder[0] if result_holder else b"<nothing>"
            print(f"[FAIL] Test {i+1}: expected {payload[:40]!r}  got {got[:40]!r}")
            all_passed = False

    print()
    if all_passed:
        print("✓ All tests passed — tunnel encode/decode is correct")
    else:
        print("✗ Some tests failed")
        sys.exit(1)

if __name__ == "__main__":
    main()
