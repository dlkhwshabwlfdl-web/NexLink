#!/usr/bin/env python3
"""Send one raw DNS query through the tunnel and check the answer.

Usage: dns_query.py <dns-server-ip>
The query is for example.test/A. Success = a response whose answer is
203.0.113.99 (the fake resolver's fixed answer). The server IP given here is
deliberately NOT where the fake resolver lives: if NexLink's DNS
interception works, the phone side resolves it locally anyway.
"""
import socket
import struct
import sys

server_ip = sys.argv[1]

# Build query: id=0x1234, rd=1, one question: example.test A IN
qname = b"".join(bytes([len(part)]) + part.encode() for part in "example.test".split(".")) + b"\x00"
query = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + qname + struct.pack(">HH", 1, 1)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(10)
sock.sendto(query, (server_ip, 53))
data, _ = sock.recvfrom(4096)

tid, flags, _qd, ancount = struct.unpack(">HHHH", data[:8])
assert tid == 0x1234, f"transaction id mismatch: {tid:#x}"
assert flags & 0x8000, "not a response"
assert ancount >= 1, "no answers"
assert data[-4:] == bytes([203, 0, 113, 99]), f"unexpected answer IP: {list(data[-4:])}"
print("dns_query: OK — answer 203.0.113.99 received via intercepted resolution")
