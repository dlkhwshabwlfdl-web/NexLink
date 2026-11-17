#!/usr/bin/env python3
"""A fake DNS resolver for the NexLink end-to-end test.

Listens on 127.0.0.1:15353 and answers every A query with 203.0.113.99.
In the test topology this plays the role of "the phone's own resolver":
simphone intercepts PC DNS flows (port 53) and sends them here instead of
to the address the PC dialed — so a correct answer proves interception.
"""
import socket
import struct
import sys

ANSWER_IP = bytes([203, 0, 113, 99])


def build_response(query: bytes) -> bytes:
    tid, _flags, qdcount = struct.unpack(">HHH", query[:6])
    # Find the end of the question section.
    pos = 12
    for _ in range(qdcount):
        while query[pos] != 0:
            pos += query[pos] + 1
        pos += 5  # null terminator + qtype + qclass
    question = query[12:pos]
    header = struct.pack(">HHHHHH", tid, 0x8180, qdcount, 1, 0, 0)
    answer = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + ANSWER_IP
    return header + question + answer


def main() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 15353))
    print("fake_dns: listening on 127.0.0.1:15353", flush=True)
    while True:
        data, addr = sock.recvfrom(4096)
        try:
            sock.sendto(build_response(data), addr)
        except Exception as exc:  # noqa: BLE001 - test helper, keep serving
            print(f"fake_dns: bad query: {exc}", file=sys.stderr, flush=True)


if __name__ == "__main__":
    main()
