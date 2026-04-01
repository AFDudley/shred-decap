#!/usr/bin/env python3
"""Debug the nested GRE structure of mirrored bebop packets on gretap-bebop.

Captures a few packets and prints the layer-by-layer structure to understand
what needs to be stripped before forwarding to the validator.

Usage:
    scripts/bebop-packet-debug.py              # capture 5 packets
    scripts/bebop-packet-debug.py -n 20        # capture 20 packets
    scripts/bebop-packet-debug.py --remote     # run via SSH on biscayne
"""

from __future__ import annotations

import argparse
import socket
import struct
import subprocess
import sys

IFACE = "gretap-bebop"
ETH_P_ALL = 0x0003
ETH_HEADER_LEN = 14
IP_HEADER_MIN = 20
GRE_HEADER_MIN = 4

# GRE protocol types
GRE_PROTO_TEB = 0x6558  # transparent ethernet bridging
GRE_PROTO_IP4 = 0x0800


def parse_ip(data: bytes, offset: int) -> tuple[str, str, int, int]:
    """Parse IP header. Returns (src, dst, protocol, header_len)."""
    if len(data) < offset + IP_HEADER_MIN:
        return ("?", "?", 0, 0)
    vhl = data[offset]
    ihl = (vhl & 0x0F) * 4
    proto = data[offset + 9]
    src = socket.inet_ntoa(data[offset + 12 : offset + 16])
    dst = socket.inet_ntoa(data[offset + 16 : offset + 20])
    return (src, dst, proto, ihl)


def parse_gre(data: bytes, offset: int) -> tuple[int, int]:
    """Parse GRE header. Returns (protocol, header_len)."""
    if len(data) < offset + GRE_HEADER_MIN:
        return (0, 0)
    flags = struct.unpack("!H", data[offset : offset + 2])[0]
    proto = struct.unpack("!H", data[offset + 2 : offset + 4])[0]
    hdr_len = 4
    if flags & 0x8000:  # checksum present
        hdr_len += 4
    if flags & 0x2000:  # key present
        hdr_len += 4
    if flags & 0x1000:  # sequence present
        hdr_len += 4
    return (proto, hdr_len)


def parse_udp(data: bytes, offset: int) -> tuple[int, int, int]:
    """Parse UDP header. Returns (src_port, dst_port, payload_len)."""
    if len(data) < offset + 8:
        return (0, 0, 0)
    src_port, dst_port, length = struct.unpack("!HHH", data[offset : offset + 6])
    return (src_port, dst_port, length - 8)


def decode_packet(data: bytes) -> None:
    """Walk through nested GRE layers and print structure."""
    offset = 0
    depth = 0
    indent = "  "

    # Outer Ethernet (from gretap)
    if len(data) < ETH_HEADER_LEN:
        print(f"  [too short: {len(data)} bytes]")
        return

    eth_type = struct.unpack("!H", data[offset + 12 : offset + 14])[0]
    print(f"{indent * depth}ETH type=0x{eth_type:04x} ({len(data)} bytes)")
    offset += ETH_HEADER_LEN

    while offset < len(data):
        if eth_type == 0x0800:  # IPv4
            src, dst, proto, ihl = parse_ip(data, offset)
            print(f"{indent * depth}IP {src} > {dst} proto={proto} ihl={ihl}")
            offset += ihl

            if proto == 47:  # GRE
                gre_proto, gre_len = parse_gre(data, offset)
                print(f"{indent * depth}GRE proto=0x{gre_proto:04x} " f"hdr={gre_len}")
                offset += gre_len
                depth += 1

                if gre_proto == GRE_PROTO_TEB:
                    # Another Ethernet frame
                    if len(data) < offset + ETH_HEADER_LEN:
                        print(f"{indent * depth}[truncated ETH]")
                        break
                    eth_type = struct.unpack("!H", data[offset + 12 : offset + 14])[0]
                    print(
                        f"{indent * depth}ETH type=0x{eth_type:04x} "
                        f"(remaining {len(data) - offset} bytes)"
                    )
                    offset += ETH_HEADER_LEN
                    continue
                elif gre_proto == GRE_PROTO_IP4:
                    # Inner IPv4 — this is likely the payload
                    eth_type = 0x0800
                    continue
                else:
                    print(f"{indent * depth}[unknown GRE proto " f"0x{gre_proto:04x}]")
                    break

            elif proto == 17:  # UDP
                src_port, dst_port, payload_len = parse_udp(data, offset)
                print(
                    f"{indent * depth}UDP {src_port} > {dst_port} " f"payload={payload_len} bytes"
                )
                print(
                    f"{indent * depth}>>> INNERMOST PAYLOAD at offset "
                    f"{offset + 8}, {payload_len} bytes"
                )
                # Show first 32 bytes of payload as hex
                payload_start = offset + 8
                payload_end = min(payload_start + 32, len(data))
                hexdump = data[payload_start:payload_end].hex(" ")
                print(f"{indent * depth}    hex: {hexdump}")
                break

            else:
                print(f"{indent * depth}[proto {proto}, stopping]")
                break
        else:
            print(f"{indent * depth}[non-IPv4 ethertype 0x{eth_type:04x}]")
            break


def capture_local(count: int) -> None:
    """Capture packets locally on gretap-bebop."""
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    sock.bind((IFACE, 0))
    sock.settimeout(5.0)

    print(f"Capturing {count} packets on {IFACE}...\n")

    for i in range(count):
        try:
            data = sock.recv(65535)
        except TimeoutError:
            print("(timeout)")
            break

        print(f"--- Packet {i + 1} ({len(data)} bytes) ---")
        decode_packet(data)
        print()

    sock.close()


def capture_remote(count: int) -> None:
    """Run this script on biscayne via SSH."""

    script = __file__
    r = subprocess.run(
        ["ssh", "biscayne.vaasl.io", f"sudo python3 - -n {count}"],
        input=open(script, "rb").read(),
        capture_output=True,
        timeout=30,
    )
    sys.stdout.write(r.stdout.decode())
    if r.stderr:
        sys.stderr.write(r.stderr.decode())
    sys.exit(r.returncode)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("-n", "--count", type=int, default=5)
    p.add_argument("--remote", action="store_true", help="Run on biscayne via SSH")
    args = p.parse_args()

    if args.remote:
        capture_remote(args.count)
    else:
        capture_local(args.count)
    return 0


if __name__ == "__main__":
    sys.exit(main())
