#!/usr/bin/env python3
"""Decapsulate shreds from nested GRE tunnels and forward as raw UDP.

Reads raw packets from a network interface, walks through nested GRE
layers (TEB 0x6558, IPv4 0x0800, ERSPAN 0x88be) added by DoubleZero
tunnels and Arista ERSPAN mirrors, extracts the innermost UDP payload,
and forwards it to a destination.

Filters out DZ heartbeats (port 44880) and tiny packets. Only forwards
packets likely to be shreds (large UDP payloads on non-heartbeat ports).

Usage:
    sudo scripts/shred-decap.py
    sudo scripts/shred-decap.py --forward-port 7005
    scripts/shred-decap.py --remote
"""

from __future__ import annotations

import argparse
import os
import signal
import socket
import struct
import subprocess
import sys
import time

IFACE = "eno1"
ETH_P_ALL = 0x0003
ETH_HEADER_LEN = 14
IP_HEADER_MIN = 20
GRE_HEADER_MIN = 4
UDP_HEADER_LEN = 8

GRE_PROTO_TEB = 0x6558  # transparent ethernet bridging
GRE_PROTO_IP4 = 0x0800
# ERSPAN Type II — Arista 7280CR3A sends raw IPv4 after the GRE key,
# no ERSPAN header. Treat same as GRE_PROTO_IP4.
GRE_PROTO_ERSPAN_II = 0x88BE

# Skip DZ heartbeat ports
HEARTBEAT_PORTS = frozenset({44880})

# Minimum payload size to forward (skip tiny control packets)
MIN_PAYLOAD_SIZE = 100

# Maximum GRE nesting depth — DZ full mesh can nest 30+ layers
MAX_GRE_DEPTH = 64


def extract_inner_udp(data: bytes) -> tuple[bytes, int, int] | None:
    """Walk nested GRE layers and extract innermost UDP payload.

    Returns (payload, src_port, dst_port) or None if not a forwardable packet.
    """
    offset = 0
    depth = 0

    # Outer Ethernet (from gretap)
    if len(data) < ETH_HEADER_LEN:
        return None

    eth_type = struct.unpack("!H", data[offset + 12 : offset + 14])[0]
    offset += ETH_HEADER_LEN

    while offset < len(data) and depth < MAX_GRE_DEPTH:
        if eth_type != 0x0800:
            return None

        # Parse IP header
        if len(data) < offset + IP_HEADER_MIN:
            return None
        vhl = data[offset]
        if (vhl >> 4) != 4:
            return None
        ihl = (vhl & 0x0F) * 4
        proto = data[offset + 9]
        offset += ihl

        if proto == 47:  # GRE
            if len(data) < offset + GRE_HEADER_MIN:
                return None
            flags = struct.unpack("!H", data[offset : offset + 2])[0]
            gre_proto = struct.unpack("!H", data[offset + 2 : offset + 4])[0]
            gre_len = 4
            if flags & 0x8000:  # checksum
                gre_len += 4
            if flags & 0x2000:  # key
                gre_len += 4
            if flags & 0x1000:  # sequence
                gre_len += 4
            offset += gre_len
            depth += 1

            if gre_proto == GRE_PROTO_TEB:
                # Another Ethernet frame inside
                if len(data) < offset + ETH_HEADER_LEN:
                    return None
                eth_type = struct.unpack("!H", data[offset + 12 : offset + 14])[0]
                offset += ETH_HEADER_LEN
                continue
            elif gre_proto in (GRE_PROTO_IP4, GRE_PROTO_ERSPAN_II):
                eth_type = 0x0800
                continue
            else:
                return None

        elif proto == 17:  # UDP
            if len(data) < offset + UDP_HEADER_LEN:
                return None
            src_port, dst_port, udp_len = struct.unpack("!HHH", data[offset : offset + 6])
            payload_len = udp_len - UDP_HEADER_LEN
            payload_start = offset + UDP_HEADER_LEN
            payload = data[payload_start : payload_start + payload_len]
            return (payload, src_port, dst_port)

        else:
            return None

    return None


def run_forwarder(
    forward_host: str,
    forward_port: int,
    stats_interval: int,
) -> None:
    """Main forwarding loop."""
    # Raw socket on gretap-bebop
    sock_in = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    sock_in.bind((IFACE, 0))

    # UDP socket for forwarding
    sock_out = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    dest = (forward_host, forward_port)

    forwarded = 0
    dropped_heartbeat = 0
    dropped_small = 0
    dropped_parse = 0
    total = 0
    start = time.monotonic()
    last_stats = start

    # Graceful shutdown
    running = True

    def handle_signal(signum: int, frame: object) -> None:
        nonlocal running
        running = False

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    print(
        f"Forwarding {IFACE} → {forward_host}:{forward_port} "
        f"(skip heartbeat ports {HEARTBEAT_PORTS}, "
        f"min payload {MIN_PAYLOAD_SIZE}B)",
        flush=True,
    )

    while running:
        try:
            data = sock_in.recv(65535)
        except (TimeoutError, OSError):
            if not running:
                break
            continue

        total += 1

        result = extract_inner_udp(data)
        if result is None:
            dropped_parse += 1
            continue

        payload, src_port, dst_port = result

        # Filter heartbeats
        if src_port in HEARTBEAT_PORTS or dst_port in HEARTBEAT_PORTS:
            dropped_heartbeat += 1
            continue

        # Filter tiny packets
        if len(payload) < MIN_PAYLOAD_SIZE:
            dropped_small += 1
            continue

        sock_out.sendto(payload, dest)
        forwarded += 1

        # Periodic stats
        now = time.monotonic()
        if now - last_stats >= stats_interval:
            elapsed = now - start
            rate = forwarded / elapsed if elapsed > 0 else 0
            total_rate = total / elapsed if elapsed > 0 else 0
            print(
                f"[{elapsed:.0f}s] forwarded={forwarded:,} "
                f"({rate:.0f}/s) "
                f"total={total:,} ({total_rate:.0f}/s) "
                f"dropped: heartbeat={dropped_heartbeat:,} "
                f"small={dropped_small:,} "
                f"parse={dropped_parse:,}",
                flush=True,
            )
            last_stats = now

    # Final stats
    elapsed = time.monotonic() - start
    print(
        f"\nShutdown after {elapsed:.0f}s. "
        f"Forwarded {forwarded:,} packets, "
        f"dropped {dropped_heartbeat + dropped_small + dropped_parse:,} "
        f"(heartbeat={dropped_heartbeat:,} "
        f"small={dropped_small:,} "
        f"parse={dropped_parse:,})",
        flush=True,
    )

    sock_in.close()
    sock_out.close()


def run_remote(args: argparse.Namespace) -> None:
    """Run this script on biscayne via SSH."""
    script = os.path.abspath(__file__)
    cmd = [
        "ssh",
        "biscayne.vaasl.io",
        f"sudo python3 - "
        f"--forward-host {args.forward_host} "
        f"--forward-port {args.forward_port} "
        f"--stats-interval {args.stats_interval}",
    ]
    with open(script, "rb") as f:
        r = subprocess.run(cmd, input=f.read(), timeout=None)
    sys.exit(r.returncode)


def main() -> int:
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--forward-host",
        default="172.20.0.2",
        help="Host to forward extracted payloads to (default: 172.20.0.2, " "the kind node pod IP)",
    )
    p.add_argument(
        "--forward-port",
        type=int,
        default=9000,
        help="Port to forward extracted payloads to (default: 9000, " "the validator TVU port)",
    )
    p.add_argument(
        "--stats-interval",
        type=int,
        default=30,
        help="Print stats every N seconds (default: 30)",
    )
    p.add_argument(
        "--remote",
        action="store_true",
        help="Run on biscayne via SSH",
    )
    args = p.parse_args()

    if args.remote:
        run_remote(args)
        return 0

    run_forwarder(args.forward_host, args.forward_port, args.stats_interval)
    return 0


if __name__ == "__main__":
    sys.exit(main())
