#!/usr/bin/env python3
import argparse
import socket
import sys
import time
from typing import List, Tuple


def parse_ports(spec: str) -> List[int]:
    """Accepts '1-1000' or '22,80,443' or mixed '1-1024,3306'."""
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            start, end = int(a), int(b)
            if start > end:
                start, end = end, start
            for p in range(start, end + 1):
                ports.add(p)
        else:
            ports.add(int(part))

    ports_list = sorted(ports)
    for p in ports_list:
        if p < 1 or p > 65535:
            raise ValueError(f"Invalid port {p}. Must be 1-65535.")
    return ports_list


def grab_banner(sock: socket.socket) -> str:
    """Try to read a small banner after connecting."""
    try:
        data = sock.recv(512)
        if not data:
            return ""
        text = data.decode(errors="replace").strip()
        return " ".join(text.split())[:120]
    except (socket.timeout, OSError):
        return ""


def guess_service(port: int, banner: str) -> str:
    b = banner.lower()
    if port == 3306 or "mysql" in b:
        return "MySQL"
    if port == 6379 or "redis" in b:
        return "Redis"
    if port in (80, 443, 5000, 5001, 8888) or "http" in b:
        return "HTTP"
    if port in (22, 2222) or "ssh" in b:
        return "SSH"
    return "Unknown" if banner else ""


def scan_port(target: str, port: int, timeout: float) -> Tuple[bool, float, str, str]:
    """TCP connect scan a single port. Returns open?, rtt_ms, banner, service_guess."""
    t0 = time.perf_counter()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((target, port))
        rtt_ms = (time.perf_counter() - t0) * 1000.0
        s.settimeout(0.5)
        banner = grab_banner(s)
        service = guess_service(port, banner)
        return True, rtt_ms, banner, service
    except (socket.timeout, ConnectionRefusedError, OSError):
        rtt_ms = (time.perf_counter() - t0) * 1000.0
        return False, rtt_ms, "", ""
    finally:
        try:
            s.close()
        except OSError:
            pass


def main() -> None:
    parser = argparse.ArgumentParser(description="CSCE 413 A2 - TCP Connect Port Scanner")
    parser.add_argument("--target", required=True, help="Target hostname/IP (e.g., secret_api, webapp, 172.20.0.5)")
    parser.add_argument("--ports", required=True, help='Ports (e.g., "1-10000" or "22,80,443")')
    parser.add_argument("--timeout", type=float, default=1.0, help="Connect timeout seconds (default 1.0)")
    args = parser.parse_args()

    # Resolve target early for nicer errors
    try:
        resolved = socket.gethostbyname(args.target)
    except socket.gaierror:
        print(f"[!] Could not resolve target: {args.target}")
        sys.exit(1)

    try:
        ports = parse_ports(args.ports)
    except ValueError as e:
        print(f"[!] {e}")
        sys.exit(1)

    print(f"[*] Target: {args.target} ({resolved})")
    print(f"[*] Ports: {ports[0]}-{ports[-1]} ({len(ports)} total)")
    print(f"[*] Timeout: {args.timeout}s\n")

    open_ports = []
    for i, port in enumerate(ports, start=1):
        is_open, rtt_ms, banner, service = scan_port(args.target, port, args.timeout)
        state = "open" if is_open else "closed"

        # Required: show port, state, timing
        print(f"Port {port:5d}: {state:6s} | {rtt_ms:7.1f} ms", end="")
        if is_open:
            if service:
                print(f" | {service}", end="")
            if banner:
                print(f" | banner: {banner}", end="")
            open_ports.append(port)
        print()

    print("\n[+] Scan complete")
    print(f"[+] Open ports found: {len(open_ports)}")
    if open_ports:
        print("[+] Open port list:", ", ".join(map(str, open_ports)))


if __name__ == "__main__":
    main()
