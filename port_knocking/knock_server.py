#!/usr/bin/env python3
"""Port knocking server (TCP knocks + iptables)."""

import argparse
import logging
import socket
import threading
import time
import subprocess
from collections import defaultdict
from typing import Dict, List, Optional, Tuple

DEFAULT_KNOCK_SEQUENCE = [1234, 5678, 9012]
DEFAULT_PROTECTED_PORT = 2222
DEFAULT_SEQUENCE_WINDOW = 10.0

# How long to keep the protected port open for a successful client (seconds)
DEFAULT_OPEN_TTL = 30.0


def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[logging.StreamHandler()],
    )


def _run_iptables(cmd: List[str]) -> None:
    """Run iptables command; don't crash on 'rule not found' etc."""
    try:
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        # OK for idempotent deletes, etc.
        pass


def _ensure_default_block(protected_port: int) -> None:
    """
    Make sure protected port is blocked by default.
    We DROP all inbound TCP to protected_port unless a higher-priority ACCEPT exists.
    """
    # Remove any previous DROP rule (best effort), then add it at the end.
    _run_iptables(["iptables", "-D", "INPUT", "-p", "tcp", "--dport", str(protected_port), "-j", "DROP"])
    _run_iptables(["iptables", "-A", "INPUT", "-p", "tcp", "--dport", str(protected_port), "-j", "DROP"])


def open_protected_port_for_ip(protected_port: int, src_ip: str, ttl: float) -> None:
    """
    Open the protected port for a specific source IP using iptables.
    Insert ACCEPT rule at top so it overrides the DROP.
    """
    logging.info("Opening protected port %s for %s (ttl=%.0fs)", protected_port, src_ip, ttl)

    # Insert allow rule at the top
    _run_iptables(["iptables", "-I", "INPUT", "1", "-p", "tcp", "-s", src_ip, "--dport", str(protected_port), "-j", "ACCEPT"])

    # Remove it later
    def revoke():
        time.sleep(ttl)
        logging.info("Closing protected port %s for %s", protected_port, src_ip)
        # Delete matching rule (try a few times in case duplicates)
        for _ in range(5):
            _run_iptables(["iptables", "-D", "INPUT", "-p", "tcp", "-s", src_ip, "--dport", str(protected_port), "-j", "ACCEPT"])

    threading.Thread(target=revoke, daemon=True).start()


class KnockTracker:
    """
    Tracks per-IP progress through the knock sequence.
    Enforces a window: sequence must complete within window_seconds.
    """

    def __init__(self, sequence: List[int], window_seconds: float):
        self.sequence = sequence
        self.window = window_seconds
        self.state: Dict[str, Tuple[int, float]] = {}  # ip -> (next_index, start_time)
        self.lock = threading.Lock()

    def register_knock(self, ip: str, port: int) -> bool:
        """
        Returns True if sequence completed successfully after this knock.
        """
        now = time.time()
        with self.lock:
            if ip not in self.state:
                # Start only if first knock matches
                if port == self.sequence[0]:
                    self.state[ip] = (1, now)
                    logging.info("Knock 1/%d from %s on %d", len(self.sequence), ip, port)
                else:
                    # ignore
                    pass
                return False

            idx, start = self.state[ip]

            # Window expired -> reset
            if now - start > self.window:
                logging.info("Sequence window expired for %s (reset)", ip)
                del self.state[ip]
                # Re-check if this knock can start a new sequence
                if port == self.sequence[0]:
                    self.state[ip] = (1, now)
                    logging.info("Knock 1/%d from %s on %d", len(self.sequence), ip, port)
                return False

            # Expecting sequence[idx]
            expected = self.sequence[idx]
            if port == expected:
                idx += 1
                if idx == len(self.sequence):
                    # Completed!
                    logging.info("Knock %d/%d from %s on %d (COMPLETE)", len(self.sequence), len(self.sequence), ip, port)
                    del self.state[ip]
                    return True
                self.state[ip] = (idx, start)
                logging.info("Knock %d/%d from %s on %d", idx, len(self.sequence), ip, port)
                return False

            # Wrong knock -> reset
            logging.info("Wrong knock from %s on %d (expected %d). Reset.", ip, port, expected)
            del self.state[ip]
            # If they hit the first port again, restart
            if port == self.sequence[0]:
                self.state[ip] = (1, now)
                logging.info("Knock 1/%d from %s on %d", len(self.sequence), ip, port)
            return False


def _listen_tcp(port: int, on_knock):
    """
    TCP knock listener: accept connection, grab source IP, close immediately.
    """
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(200)
    logging.info("Listening for TCP knocks on port %d", port)

    while True:
        conn, addr = srv.accept()
        ip, _ = addr
        try:
            conn.close()
        finally:
            on_knock(ip, port)


def listen_for_knocks(sequence, window_seconds, protected_port, open_ttl):
    """Listen for knock sequence and open the protected port."""
    logger = logging.getLogger("KnockServer")
    logger.info("Knock sequence: %s", sequence)
    logger.info("Protected port: %s", protected_port)
    logger.info("Sequence window: %.1fs", window_seconds)
    logger.info("Open TTL: %.1fs", open_ttl)

    _ensure_default_block(protected_port)
    logger.info("Protected port %s is blocked by default (iptables DROP)", protected_port)

    tracker = KnockTracker(sequence, window_seconds)

    def on_knock(ip: str, port: int):
        if tracker.register_knock(ip, port):
            open_protected_port_for_ip(protected_port, ip, open_ttl)

    # Start listeners (one per knock port)
    for p in sequence:
        t = threading.Thread(target=_listen_tcp, args=(p, on_knock), daemon=True)
        t.start()

    while True:
        time.sleep(5)


def parse_args():
    parser = argparse.ArgumentParser(description="Port knocking server")
    parser.add_argument(
        "--sequence",
        default=",".join(str(port) for port in DEFAULT_KNOCK_SEQUENCE),
        help="Comma-separated knock ports",
    )
    parser.add_argument(
        "--protected-port",
        type=int,
        default=DEFAULT_PROTECTED_PORT,
        help="Protected service port",
    )
    parser.add_argument(
        "--window",
        type=float,
        default=DEFAULT_SEQUENCE_WINDOW,
        help="Seconds allowed to complete the sequence",
    )
    parser.add_argument(
        "--ttl",
        type=float,
        default=DEFAULT_OPEN_TTL,
        help="Seconds to keep protected port open after success",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    setup_logging()

    try:
        sequence = [int(port) for port in args.sequence.split(",")]
    except ValueError:
        raise SystemExit("Invalid sequence. Use comma-separated integers.")

    listen_for_knocks(sequence, args.window, args.protected_port, args.ttl)


if __name__ == "__main__":
    main()
