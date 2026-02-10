#!/usr/bin/env python3
"""SSH-like honeypot (fake SSH service)"""

import os
import socket
import threading
import time
from dataclasses import dataclass
from typing import Optional, Tuple

from logger import create_logger

LOG_PATH = "/app/logs/honeypot.log"
LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 22

SSH_BANNER = b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.11\r\n"
MAX_LINE = 1024
SOCKET_TIMEOUT = 60


@dataclass
class SessionInfo:
    src_ip: str
    src_port: int
    start_ts: float
    bytes_received: int = 0
    username: Optional[str] = None
    password: Optional[str] = None
    commands: str = ""


def _recv_line(conn: socket.socket, info: SessionInfo, prompt_timeout: int = SOCKET_TIMEOUT) -> Optional[str]:
    """Receive a line (ending in \\n) with a size limit."""
    conn.settimeout(prompt_timeout)
    data = b""
    try:
        while len(data) < MAX_LINE:
            chunk = conn.recv(1)
            if not chunk:
                break
            info.bytes_received += len(chunk)
            data += chunk
            if chunk in (b"\n",):
                break
    except socket.timeout:
        return None

    if not data:
        return None
    # Normalize
    return data.replace(b"\r", b"").decode(errors="replace").strip("\n")


def _send(conn: socket.socket, b: bytes) -> None:
    try:
        conn.sendall(b)
    except OSError:
        pass


def handle_client(conn: socket.socket, addr: Tuple[str, int], logger):
    info = SessionInfo(src_ip=addr[0], src_port=addr[1], start_ts=time.time())

    # 1) Send realistic SSH banner (helps it look legit)
    _send(conn, SSH_BANNER)

    # Many tools will send their own banner line back; read a line if present
    client_banner = _recv_line(conn, info, prompt_timeout=5)
    if client_banner:
        logger.info("Connection from %s:%d | client_banner=%r", info.src_ip, info.src_port, client_banner)
    else:
        logger.info("Connection from %s:%d | no client banner", info.src_ip, info.src_port)

    # 2) Fake "login" flow (not real SSH, but captures creds from humans/scripts)
    _send(conn, b"login as: ")
    user = _recv_line(conn, info)
    if user is None:
        _finish(conn, info, logger, reason="no_username")
        return
    info.username = user.strip()

    _send(conn, b"password: ")
    pw = _recv_line(conn, info)
    if pw is None:
        _finish(conn, info, logger, reason="no_password")
        return
    info.password = pw.strip()

    logger.info(
        "Auth attempt from %s:%d | username=%r password=%r",
        info.src_ip, info.src_port, info.username, info.password
    )

    # 3) Always fail auth (but do it realistically)
    _send(conn, b"\r\nPermission denied, please try again.\r\n")
    # Give them another chance to look real
    _send(conn, b"login as: ")
    user2 = _recv_line(conn, info)
    if user2 is None:
        _finish(conn, info, logger, reason="disconnect_after_fail1")
        return
    _send(conn, b"password: ")
    pw2 = _recv_line(conn, info)
    if pw2 is None:
        _finish(conn, info, logger, reason="disconnect_after_fail1_pw")
        return

    logger.info(
        "Auth attempt (2) from %s:%d | username=%r password=%r",
        info.src_ip, info.src_port, user2.strip(), pw2.strip()
    )

    _send(conn, b"\r\nPermission denied (publickey,password).\r\n")
    # Some bots will still send garbage/commands; read a little
    _send(conn, b"Connection closed by remote host.\r\n")
    _finish(conn, info, logger, reason="auth_failed")
    return


def _finish(conn: socket.socket, info: SessionInfo, logger, reason: str):
    dur = time.time() - info.start_ts
    logger.info(
        "Session end %s:%d | duration=%.2fs bytes_received=%d reason=%s",
        info.src_ip, info.src_port, dur, info.bytes_received, reason
    )
    try:
        conn.close()
    except OSError:
        pass


def run_honeypot():
    logger = create_logger(log_path=LOG_PATH)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((LISTEN_HOST, LISTEN_PORT))
    s.listen(200)

    logger.info("Honeypot listening on %s:%d (fake SSH)", LISTEN_HOST, LISTEN_PORT)

    while True:
        conn, addr = s.accept()
        t = threading.Thread(target=handle_client, args=(conn, addr, logger), daemon=True)
        t.start()


if __name__ == "__main__":
    os.makedirs("/app/logs", exist_ok=True)
    run_honeypot()
