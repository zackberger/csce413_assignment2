#!/usr/bin/env python3
import socket

HOST = "0.0.0.0"
PORT = 2222

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(50)
    print(f"[protected] listening on {HOST}:{PORT}")

    while True:
        conn, addr = s.accept()
        ip, _ = addr
        try:
            conn.sendall(b"Protected service reached. Port knocking worked.\n")
            print(f"[protected] connection from {ip}")
        finally:
            conn.close()

if __name__ == "__main__":
    main()
