#!/usr/bin/env python3
"""SOCKS5 server that accepts CONNECT and does not dial the destination.

An emulator client can only complete the TCP handshake when ShieldProxy
handed the flow to this process.
"""
import socket
import sys
import threading


def recvn(conn, size):
    buf = b""
    while len(buf) < size:
        chunk = conn.recv(size - len(buf))
        if not chunk:
            raise EOFError("closed")
        buf += chunk
    return buf


def handle(conn, log_path):
    try:
        ver_n = recvn(conn, 2)
        recvn(conn, ver_n[1])
        conn.sendall(b"\x05\x00")
        head = recvn(conn, 4)
        atyp = head[3]
        if atyp == 1:
            host = socket.inet_ntoa(recvn(conn, 4))
        elif atyp == 3:
            length = recvn(conn, 1)[0]
            host = recvn(conn, length).decode("utf-8", "replace")
        elif atyp == 4:
            host = socket.inet_ntop(socket.AF_INET6, recvn(conn, 16))
        else:
            return
        port = int.from_bytes(recvn(conn, 2), "big")
        with open(log_path, "a", encoding="utf-8") as log:
            log.write(f"CONNECT {host} {port}\n")
        conn.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        conn.settimeout(8)
        try:
            while conn.recv(4096):
                pass
        except OSError:
            pass
    except Exception as exc:
        with open(log_path, "a", encoding="utf-8") as log:
            log.write(f"ERROR {exc}\n")
    finally:
        conn.close()


def main():
    port = int(sys.argv[1])
    log_path = sys.argv[2]
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", port))
    server.listen(32)
    while True:
        client, _ = server.accept()
        threading.Thread(target=handle, args=(client, log_path), daemon=True).start()


if __name__ == "__main__":
    main()
