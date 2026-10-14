#!/usr/bin/env python3
"""
relay.py
--------
A dumb TCP relay: pairs up the first two clients that connect and pipes
raw bytes between them in both directions, blindly. It never parses,
decrypts, or understands anything it forwards.

Why this is safe to run on a VPS you don't fully trust with your message
CONTENT (though you should still trust it with metadata): your chat
program's own handshake and AES-GCM encryption happen between the two
real peers, end-to-end. The relay only ever sees ciphertext. It is a
NAT/firewall workaround, not a trusted third party in your security
model -- say so explicitly in your threat model and report.

What it CAN see (be upfront about this): connection timing, message
sizes/frequency, and the fact that two specific IPs are talking to each
other. That's metadata leakage, not a content break.

Usage on the VPS:
    python3 relay.py --port 9000

Then both peers connect to the relay instead of to each other:
    python main.py --connect <relay_public_ip>:9000 --name alice --keyfile alice.pem
    python main.py --connect <relay_public_ip>:9000 --name bob   --keyfile bob.pem

No third-party libraries needed -- this file only uses the standard
library, so there's nothing to `pip install` on the server.
"""

import argparse
import socket
import threading


def pipe(src: socket.socket, dst: socket.socket, label: str) -> None:
    """Forward raw bytes from src to dst until either side closes."""
    try:
        while True:
            data = src.recv(4096)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def bridge_pair(conn_a: socket.socket, conn_b: socket.socket) -> None:
    """Start two threads that copy bytes in each direction, then clean up."""
    t1 = threading.Thread(target=pipe, args=(conn_a, conn_b, "a->b"), daemon=True)
    t2 = threading.Thread(target=pipe, args=(conn_b, conn_a, "b->a"), daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    conn_a.close()
    conn_b.close()
    print("[relay] Pair disconnected.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Dumb two-peer TCP relay")
    parser.add_argument("--host", default="0.0.0.0", help="interface to listen on")
    parser.add_argument("--port", type=int, required=True, help="port to listen on")
    args = parser.parse_args()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((args.host, args.port))
    server.listen()
    print(f"[relay] Listening on {args.host}:{args.port}. "
          f"Waiting for pairs of peers to connect...")

    while True:
        print("[relay] Waiting for peer 1 of a new pair...")
        conn_a, addr_a = server.accept()
        print(f"[relay] Peer 1 connected from {addr_a}")

        print("[relay] Waiting for peer 2 of this pair...")
        conn_b, addr_b = server.accept()
        print(f"[relay] Peer 2 connected from {addr_b}. Bridging.")

        # Each pair gets its own bridging thread so the relay can
        # immediately go back to accepting the NEXT pair, if you want to
        # support more than one conversation at a time.
        threading.Thread(target=bridge_pair, args=(conn_a, conn_b), daemon=True).start()


if __name__ == "__main__":
    main()
