#!/usr/bin/env python3
"""
Secure version of the group's p2p_chat.py.

Keeps the same shape as the original (every instance is both a server and
a client, broadcast-style messaging, /connect /peers /quit commands) but
every connection now gets its OWN authenticated handshake and session key
before any chat message is allowed to flow.

Why per-connection, not one shared key for everyone:
  - In a broadcast mesh you can't assume all peers trust each other, or
    that a key safe to share with peer A is safe to share with peer B.
  - Each pairwise link gets independent confidentiality, integrity, and
    authentication, exactly like the two-peer version -- it's just run
    once per socket instead of once per program.

Usage:
    Terminal 1:  python p2p_chat_secure.py --name Alice --port 5000 \\
                     --keyfile alice_identity.pem
    Terminal 2:  python p2p_chat_secure.py --name Bob   --port 5001 \\
                     --connect 127.0.0.1:5000 --keyfile bob_identity.pem

Commands (inside the chat):
    /connect <host> <port>   connect to another peer (runs a new handshake)
    /peers                   list connected, authenticated peers
    /quit                    exit
Anything else is broadcast, encrypted individually to every connected peer.
"""

import argparse
import socket
import threading

from network import Connection
from protocol import perform_handshake, HandshakeFailed, SecureChannel
from keystore import load_identity, TrustStore


class Peer:
    def __init__(self, name: str, host: str, port: int, identity, trust_store: TrustStore):
        self.name = name
        self.host = host
        self.port = port
        self.identity = identity
        self.trust_store = trust_store

        self.channels = {}               # socket -> SecureChannel
        self.lock = threading.Lock()     # protects self.channels
        self.running = True
        self.server = None

    # ---------- output ----------
    def show(self, text: str) -> None:
        """Print a line without mangling the input prompt."""
        print(f"\r{text}\n{self.name}> ", end="", flush=True)

    # ---------- networking ----------
    def start_server(self) -> None:
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((self.host, self.port))
        self.server.listen()
        threading.Thread(target=self._accept_loop, daemon=True).start()

    def _accept_loop(self) -> None:
        while self.running:
            try:
                sock, addr = self.server.accept()
            except OSError:
                break
            threading.Thread(target=self._handle, args=(sock, addr), daemon=True).start()

    def connect(self, host: str, port: int) -> None:
        try:
            sock = socket.create_connection((host, port), timeout=5)
            sock.settimeout(None)
        except OSError as e:
            self.show(f"* Could not connect to {host}:{port} ({e})")
            return
        threading.Thread(target=self._handle, args=(sock, (host, port)), daemon=True).start()

    def _handle(self, sock: socket.socket, addr) -> None:
        """
        Run for each connection: handshake first (auth + key exchange),
        then read encrypted messages until the peer disconnects.
        Nothing from this socket is trusted or printed until the
        handshake succeeds.
        """
        conn = Connection(sock)

        try:
            # interactive=False: this handshake runs in a background thread
            # while the main thread may simultaneously be reading stdin for
            # chat input, so it must never call input() itself (see
            # keystore.TrustStore.auto_verify for why).
            channel = perform_handshake(conn, self.identity, self.name,
                                         self.trust_store, interactive=False)
        except HandshakeFailed as e:
            self.show(f"* Handshake with {addr} FAILED: {e}")
            conn.close()
            return
        except (ConnectionError, OSError) as e:
            self.show(f"* Connection to {addr} lost during handshake: {e}")
            return

        with self.lock:
            self.channels[sock] = channel
        self.show(f"* {channel.peer_name} connected (authenticated)")

        try:
            while self.running:
                try:
                    plaintext = channel.recv_message()
                except ValueError as e:
                    # Authentication or replay failure -- warn, don't crash,
                    # don't trust the content, keep the connection open.
                    self.show(f"* [!] Dropped a bad message from {channel.peer_name}: {e}")
                    continue
                self.show(f"[{channel.peer_name}] {plaintext}")
        except (ConnectionError, OSError):
            pass
        finally:
            with self.lock:
                self.channels.pop(sock, None)
            conn.close()
            if self.running:
                self.show(f"* {channel.peer_name} disconnected")

    def broadcast(self, text: str) -> None:
        with self.lock:
            channels = list(self.channels.values())
        if not channels:
            self.show("* No peers connected. Use /connect <host> <port>")
            return
        for channel in channels:
            try:
                channel.send_message(text)
            except (ConnectionError, OSError):
                pass  # the handler thread will notice and clean up

    def shutdown(self) -> None:
        self.running = False
        with self.lock:
            channels = list(self.channels.values())
        for channel in channels:
            channel.conn.close()
        if self.server:
            self.server.close()

    # ---------- UI loop ----------
    def run(self) -> None:
        print(f"Listening on {self.host}:{self.port} as '{self.name}'. Type /quit to exit.")
        while True:
            try:
                line = input(f"{self.name}> ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                break
            if not line:
                continue

            if line.startswith("/"):
                parts = line.split()
                cmd = parts[0].lower()
                if cmd == "/quit":
                    break
                elif cmd == "/peers":
                    with self.lock:
                        names = [c.peer_name for c in self.channels.values()]
                    self.show("* Peers: " + (", ".join(names) if names else "(none)"))
                elif cmd == "/connect" and len(parts) == 3 and parts[2].isdigit():
                    self.connect(parts[1], int(parts[2]))
                else:
                    self.show("* Unknown command. Try /connect <host> <port>, /peers, /quit")
            else:
                self.broadcast(line)

        self.shutdown()


def main() -> None:
    parser = argparse.ArgumentParser(description="Secure terminal P2P chat")
    parser.add_argument("--name", required=True, help="your display name")
    parser.add_argument("--host", default="0.0.0.0", help="interface to listen on")
    parser.add_argument("--port", type=int, required=True, help="port to listen on")
    parser.add_argument("--connect", metavar="HOST:PORT", help="peer to connect to at startup")
    parser.add_argument("--keyfile", required=True,
                         help="your long-term identity key file (created if missing)")
    parser.add_argument("--trust-file", default=None,
                         help="trusted-keys file (default: <name>_trusted.json)")
    args = parser.parse_args()

    identity = load_identity(args.keyfile)
    trust_file = args.trust_file or f"{args.name.lower()}_trusted.json"
    trust_store = TrustStore(trust_file)

    peer = Peer(args.name, args.host, args.port, identity, trust_store)
    peer.start_server()

    if args.connect:
        host, _, port = args.connect.rpartition(":")
        peer.connect(host or "127.0.0.1", int(port))

    peer.run()


if __name__ == "__main__":
    main()
