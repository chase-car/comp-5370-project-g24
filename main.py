#!/usr/bin/env python3
"""
Simple terminal-based peer-to-peer messaging.

Every instance is both a server (listens for incoming peers) and a client
(can connect to other peers). Messages are newline-delimited JSON over TCP.

Usage:
    Terminal 1:  python p2p_chat.py --name Alice --port 5000
    Terminal 2:  python p2p_chat.py --name Bob   --port 5001 --connect 127.0.0.1:5000

Commands (inside the chat):
    /connect <host> <port>   connect to another peer
    /peers                   list connected peers
    /quit                    exit
Anything else is sent as a message to all connected peers.
"""

import argparse
import json
import socket
import threading


class Peer:
    def __init__(self, name: str, host: str, port: int):
        self.name = name
        self.host = host
        self.port = port
        self.peers = {}                 # socket -> peer name
        self.lock = threading.Lock()    # protects self.peers
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
                conn, addr = self.server.accept()
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn, addr), daemon=True).start()

    def connect(self, host: str, port: int) -> None:
        try:
            conn = socket.create_connection((host, port), timeout=5)
            conn.settimeout(None)
        except OSError as e:
            self.show(f"* Could not connect to {host}:{port} ({e})")
            return
        threading.Thread(target=self._handle, args=(conn, (host, port)), daemon=True).start()

    @staticmethod
    def _send(sock: socket.socket, obj: dict) -> None:
        sock.sendall((json.dumps(obj) + "\n").encode("utf-8"))

    def _handle(self, conn: socket.socket, addr) -> None:
        """Run for each connection: handshake, then read messages until closed."""
        peer_name = None
        try:
            self._send(conn, {"type": "hello", "name": self.name})
            for line in conn.makefile("r", encoding="utf-8"):
                try:
                    msg = json.loads(line)
                except json.JSONDecodeError:
                    continue

                if msg.get("type") == "hello":
                    peer_name = str(msg.get("name", f"{addr[0]}:{addr[1]}"))
                    with self.lock:
                        self.peers[conn] = peer_name
                    self.show(f"* {peer_name} connected")
                elif msg.get("type") == "msg":
                    self.show(f"[{msg.get('name', '?')}] {msg.get('text', '')}")
        except OSError:
            pass
        finally:
            with self.lock:
                self.peers.pop(conn, None)
            try:
                conn.close()
            except OSError:
                pass
            if peer_name and self.running:
                self.show(f"* {peer_name} disconnected")

    def broadcast(self, text: str) -> None:
        with self.lock:
            sockets = list(self.peers)
        if not sockets:
            self.show("* No peers connected. Use /connect <host> <port>")
            return
        for s in sockets:
            try:
                self._send(s, {"type": "msg", "name": self.name, "text": text})
            except OSError:
                pass  # the handler thread will clean up the dead connection

    def shutdown(self) -> None:
        self.running = False
        with self.lock:
            sockets = list(self.peers)
        for s in sockets:
            try:
                s.close()
            except OSError:
                pass
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
                        names = list(self.peers.values())
                    self.show("* Peers: " + (", ".join(names) if names else "(none)"))
                elif cmd == "/connect" and len(parts) == 3 and parts[2].isdigit():
                    self.connect(parts[1], int(parts[2]))
                else:
                    self.show("* Unknown command. Try /connect <host> <port>, /peers, /quit")
            else:
                self.broadcast(line)

        self.shutdown()


def main() -> None:
    parser = argparse.ArgumentParser(description="Simple terminal P2P chat")
    parser.add_argument("--name", required=True, help="your display name")
    parser.add_argument("--host", default="0.0.0.0", help="interface to listen on")
    parser.add_argument("--port", type=int, required=True, help="port to listen on")
    parser.add_argument("--connect", metavar="HOST:PORT", help="peer to connect to at startup")
    args = parser.parse_args()

    peer = Peer(args.name, args.host, args.port)
    peer.start_server()

    if args.connect:
        host, _, port = args.connect.rpartition(":")
        peer.connect(host or "127.0.0.1", int(port))

    peer.run()


if __name__ == "__main__":
    main()