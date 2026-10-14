"""
main.py
-------
Command-line entry point.

Usage:
    # Peer A (listens for a connection):
    python main.py --listen 5000 --name alice --keyfile alice_identity.pem

    # Peer B (connects to peer A):
    python main.py --connect 127.0.0.1:5000 --name bob --keyfile bob_identity.pem

Both sides can type and will see incoming messages interleaved.
Type /quit to exit.
"""

import argparse
import sys
import threading

from network import Connection
from protocol import perform_handshake, HandshakeFailed, SecureChannel
from keystore import load_identity, TrustStore

TRUST_STORE_FILE = "trusted_keys.json"


def reader_thread(channel: SecureChannel, stop_event: threading.Event):
    """Continuously receive and print messages until the peer disconnects."""
    while not stop_event.is_set():
        try:
            plaintext = channel.recv_message()
        except ValueError as e:
            # Authentication / replay failure -- do NOT crash, just warn
            print(f"\n[!] Dropped a message: {e}")
            continue
        except (ConnectionError, OSError):
            print("\n[network] Connection closed by peer.")
            stop_event.set()
            break
        print(f"\rpeer> {plaintext}\nyou> ", end="", flush=True)


def writer_loop(channel: SecureChannel, stop_event: threading.Event):
    """Read from stdin and send encrypted messages until /quit."""
    while not stop_event.is_set():
        try:
            line = input("you> ")
        except (EOFError, KeyboardInterrupt):
            break
        if line.strip() == "/quit":
            break
        if line == "":
            continue
        try:
            channel.send_message(line)
        except (ConnectionError, OSError):
            print("[network] Could not send -- connection closed.")
            break
    stop_event.set()


def main():
    parser = argparse.ArgumentParser(description="Secure P2P terminal chat")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--listen", type=int, metavar="PORT",
                       help="Listen for an incoming connection on this port")
    mode.add_argument("--connect", type=str, metavar="HOST:PORT",
                       help="Connect out to a peer at host:port")
    parser.add_argument("--name", required=True, help="Your display name")
    parser.add_argument("--keyfile", required=True,
                         help="Path to your long-term identity key (created if missing)")
    args = parser.parse_args()

    identity_private_key = load_identity(args.keyfile)
    trust_store = TrustStore(TRUST_STORE_FILE)

    if args.listen is not None:
        conn = Connection.listen_and_accept("0.0.0.0", args.listen)
    else:
        host, port_str = args.connect.split(":")
        conn = Connection.connect_to(host, int(port_str))

    try:
        channel = perform_handshake(conn, identity_private_key, args.name, trust_store)
    except HandshakeFailed as e:
        print(f"[!] Handshake failed: {e}")
        conn.close()
        sys.exit(1)

    stop_event = threading.Event()
    t = threading.Thread(target=reader_thread, args=(channel, stop_event), daemon=True)
    t.start()

    print("Connected and secured. Type /quit to exit.\n")
    writer_loop(channel, stop_event)
    conn.close()
    print("Disconnected.")


if __name__ == "__main__":
    main()
