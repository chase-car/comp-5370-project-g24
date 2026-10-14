"""
network.py
----------
Plain TCP transport with length-prefixed framing. This layer knows
NOTHING about encryption -- it just moves bytes reliably and splits the
stream back into discrete messages. Keeping it separate from crypto.py
makes both easier to test and reason about.

Frame format on the wire:
    [ 4 bytes: big-endian length N ] [ N bytes: payload ]
"""

import socket
import struct

LENGTH_PREFIX_SIZE = 4
MAX_MESSAGE_SIZE = 10 * 1024 * 1024  # 10 MB safety cap


class Connection:
    """Wraps a connected TCP socket with framed send/recv."""

    def __init__(self, sock: socket.socket):
        self.sock = sock

    @classmethod
    def listen_and_accept(cls, host: str, port: int) -> "Connection":
        """Act as the 'server' side: bind, listen, accept one peer."""
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((host, port))
        listener.listen(1)
        print(f"[network] Listening on {host}:{port} ... waiting for peer")
        conn, addr = listener.accept()
        print(f"[network] Connected by {addr}")
        listener.close()
        return cls(conn)

    @classmethod
    def connect_to(cls, host: str, port: int) -> "Connection":
        """Act as the 'client' side: connect out to a listening peer."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))
        print(f"[network] Connected to {host}:{port}")
        return cls(sock)

    def send_frame(self, payload: bytes) -> None:
        if len(payload) > MAX_MESSAGE_SIZE:
            raise ValueError("Message too large")
        header = struct.pack(">I", len(payload))
        self.sock.sendall(header + payload)

    def _recv_exact(self, n: int) -> bytes:
        """Read exactly n bytes or raise ConnectionError if peer closes early."""
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("Peer closed the connection")
            buf += chunk
        return buf

    def recv_frame(self) -> bytes:
        header = self._recv_exact(LENGTH_PREFIX_SIZE)
        (length,) = struct.unpack(">I", header)
        if length > MAX_MESSAGE_SIZE:
            raise ValueError("Incoming message exceeds size limit")
        return self._recv_exact(length)

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass
