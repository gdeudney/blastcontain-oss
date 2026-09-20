"""Isolated test listener. Fixed protocol, no commands, no data persistence."""
import socket

with socket.socket() as listener:
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(('0.0.0.0', 18081))  # nosec B104 — internal Podman network only; no host port
    listener.listen(8)
    while True:
        connection, _ = listener.accept()
        with connection:
            connection.settimeout(2)
            try:
                if connection.recv(64) == b'VERIFY_SANDBOX_PROBE\n':
                    connection.sendall(b'VERIFY_SANDBOX_CANARY\n')
            except OSError:
                pass
