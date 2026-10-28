"""Protected TCP services on one host: public (8081), data (8080), admin (9090).
Only hosts the controller has granted can reach them. Send "BULK <MB>" after the greeting
to receive that many megabytes (used for throughput tests)."""
import os
import socket
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config as C  # noqa: E402

NAMES = {C.PORT_PUBLIC: 'public', C.PORT_DATA: 'data', C.PORT_ADMIN: 'admin'}


def handle(conn, addr, port):
    try:
        conn.sendall(('SERVICE %s (port %d): reached by %s\n' % (NAMES[port], port, addr[0])).encode())
        conn.settimeout(0.5)
        try:
            cmd = conn.recv(64).decode().split()
        except OSError:
            cmd = []
        if len(cmd) == 2 and cmd[0] == 'BULK':
            chunk = b'x' * 65536
            for _ in range(int(cmd[1]) * 16):     # 16 x 64 KB = 1 MB
                conn.sendall(chunk)
    except OSError:
        pass
    finally:
        conn.close()


def serve(port):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('0.0.0.0', port))
    srv.listen(64)
    while True:
        c, a = srv.accept()
        threading.Thread(target=handle, args=(c, a, port), daemon=True).start()


if __name__ == '__main__':
    for p in NAMES:
        threading.Thread(target=serve, args=(p,), daemon=True).start()
    print('protected services on ports %s' % list(NAMES), flush=True)
    threading.Event().wait()
