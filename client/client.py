"""Usage (run on a Mininet host, from the repo root):
  python3 client/client.py login <user> <password>
  python3 client/client.py access [port]      # default 8080 (public 8081, data 8080, admin 9090)
  python3 client/client.py logout
"""
import hashlib
import os
import socket
import sys
import time

AUTH = (os.environ.get('AUTH_HOST', '10.0.0.100'), int(os.environ.get('AUTH_PORT', 5000)))
SVC_HOST = os.environ.get('SVC_HOST', '10.0.0.200')


def sha(s):
    return hashlib.sha256(s.encode()).hexdigest()


def talk_auth(first_line, pw=None):
    """Open a connection to the auth server, send first_line, return the final reply line."""
    t0 = time.time()
    try:
        s = socket.create_connection(AUTH, timeout=5)
        f = s.makefile('rw')
        f.readline()                                    # HELLO
        f.write(first_line + '\n'); f.flush()
        reply = f.readline().strip()
        if reply.startswith('CHALLENGE'):
            _, salt, nonce = reply.split()
            f.write(sha(sha(salt + pw) + nonce) + '\n'); f.flush()
            reply = f.readline().strip()
        s.close()
    except OSError as e:
        print('AUTH SERVER UNREACHABLE (%s)' % e)
        return None
    print('%s (%.0f ms)' % (reply, (time.time() - t0) * 1000))
    return reply


def access(port):
    try:
        s = socket.create_connection((SVC_HOST, port), timeout=3)
        print('ACCESS GRANTED ->', s.recv(200).decode().strip())
        s.close()
        return True
    except OSError as e:
        print('ACCESS BLOCKED on port %d (%s)' % (port, e))
        return False


if __name__ == '__main__':
    cmd = sys.argv[1] if len(sys.argv) > 1 else 'access'
    if cmd == 'login':
        talk_auth('LOGIN %s' % sys.argv[2], sys.argv[3])
    elif cmd == 'logout':
        talk_auth('LOGOUT')
    else:
        access(int(sys.argv[2]) if len(sys.argv) > 2 else 8080)
