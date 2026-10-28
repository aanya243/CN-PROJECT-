"""TCP authentication server (port 5000).

LOGIN (challenge-response, password never sent):
  S: HELLO  | C: LOGIN <user> | S: CHALLENGE <salt> <nonce> | C: sha256(sha256(salt+pw)+nonce)
  S: AUTH_OK <role> <ttl> <ports>   or   AUTH_FAIL <reason>
LOGOUT:
  S: HELLO  | C: LOGOUT | S: LOGOUT_OK   or   LOGOUT_FAIL no_session
The server keeps a session table, expires sessions, counts failed logins and asks the
SDN controller to GRANT / REVOKE / BLOCK. All events are printed (-> /tmp/auth.log).
"""
import hashlib
import hmac
import json
import os
import socket
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config as C  # noqa: E402

HOST, PORT = '0.0.0.0', int(os.environ.get('AUTH_PORT', C.AUTH_PORT))
CTRL_SOCK = os.environ.get('CTRL_SOCK', C.CTRL_SOCK)


def sha(s):
    return hashlib.sha256(s.encode()).hexdigest()


def make_user(salt, pw, role):
    return {'salt': salt, 'hash': sha(salt + pw), 'role': role}


USERS = {
    'alice': make_user('a1f3', 'alice123', 'user'),
    'bob': make_user('9c7e', 'bob123', 'user'),
    'carol': make_user('5b2d', 'carol123', 'guest'),
    'admin': make_user('e04a', 'admin123', 'admin'),
}
sessions = {}   # ip -> {'user','role','expires'}
fails = {}      # ip -> [timestamps of recent failed logins]
lock = threading.Lock()


def log(msg):
    print('%s %s' % (time.strftime('%Y-%m-%d %H:%M:%S'), msg), flush=True)


def ctrl_cmd(payload):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(3)
    try:
        s.connect(CTRL_SOCK)
        s.sendall((json.dumps(payload) + '\n').encode())
        return s.makefile('r').readline().strip()
    except Exception as e:
        return 'ERR %s' % e
    finally:
        s.close()


def register_failure(ip):
    """Count a failed login; block the host at the switch after C.MAX_FAILS within the window."""
    now = time.time()
    with lock:
        recent = [t for t in fails.get(ip, []) if now - t < C.FAIL_WINDOW] + [now]
        fails[ip] = recent
        trip = len(recent) >= C.MAX_FAILS
        if trip:
            fails[ip] = []
            sessions.pop(ip, None)
    if trip:
        ctrl_cmd({'cmd': 'BLOCK', 'ip': ip, 'ttl': C.BLOCK_SECS})
        log('BRUTEFORCE_BLOCK ip=%s for %ds' % (ip, C.BLOCK_SECS))
    return trip


def do_logout(ip, f):
    with lock:
        s = sessions.pop(ip, None)
    if not s:
        f.write('LOGOUT_FAIL no_session\n')
        return
    reply = ctrl_cmd({'cmd': 'REVOKE', 'ip': ip})
    log('LOGOUT user=%s ip=%s revoke=%s' % (s['user'], ip, reply))
    f.write('LOGOUT_OK\n' if reply == 'OK' else 'LOGOUT_FAIL controller_error\n')


def do_login(ip, name, f):
    user = USERS.get(name)
    nonce = os.urandom(8).hex()
    f.write('CHALLENGE %s %s\n' % (user['salt'] if user else '0000', nonce)); f.flush()
    resp = f.readline().strip()
    if user and hmac.compare_digest(resp, sha(user['hash'] + nonce)):
        role = user['role']
        ports, ttl = C.ROLE_PORTS[role], C.ROLE_TTL[role]
        reply = ctrl_cmd({'cmd': 'GRANT', 'ip': ip, 'ports': ports, 'ttl': ttl})
        if reply == 'OK':
            with lock:
                sessions[ip] = {'user': name, 'role': role, 'expires': time.time() + ttl}
                fails.pop(ip, None)
            log('LOGIN_OK user=%s role=%s ip=%s ports=%s ttl=%d' % (name, role, ip, ports, ttl))
            f.write('AUTH_OK %s %d %s\n' % (role, ttl, ','.join(map(str, ports))))
        else:
            log('GRANT_FAILED ip=%s (%s)' % (ip, reply))
            f.write('AUTH_FAIL controller_error\n')
    else:
        log('LOGIN_FAIL user=%s ip=%s' % (name, ip))
        blocked = register_failure(ip)
        f.write('AUTH_FAIL blocked_%ds\n' % C.BLOCK_SECS if blocked else 'AUTH_FAIL bad_credentials\n')


def handle(conn, addr):
    ip = addr[0]
    f = conn.makefile('rw')
    try:
        f.write('HELLO\n'); f.flush()
        parts = f.readline().split()
        if parts == ['LOGOUT']:
            do_logout(ip, f)
        elif len(parts) == 2 and parts[0] == 'LOGIN':
            do_login(ip, parts[1], f)
        else:
            f.write('AUTH_FAIL bad_request\n')
        f.flush()
    except Exception as e:
        log('error ip=%s: %s' % (ip, e))
    finally:
        conn.close()


def reaper():
    """Expire sessions: tell the controller to REVOKE (the flows' hard_timeout is only a backup)."""
    while True:
        time.sleep(1)
        now = time.time()
        with lock:
            expired = [(ip, s) for ip, s in sessions.items() if s['expires'] <= now]
            for ip, _ in expired:
                sessions.pop(ip, None)
        for ip, s in expired:
            reply = ctrl_cmd({'cmd': 'REVOKE', 'ip': ip})
            log('SESSION_EXPIRED user=%s ip=%s revoke=%s' % (s['user'], ip, reply))


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(64)
    threading.Thread(target=reaper, daemon=True).start()
    log('auth server listening on %s:%d' % (HOST, PORT))
    while True:
        c, a = srv.accept()
        c.settimeout(10)
        threading.Thread(target=handle, args=(c, a), daemon=True).start()


if __name__ == '__main__':
    main()
