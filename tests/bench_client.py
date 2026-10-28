"""Helper that runs ON a Mininet host (called by run_experiments.py; not meant for manual use).
  latency <N>                     N rounds of login -> grant -> logout -> revoke timings (CSV rows)
  perf <N> <MB> <login|noauth>    N connect timings + 3 bulk transfers of MB megabytes
  once <login|noauth> [start_ts]  optional login + one access, after waiting until start_ts
  logout                          end this host's session
"""
import hashlib
import os
import socket
import sys
import time

AUTH = (os.environ.get('AUTH_HOST', '10.0.0.100'), int(os.environ.get('AUTH_PORT', 5000)))
SVC = os.environ.get('SVC_HOST', '10.0.0.200')


def sha(s):
    return hashlib.sha256(s.encode()).hexdigest()


def login(user='alice', pw='alice123'):
    t0 = time.time()
    try:
        s = socket.create_connection(AUTH, timeout=8)
        f = s.makefile('rw')
        f.readline()
        f.write('LOGIN %s\n' % user); f.flush()
        _, salt, nonce = f.readline().split()
        f.write(sha(sha(salt + pw) + nonce) + '\n'); f.flush()
        ok = f.readline().startswith('AUTH_OK')
        s.close()
    except Exception:
        ok = False
    return ok, (time.time() - t0) * 1000


def logout():
    try:
        s = socket.create_connection(AUTH, timeout=8)
        f = s.makefile('rw')
        f.readline()
        f.write('LOGOUT\n'); f.flush()
        r = f.readline().startswith('LOGOUT_OK')
        s.close()
        return r
    except Exception:
        return False


def try_access(port=8080, timeout=0.3):
    t0 = time.time()
    try:
        s = socket.create_connection((SVC, port), timeout=timeout)
        s.recv(200)
        s.close()
        return True, (time.time() - t0) * 1000
    except OSError:
        return False, (time.time() - t0) * 1000


def bulk(mb):
    s = socket.create_connection((SVC, 8080), timeout=8)
    s.recv(200)                                   # greeting
    t0 = time.time()
    s.sendall(('BULK %d\n' % mb).encode())
    got, target = 0, mb * 1024 * 1024
    while got < target:
        d = s.recv(65536)
        if not d:
            break
        got += len(d)
    el = time.time() - t0
    s.close()
    return got * 8 / el / 1e6


def main():
    mode = sys.argv[1]
    nan = float('nan')
    if mode == 'latency':
        for i in range(int(sys.argv[2])):
            t0 = time.time()
            ok, auth_ms = login()
            grant_ms = revoke_ms = nan
            if ok:
                while time.time() - t0 < 5:                      # until access works
                    a, _ = try_access(timeout=1)
                    if a:
                        grant_ms = (time.time() - t0) * 1000
                        break
                t1 = time.time()
                logout()
                while time.time() - t1 < 3:                      # until access is blocked
                    ts = time.time()
                    a, _ = try_access(timeout=0.3)
                    if not a:
                        revoke_ms = (ts - t1) * 1000
                        break
            print('%d,%.1f,%.1f,%.1f' % (i, auth_ms if ok else nan, grant_ms, revoke_ms), flush=True)
            time.sleep(0.3)
    elif mode == 'perf':
        n, mb, how = int(sys.argv[2]), int(sys.argv[3]), sys.argv[4]
        if how == 'login':
            login()
        for _ in range(n):
            ok, ms = try_access(timeout=3)
            if ok:
                print('connect,%.2f' % ms)
        for _ in range(3):
            try:
                print('bulk,%.1f' % bulk(mb))
            except Exception:
                pass
        if how == 'login':
            logout()
    elif mode == 'once':
        how = sys.argv[2]
        if len(sys.argv) > 3:
            time.sleep(max(0, float(sys.argv[3]) - time.time()))
        auth_ok, auth_ms = (True, 0.0)
        if how == 'login':
            auth_ok, auth_ms = login()
        ok, ms = try_access(timeout=3)
        print('%d,%.1f,%d,%.1f' % (auth_ok, auth_ms, ok, ms))
    elif mode == 'logout':
        print('logout', logout())


if __name__ == '__main__':
    main()
