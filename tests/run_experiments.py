#!/usr/bin/env python3
"""Performance experiments. Builds its own Mininet network (do NOT run it inside the Mininet CLI).

  Terminal 1:  ryu-manager controller/nac_controller.py                  (dynamic)
  Terminal 2:  sudo python3 tests/run_experiments.py --mode dynamic
  then restart Ryu as:  NAC_MODE=static ryu-manager controller/nac_controller.py
               sudo python3 tests/run_experiments.py --mode static

Writes CSVs to results/perf/. Then: python3 tests/plot_results.py
"""
import argparse
import csv
import os
import sys
import time
from subprocess import PIPE

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, 'topology'))
import config as C  # noqa: E402
from topo import build  # noqa: E402
from mininet.log import setLogLevel  # noqa: E402

BENCH = os.path.join(ROOT, 'tests', 'bench_client.py')
OUT = os.path.join(ROOT, 'results', 'perf')


def flow_counts(net):
    out = net.get('s1').cmd('ovs-ofctl -O OpenFlow13 dump-flows s1')
    lines = [l for l in out.splitlines() if 'cookie=' in l]
    return len(lines), sum(1 for l in lines if 'priority=20' in l)


def write_csv(name, header, rows):
    path = os.path.join(OUT, name)
    with open(path, 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)
    print('  wrote', path)


def text(x):
    return x.decode() if isinstance(x, bytes) else x


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--mode', choices=['dynamic', 'static'], required=True)
    ap.add_argument('--repeats', type=int, default=20)
    ap.add_argument('--mb', type=int, default=20)
    args = ap.parse_args()
    dyn = args.mode == 'dynamic'
    os.makedirs(OUT, exist_ok=True)
    setLogLevel('warning')

    net = build(C.MAX_CLIENTS)
    net.start()
    net.get('svc').cmd('python3 -u %s/service/protected_service.py > /tmp/svc.log 2>&1 &' % ROOT)
    net.get('auth').cmd('python3 -u %s/auth/auth_server.py > /tmp/auth.log 2>&1 &' % ROOT)
    time.sleep(4)                                   # let the switch connect and flows install

    total, grants = flow_counts(net)
    print('baseline flows: total=%d priority-20=%d' % (total, grants))
    if (dyn and grants > 0) or (not dyn and grants == 0):
        print('ERROR: the running controller is not in %s mode. Restart Ryu correctly.' % args.mode)
        net.stop()
        sys.exit(1)

    h1 = net.get('h1')
    if dyn:
        print('E1: auth / grant / revoke latency (%d rounds)' % args.repeats)
        out = text(h1.cmd('python3 %s latency %d' % (BENCH, args.repeats)))
        rows = [l.split(',') for l in out.splitlines() if l[:1].isdigit()]
        write_csv('dynamic_latency.csv', ['round', 'auth_ms', 'grant_ms', 'revoke_ms'], rows)

    print('E2: connect latency and throughput (%d MB x3)' % args.mb)
    out = text(h1.cmd('python3 %s perf 30 %d %s' % (BENCH, args.mb, 'login' if dyn else 'noauth')))
    rows = [l.split(',') for l in out.splitlines() if l.startswith(('connect,', 'bulk,'))]
    write_csv('%s_perf.csv' % args.mode, ['type', 'value'], rows)

    print('E3/E4: concurrent users and flow table size')
    conc_rows, flow_rows = [], [['0', 'baseline', total, grants]]
    for n in (5, 10, 20):
        start = time.time() + 2
        procs = [(i, net.get('h%d' % i).popen(
            ['python3', BENCH, 'once', 'login' if dyn else 'noauth', str(start)],
            stdout=PIPE, stderr=PIPE)) for i in range(1, n + 1)]
        for i, p in procs:
            out, _ = p.communicate()
            for l in text(out).splitlines():
                parts = l.split(',')
                if len(parts) == 4:
                    conc_rows.append([n, 'h%d' % i] + parts)
        t, g = flow_counts(net)
        flow_rows.append([n, 'active', t, g])
        if dyn:                                     # end the sessions, then count again
            ps = [net.get('h%d' % i).popen(['python3', BENCH, 'logout'], stdout=PIPE, stderr=PIPE)
                  for i in range(1, n + 1)]
            for p in ps:
                p.communicate()
            time.sleep(1)
            t, g = flow_counts(net)
            flow_rows.append([n, 'after_logout', t, g])
        print('  n=%d done (flows: %d, priority-20: %d)' % (n, *flow_counts(net)))
    write_csv('%s_concurrency.csv' % args.mode,
              ['n', 'host', 'auth_ok', 'auth_ms', 'access_ok', 'access_ms'], conc_rows)
    write_csv('%s_flows.csv' % args.mode, ['n', 'stage', 'total_flows', 'priority20_flows'], flow_rows)

    os.system('pkill -f auth/auth_server.py; pkill -f service/protected_service.py')
    net.stop()
    print('Done (%s). Next: run the other mode, then python3 tests/plot_results.py' % args.mode)


if __name__ == '__main__':
    main()
