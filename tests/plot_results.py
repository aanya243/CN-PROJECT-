#!/usr/bin/env python3
"""Reads results/perf/*.csv, writes graphs (PNG) and results/perf/summary.md.
Run with the system python3 (sudo apt install -y python3-matplotlib), not inside the Ryu venv."""
import csv
import math
import os
import statistics as st

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
D = os.environ.get('PERF_DIR', os.path.join(ROOT, 'results', 'perf'))


def read(name):
    p = os.path.join(D, name)
    return list(csv.DictReader(open(p))) if os.path.exists(p) else []


def fl(x):
    try:
        return float(x)
    except (TypeError, ValueError):
        return math.nan


def vals(rows, key):
    return [v for v in (fl(r[key]) for r in rows) if not math.isnan(v)]


def mean(xs):
    return st.mean(xs) if xs else math.nan


def med(xs):
    return st.median(xs) if xs else math.nan


def sd(xs):
    return st.stdev(xs) if len(xs) > 1 else 0.0


def save(fig, name):
    fig.tight_layout()
    fig.savefig(os.path.join(D, name), dpi=150)
    plt.close(fig)
    print('wrote', name)


summary = ['# Performance summary', '']

# --- 1. dynamic latencies ---
lat = read('dynamic_latency.csv')
if lat:
    keys = [('auth_ms', 'Authentication latency'), ('grant_ms', 'Grant time (login to access)'),
            ('revoke_ms', 'Revoke time (logout to blocked)')]
    means = [med(vals(lat, k)) for k, _ in keys]          # median: robust to the rare 1 s TCP SYN retransmit
    sds = [sd([x for x in vals(lat, k) if x < 500]) for k, _ in keys]
    fig, ax = plt.subplots(figsize=(6, 4))
    ax.bar([n for _, n in keys], means, yerr=sds, capsize=4, color=['#4c78a8', '#59a14f', '#e15759'])
    ax.set_ylabel('milliseconds (median)'); ax.set_title('Dynamic SDN: latency of authentication events')
    plt.setp(ax.get_xticklabels(), rotation=12, ha='right')
    save(fig, 'fig1_event_latency.png')
    summary += ['## Event latency (dynamic, %d rounds)' % len(lat), '',
                '| Metric | Median (ms) | Mean (ms) | Std | Min | Max | Rounds > 500 ms |', '|---|---|---|---|---|---|---|']
    for (k, n) in keys:
        v = vals(lat, k)
        summary.append('| %s | %.1f | %.1f | %.1f | %.1f | %.1f | %d |' % (
            n, med(v), mean(v), sd(v), min(v) if v else math.nan, max(v) if v else math.nan,
            sum(1 for x in v if x > 500)))
    summary += ['', 'Rounds above 500 ms are ~1 s outliers: the first SYN after a grant was lost and TCP retransmitted after its 1 s timeout.', '']

# --- 2. connect latency and throughput ---
dp, sp = read('dynamic_perf.csv'), read('static_perf.csv')
if dp or sp:
    def pick(rows, t):
        return [fl(r['value']) for r in rows if r['type'] == t]
    labels = ['Static ACL', 'Dynamic SDN']
    fig, axs = plt.subplots(1, 2, figsize=(9, 4))
    for ax, t, title, unit in ((axs[0], 'connect', 'TCP connect + first byte', 'ms'),
                               (axs[1], 'bulk', 'Bulk transfer throughput', 'Mbit/s')):
        data = [pick(sp, t), pick(dp, t)]
        agg = med if t == 'connect' else mean
        ax.bar(labels, [agg(d) for d in data], yerr=[sd([x for x in d if x < 500] if t == 'connect' else d) for d in data], capsize=4, color=['#9d9d9d', '#4c78a8'])
        ax.set_title(title); ax.set_ylabel(unit)
    save(fig, 'fig2_connect_throughput.png')
    summary += ['## Data-path performance', '', '| Metric | Static ACL | Dynamic SDN |', '|---|---|---|']
    for t, n, u in (('connect', 'Connect + first byte (median)', 'ms'), ('bulk', 'Throughput (mean)', 'Mbit/s')):
        agg = med if t == 'connect' else mean
        summary.append('| %s (%s) | %.2f | %.2f |' % (n, u, agg(pick(sp, t)), agg(pick(dp, t))))
    summary.append('')

# --- 3. concurrency ---
dc, sc = read('dynamic_concurrency.csv'), read('static_concurrency.csv')
if dc or sc:
    ns = sorted({int(r['n']) for r in dc + sc})
    def per_n(rows, key, n):
        return vals([r for r in rows if int(r['n']) == n], key)
    def success(rows, n):
        rs = [r for r in rows if int(r['n']) == n]
        return 100.0 * sum(1 for r in rs if r['access_ok'] == '1') / len(rs) if rs else math.nan
    fig, axs = plt.subplots(1, 2, figsize=(9, 4))
    if dc:
        axs[0].plot(ns, [mean(per_n(dc, 'auth_ms', n)) for n in ns], 'o-', label='mean auth latency')
        axs[0].plot(ns, [max(per_n(dc, 'auth_ms', n) or [math.nan]) for n in ns], 's--', label='max auth latency')
    axs[0].set_xlabel('simultaneous users'); axs[0].set_ylabel('ms'); axs[0].set_title('Dynamic: login under load')
    axs[0].set_xticks(ns); axs[0].legend()
    if dc:
        axs[1].plot(ns, [mean(per_n(dc, 'access_ms', n)) for n in ns], 'o-', label='Dynamic SDN (after login)')
    if sc:
        axs[1].plot(ns, [mean(per_n(sc, 'access_ms', n)) for n in ns], 's--', label='Static ACL')
    axs[1].set_xlabel('simultaneous users'); axs[1].set_ylabel('ms'); axs[1].set_title('Service access time')
    axs[1].set_xticks(ns); axs[1].legend()
    save(fig, 'fig3_concurrency.png')
    summary += ['## Concurrent users', '', '| Users | Dyn mean auth (ms) | Dyn max auth (ms) | Dyn access success % | Static access success % |', '|---|---|---|---|---|']
    for n in ns:
        a = per_n(dc, 'auth_ms', n)
        summary.append('| %d | %.1f | %.1f | %.0f | %.0f |' % (n, mean(a), max(a) if a else math.nan, success(dc, n), success(sc, n)))
    summary.append('')

# --- 4. flow table size ---
df, sf = read('dynamic_flows.csv'), read('static_flows.csv')
if df or sf:
    def series(rows, stage):
        return {int(r['n']): int(r['priority20_flows']) for r in rows if r['stage'] == stage}
    fig, ax = plt.subplots(figsize=(6, 4))
    ns = [5, 10, 20]
    for rows, stage, lab, sty in ((df, 'active', 'Dynamic: users logged in', 'o-'),
                                  (df, 'after_logout', 'Dynamic: after logout', 'o:'),
                                  (sf, 'active', 'Static ACL', 's--')):
        s = series(rows, stage)
        if s:
            ax.plot(ns, [s.get(n, math.nan) for n in ns], sty, label=lab)
    ax.set_xlabel('users'); ax.set_ylabel('priority-20 (access) flow entries'); ax.set_xticks(ns)
    ax.set_title('Flow table usage'); ax.legend()
    save(fig, 'fig4_flow_table.png')
    summary += ['## Flow table (priority-20 access rules)', '', '| Users | Dynamic (logged in) | Dynamic (after logout) | Static ACL |', '|---|---|---|---|']
    a, b, c = series(df, 'active'), series(df, 'after_logout'), series(sf, 'active')
    for n in ns:
        summary.append('| %d | %s | %s | %s |' % (n, a.get(n, '-'), b.get(n, '-'), c.get(n, '-')))
    summary.append('')

summary += ['## Notes', '',
            '- ICMP is dropped by the default-deny policy, so latency is measured at TCP level (connect + first byte).',
            '- Static ACL cannot revoke a single user without manually editing rules; dynamic revoke time is in the first table.',
            '- Throughput is expected to be similar: once rules are installed both approaches forward in the switch data plane.']
open(os.path.join(D, 'summary.md'), 'w').write('\n'.join(summary) + '\n')
print('wrote summary.md')
