#!/usr/bin/env python3
"""Mininet topology: 1 OVS switch, N clients, 1 attacker, auth server, protected services.
Run from the repo root (start Ryu first):
    sudo python3 topology/topo.py --clients 4
"""
import argparse
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import config as C  # noqa: E402

from mininet.cli import CLI  # noqa: E402
from mininet.log import setLogLevel  # noqa: E402
from mininet.net import Mininet  # noqa: E402
from mininet.node import OVSSwitch, RemoteController  # noqa: E402


def build(n_clients):
    net = Mininet(controller=None, switch=OVSSwitch, autoSetMacs=False)
    net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6653)
    s1 = net.addSwitch('s1', protocols='OpenFlow13')
    for name, (ip, mac, port) in C.build_hosts().items():
        if name.startswith('h') and int(name[1:]) > n_clients:
            continue
        h = net.addHost(name, ip=ip + '/24', mac=mac)
        net.addLink(h, s1, port2=port)               # switch port numbers match the controller
    return net


def run():
    ap = argparse.ArgumentParser()
    ap.add_argument('--clients', type=int, default=4, help='number of client hosts h1..hN (max 20)')
    args = ap.parse_args()
    net = build(min(args.clients, C.MAX_CLIENTS))
    net.start()
    net.get('svc').cmd('python3 -u %s/service/protected_service.py > /tmp/svc.log 2>&1 &' % ROOT)
    net.get('auth').cmd('python3 -u %s/auth/auth_server.py > /tmp/auth.log 2>&1 &' % ROOT)
    print('\nReady. Logs: /tmp/auth.log  /tmp/svc.log  /tmp/nac_events.log (controller)')
    CLI(net)
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    run()
