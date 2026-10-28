"""Ryu app (OpenFlow 1.3): default-deny network with dynamic GRANT / REVOKE / BLOCK.

Run:  ryu-manager controller/nac_controller.py                 (dynamic mode, default)
      NAC_MODE=static ryu-manager controller/nac_controller.py (static-ACL baseline)

The auth server sends one JSON line per command over a Unix socket (CTRL_SOCK):
  {"cmd":"GRANT","ip":..,"ports":[..],"ttl":60}   {"cmd":"REVOKE","ip":..}
  {"cmd":"BLOCK","ip":..,"ttl":30}                {"cmd":"UNBLOCK","ip":..}
Every change is also appended to /tmp/nac_events.log.
"""
import json
import os
import socket
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config as C  # noqa: E402

from ryu.base import app_manager  # noqa: E402
from ryu.controller import ofp_event  # noqa: E402
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls  # noqa: E402
from ryu.lib import hub  # noqa: E402
from ryu.ofproto import ofproto_v1_3  # noqa: E402

EVENT_LOG = '/tmp/nac_events.log'
MODE = os.environ.get('NAC_MODE', 'dynamic')

_hosts = C.build_hosts()
HOSTS = {ip: (port, mac) for (ip, mac, port) in _hosts.values()}                  # ip -> (port, mac)
CLIENT_IPS = [v[0] for n, v in _hosts.items() if n not in ('auth', 'svc')]        # clients + attacker
STATIC_ALLOWED = [v[0] for n, v in _hosts.items() if n.startswith('h')]            # baseline: h1..h20

PRIO_ARP, PRIO_AUTH, PRIO_GRANT, PRIO_BLOCK = 5, 10, 20, 30


class NacController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.dp = None
        self._barriers = {}          # xid -> hub.Event, used to wait for the switch to confirm flow-mods
        open(EVENT_LOG, 'w').close()
        hub.spawn(self._serve)

    def _event(self, msg):
        self.logger.info(msg)
        with open(EVENT_LOG, 'a') as f:
            f.write('%s %s\n' % (time.strftime('%Y-%m-%d %H:%M:%S'), msg))

    # ---------- OpenFlow helpers ----------
    def _add_flow(self, prio, match, actions, hard_timeout=0):
        dp = self.dp
        p, ofp = dp.ofproto_parser, dp.ofproto
        inst = [p.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)] if actions else []
        dp.send_msg(p.OFPFlowMod(datapath=dp, priority=prio, match=match,
                                 instructions=inst, hard_timeout=hard_timeout))

    def _del_flow(self, match, prio=None):
        """prio=None: non-strict delete (removes every flow at least as specific as match)."""
        dp = self.dp
        p, ofp = dp.ofproto_parser, dp.ofproto
        kw = dict(datapath=dp, out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY, match=match)
        if prio is None:
            kw['command'] = ofp.OFPFC_DELETE
        else:
            kw['command'] = ofp.OFPFC_DELETE_STRICT
            kw['priority'] = prio
        dp.send_msg(p.OFPFlowMod(**kw))

    def _barrier(self, timeout=2):
        """Block until the switch has processed every flow-mod sent before this call.
        Without it the controller could answer the auth server before the rules exist, and the
        client's first SYN would be dropped (it then waits ~1 s for the TCP retransmission)."""
        dp = self.dp
        req = dp.ofproto_parser.OFPBarrierRequest(dp)
        dp.set_xid(req)
        ev = hub.Event()
        self._barriers[req.xid] = ev
        dp.send_msg(req)
        ev.wait(timeout=timeout)
        self._barriers.pop(req.xid, None)

    @set_ev_cls(ofp_event.EventOFPBarrierReply, MAIN_DISPATCHER)
    def on_barrier_reply(self, ev):
        waiter = self._barriers.get(ev.msg.xid)
        if waiter:
            waiter.set()

    def _out(self, port):
        return [self.dp.ofproto_parser.OFPActionOutput(port)]

    def _tcp_match(self, src_ip, dst_ip, src_port=None, dst_port=None, eth_src=None):
        kw = dict(eth_type=0x0800, ip_proto=6, ipv4_src=src_ip, ipv4_dst=dst_ip)
        if src_port: kw['tcp_src'] = src_port
        if dst_port: kw['tcp_dst'] = dst_port
        if eth_src: kw['eth_src'] = eth_src
        return self.dp.ofproto_parser.OFPMatch(**kw)

    # ---------- switch connects: install the locked-down baseline ----------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def on_features(self, ev):
        self.dp = ev.msg.datapath
        p, ofp = self.dp.ofproto_parser, self.dp.ofproto
        self._add_flow(0, p.OFPMatch(), [])                                    # default: drop
        self._add_flow(PRIO_ARP, p.OFPMatch(eth_type=0x0806),
                       [p.OFPActionOutput(ofp.OFPP_FLOOD)])                    # ARP allowed
        auth_port = HOSTS[C.AUTH_IP][0]
        for ip in CLIENT_IPS:
            port = HOSTS[ip][0]
            self._add_flow(PRIO_AUTH, self._tcp_match(ip, C.AUTH_IP, dst_port=C.AUTH_PORT),
                           self._out(auth_port))                               # client -> auth
            self._add_flow(PRIO_AUTH, self._tcp_match(C.AUTH_IP, ip, src_port=C.AUTH_PORT),
                           self._out(port))                                    # auth -> client
        self._event('SWITCH_READY mode=%s' % MODE)
        if MODE == 'static':                      # baseline: permanent, unauthenticated ACL
            for ip in STATIC_ALLOWED:
                self.grant(ip, C.SVC_PORTS, 0)

    # ---------- dynamic policy ----------
    def grant(self, ip, ports, ttl):
        port, mac = HOSTS[ip]
        svc_port = HOSTS[C.SVC_IP][0]
        self._revoke_flows(ip)                    # replace any older grant (e.g. role change)
        for sp in ports:
            self._add_flow(PRIO_GRANT,
                           self._tcp_match(ip, C.SVC_IP, dst_port=sp, eth_src=mac),   # IP+MAC bound
                           self._out(svc_port), hard_timeout=ttl)
            self._add_flow(PRIO_GRANT, self._tcp_match(C.SVC_IP, ip, src_port=sp),
                           self._out(port), hard_timeout=ttl)
        self._event('GRANT ip=%s ports=%s ttl=%s' % (ip, ports, ttl))

    def _revoke_flows(self, ip):
        self._del_flow(self._tcp_match(ip, C.SVC_IP))
        self._del_flow(self._tcp_match(C.SVC_IP, ip))

    def revoke(self, ip):
        self._revoke_flows(ip)
        self._event('REVOKE ip=%s' % ip)

    def block(self, ip, ttl):
        self._revoke_flows(ip)
        m = self.dp.ofproto_parser.OFPMatch(eth_type=0x0800, ipv4_src=ip)
        self._add_flow(PRIO_BLOCK, m, [], hard_timeout=ttl)      # drop everything from this host
        self._event('BLOCK ip=%s ttl=%s' % (ip, ttl))

    def unblock(self, ip):
        m = self.dp.ofproto_parser.OFPMatch(eth_type=0x0800, ipv4_src=ip)
        self._del_flow(m, prio=PRIO_BLOCK)
        self._event('UNBLOCK ip=%s' % ip)

    # ---------- control channel (auth server -> controller) ----------
    def _serve(self):
        if os.path.exists(C.CTRL_SOCK):
            os.unlink(C.CTRL_SOCK)
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(C.CTRL_SOCK)
        os.chmod(C.CTRL_SOCK, 0o777)
        srv.listen(32)
        while True:
            conn, _ = srv.accept()
            hub.spawn(self._handle, conn)

    def _handle(self, conn):
        try:
            req = json.loads(conn.makefile('r').readline())
            cmd, ip = req['cmd'], req['ip']
            if self.dp is None or ip not in HOSTS:
                raise ValueError('no switch or unknown host')
            if cmd == 'GRANT':
                self.grant(ip, [int(x) for x in req['ports']], int(req.get('ttl', 60)))
            elif cmd == 'REVOKE':
                self.revoke(ip)
            elif cmd == 'BLOCK':
                self.block(ip, int(req.get('ttl', C.BLOCK_SECS)))
            elif cmd == 'UNBLOCK':
                self.unblock(ip)
            else:
                raise ValueError('bad cmd')
            self._barrier()                       # reply OK only once the switch has applied the rules
            conn.sendall(b'OK\n')
        except Exception as e:  # noqa
            self.logger.warning('control error: %s', e)
            conn.sendall(('ERR %s\n' % e).encode())
        finally:
            conn.close()
