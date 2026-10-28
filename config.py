"""Shared settings used by the controller, topology, auth server and client."""
MAX_CLIENTS = 20                      # h1..h20 (topology starts only as many as you ask for)
AUTH_IP, AUTH_PORT = '10.0.0.100', 5000
SVC_IP = '10.0.0.200'
ATTACKER_IP = '10.0.0.66'
CTRL_SOCK = '/tmp/sdn_ctrl.sock'

# Protected service ports: public info, data, admin console
PORT_PUBLIC, PORT_DATA, PORT_ADMIN = 8081, 8080, 9090
SVC_PORTS = [PORT_PUBLIC, PORT_DATA, PORT_ADMIN]

# Role-based policy: which service ports a role may reach, and how long a session lasts (s)
ROLE_PORTS = {'admin': [8081, 8080, 9090], 'user': [8081, 8080], 'guest': [8081]}
ROLE_TTL = {'admin': 120, 'user': 60, 'guest': 30}

# Brute-force protection
MAX_FAILS, FAIL_WINDOW, BLOCK_SECS = 3, 60, 30


def mac(n):
    return '00:00:00:00:00:%02x' % n


def build_hosts():
    """name -> (ip, mac, switch_port). Used by both the topology and the controller."""
    hosts = {}
    for i in range(1, MAX_CLIENTS + 1):
        hosts['h%d' % i] = ('10.0.0.%d' % i, mac(i), i)
    hosts['attacker'] = (ATTACKER_IP, mac(21), 21)
    hosts['auth'] = (AUTH_IP, mac(22), 22)
    hosts['svc'] = (SVC_IP, mac(23), 23)
    return hosts
