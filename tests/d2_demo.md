# D2 demo script (Mininet CLI, repo root). Type ONE command at a time; wait for the prompt.
Hosts: h1..h4 clients, attacker (10.0.0.66). Users: alice/alice123 (user), bob/bob123 (user),
carol/carol123 (guest), admin/admin123 (admin). Ports: public 8081, data 8080, admin 9090.
Roles: admin = 8081+8080+9090 (120 s), user = 8081+8080 (60 s), guest = 8081 (30 s).

## A. Roles (restrict)
| Command | Expected |
|---|---|
| `h1 python3 client/client.py login alice alice123` | AUTH_OK user 60 8081,8080 |
| `h1 python3 client/client.py access 8080` | GRANTED |
| `h1 python3 client/client.py access 9090` | BLOCKED (user cannot reach admin port) |
| `h2 python3 client/client.py login admin admin123` | AUTH_OK admin 120 ... |
| `h2 python3 client/client.py access 9090` | GRANTED |
| `h3 python3 client/client.py login carol carol123` | AUTH_OK guest 30 8081 |
| `h3 python3 client/client.py access 8081` | GRANTED |
| `h3 python3 client/client.py access 8080` | BLOCKED (guest limited) |
| `sh ovs-ofctl -O OpenFlow13 dump-flows s1` | priority-20 rules per host with different ports |

## B. Logout / explicit revoke
| `h1 python3 client/client.py logout` | LOGOUT_OK |
| `h1 python3 client/client.py access 8080` | BLOCKED immediately (no waiting for timeout) |

## C. Session expiry
| `h3 python3 client/client.py login carol carol123` | AUTH_OK ... 30 |
| wait 35 s, then `h3 python3 client/client.py access 8081` | BLOCKED |
| `sh cat /tmp/auth.log` | SESSION_EXPIRED line |

## D. Brute-force protection (attacker)
| `attacker python3 client/client.py login alice wrong1` | AUTH_FAIL bad_credentials |
| `attacker python3 client/client.py login alice wrong2` | AUTH_FAIL bad_credentials |
| `attacker python3 client/client.py login alice wrong3` | AUTH_FAIL blocked_30s |
| `attacker python3 client/client.py login alice alice123` | AUTH SERVER UNREACHABLE (timed out): blocked at the switch, even with the right password |
| `sh ovs-ofctl -O OpenFlow13 dump-flows s1` | a priority=30 drop rule for 10.0.0.66 |
| wait 35 s, `attacker python3 client/client.py login alice wrong1` | reaches the server again (block expired) |

## E. Logs (save these)
`sh cat /tmp/auth.log`  and  `sh cat /tmp/nac_events.log`
