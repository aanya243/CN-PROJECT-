# D1 demo (Mininet CLI, repo root; one command at a time)
1. `h1 python3 client/client.py access` -> BLOCKED
2. `attacker python3 client/client.py access` -> BLOCKED
3. `h1 python3 client/client.py login alice alice123` -> AUTH_OK, then `h1 python3 client/client.py access` -> GRANTED
4. `sh ovs-ofctl -O OpenFlow13 dump-flows s1` -> priority-20 rules (screenshot)
5. `h2 python3 client/client.py login alice wrongpw` -> AUTH_FAIL
6. wait 65 s, `h1 python3 client/client.py access` -> BLOCKED; dump-flows again -> no priority-20 rules
