# Command cheat sheet – SDN Authentication & Network Access Control

Project folder: `~/Downloads/sdn-auth`  (always run commands from inside it)

## 0. Quick facts

| Host | IP | Role |
|---|---|---|
| h1 – h4 (up to h20) | 10.0.0.1 – 10.0.0.20 | clients |
| attacker | 10.0.0.66 | unauthorized host |
| auth | 10.0.0.100 | TCP auth server (port 5000) |
| svc | 10.0.0.200 | protected services: public 8081, data 8080, admin 9090 |

| User | Password | Role | Ports | Session |
|---|---|---|---|---|
| alice, bob | alice123, bob123 | user | 8081, 8080 | 60 s |
| carol | carol123 | guest | 8081 | 30 s |
| admin | admin123 | admin | 8081, 8080, 9090 | 120 s |

Brute force: 3 wrong logins in 60 s -> host blocked at the switch for 30 s.

---

## 1. Start the system (every time)

**Terminal 1 – Ryu controller**
```
source ~/ryu-env39/bin/activate
cd ~/Downloads/sdn-auth
ryu-manager controller/nac_controller.py
```
Leave it running. You should see `SWITCH_READY mode=dynamic` after step 2.

**Terminal 2 – Mininet** (do NOT activate ryu-env39 here)
```
cd ~/Downloads/sdn-auth
sudo mn -c
sudo python3 topology/topo.py --clients 4
```
Wait for the `mininet>` prompt.

**Stop everything:** type `exit` at `mininet>`, press Ctrl+C in Terminal 1, then `sudo mn -c`.

### Mininet prompt rules
- Type ONE command at a time. Wait for `mininet>` to come back (blocked tests take ~3 s).
- Run normal shell commands with `sh` in front: `sh date`, `sh cat /tmp/auth.log`.
- For the flow table use `sh ovs-ofctl ...`, NOT `s1 ovs-ofctl ...` (s1 gets replaced by 127.0.0.1).

---

## 2. D1 demo (basic grant / deny)

```
sh echo "=== TEST 1: no login, access blocked ==="
h1 python3 client/client.py access
attacker python3 client/client.py access

sh echo "=== TEST 2: wrong password ==="
h2 python3 client/client.py login alice wrongpw

sh echo "=== TEST 3: valid login, access granted ==="
h1 python3 client/client.py login alice alice123
h1 python3 client/client.py access 8080
sh ovs-ofctl -O OpenFlow13 dump-flows s1

sh echo "=== TEST 4: other hosts still blocked ==="
h1 python3 client/client.py access 8080
h2 python3 client/client.py access 8080
attacker python3 client/client.py access 8080

sh echo "=== TEST 5: after timeout, access revoked ==="
sh date
(wait 65 seconds, type nothing)
sh date
h1 python3 client/client.py access 8080
sh ovs-ofctl -O OpenFlow13 dump-flows s1
```
Expected: h1 allowed only while logged in; priority-20 rules appear after login and disappear after the timeout.

---

## 3. D2 demo

**A. Roles (restrict)**
```
h1 python3 client/client.py login alice alice123
h1 python3 client/client.py access 8080        # granted
h1 python3 client/client.py access 9090        # blocked (user cannot reach admin port)
h2 python3 client/client.py login admin admin123
h2 python3 client/client.py access 9090        # granted
h3 python3 client/client.py login carol carol123
h3 python3 client/client.py access 8081        # granted
h3 python3 client/client.py access 8080        # blocked (guest limited)
sh ovs-ofctl -O OpenFlow13 dump-flows s1
```

**B. Logout (explicit revoke)**
```
h1 python3 client/client.py login alice alice123
h1 python3 client/client.py logout
h1 python3 client/client.py access 8080        # blocked immediately
```

**C. Session expiry**
```
h3 python3 client/client.py login carol carol123
(wait 35 seconds)
h3 python3 client/client.py access 8081        # blocked
sh cat /tmp/auth.log                           # shows SESSION_EXPIRED
```

**D. Brute-force block** (type quickly, the block lasts only 30 s)
```
attacker python3 client/client.py login alice wrong1
attacker python3 client/client.py login alice wrong2
attacker python3 client/client.py login alice wrong3        # AUTH_FAIL blocked_30s
attacker python3 client/client.py login alice alice123      # AUTH SERVER UNREACHABLE (timed out)
sh ovs-ofctl -O OpenFlow13 dump-flows s1 | grep priority=30
(wait 35 seconds)
attacker python3 client/client.py login alice wrong1        # reachable again
```

---

## 4. Save logs and evidence

```
sh cat /tmp/auth.log
sh cat /tmp/nac_events.log
sh mkdir -p results/d2
sh cp /tmp/auth.log results/d2/auth_log.txt
sh cp /tmp/nac_events.log results/d2/controller_events.txt
```
Copy logs BEFORE restarting Ryu or Mininet (restarts overwrite them).
Screenshots: take them while the full test sequence is visible; name them `01_...`, `02_...`.

After using sudo, fix file ownership once: `sudo chown -R $USER:$USER ~/Downloads/sdn-auth`

---

## 5. Performance experiments

Do NOT have a `mininet>` prompt open (the script builds its own network). Run `sudo mn -c` first.

**Dynamic run**
```
# Terminal 1
source ~/ryu-env39/bin/activate
cd ~/Downloads/sdn-auth
ryu-manager controller/nac_controller.py
# Terminal 2
cd ~/Downloads/sdn-auth
sudo python3 tests/run_experiments.py --mode dynamic
```

**Static baseline run** (restart Ryu in static mode)
```
# Terminal 1: Ctrl+C, then
NAC_MODE=static ryu-manager controller/nac_controller.py
# Terminal 2
sudo mn -c
sudo python3 tests/run_experiments.py --mode static
```

**Graphs + summary** (new terminal, Ryu environment NOT active)
```
cd ~/Downloads/sdn-auth
sudo chown -R $USER:$USER results
sudo apt install -y python3-matplotlib
python3 tests/plot_results.py
cat results/perf/summary.md
```
Output: `results/perf/fig1..fig4.png`, `summary.md`, and the CSVs.

---

## 6. Troubleshooting

| Problem | Fix |
|---|---|
| `ryu-manager: command not found` | `source ~/ryu-env39/bin/activate` first |
| No `SWITCH_READY` in Terminal 1 | Ryu not running, or start Ryu before Mininet; then `sudo mn -c` and restart Mininet |
| Garbled commands (`tpython3`, `apython3`) | You typed during a running command. One command at a time |
| `ovs-ofctl: 127.0.0.1 is not a bridge` | Use `sh ovs-ofctl ...`, not `s1 ovs-ofctl ...` |
| Everything blocked after login | `sh cat /tmp/auth.log` (LOGIN_OK?) and check Terminal 1 for GRANT lines |
| "controller is not in dynamic/static mode" | Restart Ryu correctly (see section 5) |
| `Permission denied` on `__pycache__` or results | `sudo chown -R $USER:$USER ~/Downloads/sdn-auth` |
| Mininet left in a bad state | `exit`, then `sudo mn -c` |
| A grant takes ~1 s once in a while | Known: first SYN lost, TCP retries after 1 s (documented in the report) |

---

## 7. GitHub (submission)

One-time setup:
```
sudo apt install -y git
git config --global user.name "Your Name"
git config --global user.email "you@example.com"
```
Create an empty repo on github.com first, then:
```
cd ~/Downloads/sdn-auth
git init
git add .
git commit -m "D1 and D2: SDN authentication and access control"
git branch -M main
git remote add origin https://github.com/<username>/<repo>.git
git push -u origin main
```
GitHub asks for a personal access token instead of a password (Settings -> Developer settings -> Personal access tokens).

Later updates:
```
git add .
git commit -m "describe the change"
git push
```
