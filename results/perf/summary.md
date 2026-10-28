# Performance summary

## Event latency (dynamic, 20 rounds)

| Metric | Median (ms) | Mean (ms) | Std | Min | Max | Rounds > 500 ms |
|---|---|---|---|---|---|---|
| Authentication latency | 12.1 | 15.1 | 9.8 | 9.3 | 54.1 | 0 |
| Grant time (login to access) | 14.6 | 168.0 | 366.8 | 11.5 | 1023.4 | 3 |
| Revoke time (logout to blocked) | 8.5 | 9.6 | 4.2 | 5.8 | 20.4 | 0 |

Rounds above 500 ms are ~1 s outliers: the first SYN after a grant was lost and TCP retransmitted after its 1 s timeout.

## Data-path performance

| Metric | Static ACL | Dynamic SDN |
|---|---|---|
| Connect + first byte (median) (ms) | 1.37 | 2.49 |
| Throughput (mean) (Mbit/s) | 18959.17 | 18104.87 |

## Concurrent users

| Users | Dyn mean auth (ms) | Dyn max auth (ms) | Dyn access success % | Static access success % |
|---|---|---|---|---|
| 5 | 60.7 | 68.1 | 100 | 100 |
| 10 | 81.8 | 95.3 | 100 | 100 |
| 20 | 132.3 | 182.2 | 100 | 100 |

## Flow table (priority-20 access rules)

| Users | Dynamic (logged in) | Dynamic (after logout) | Static ACL |
|---|---|---|---|
| 5 | 20 | 0 | 120 |
| 10 | 40 | 0 | 120 |
| 20 | 80 | 0 | 120 |

## Notes

- ICMP is dropped by the default-deny policy, so latency is measured at TCP level (connect + first byte).
- Static ACL cannot revoke a single user without manually editing rules; dynamic revoke time is in the first table.
- Throughput is expected to be similar: once rules are installed both approaches forward in the switch data plane.
