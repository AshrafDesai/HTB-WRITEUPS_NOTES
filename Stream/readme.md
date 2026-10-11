# Stream — HTB (Linux, Release Arena)

AIDX ingest on FastAPI, a Spring `terminal-edge` gateway, and ClickHouse behind nginx.
Two XML parsers on the same path give the box its shape: an **in-band XXE** that
reads files for the user, and a **malformed-body** route that wakes a root-level
DLQ drainer for root.

---

## Box

| | |
|---|---|
| OS | Ubuntu · OpenSSH 9.6p1 |
| Hosts | `htb-airport.htb` · `api.htb-airport.htb` · `db.htb-airport.htb` |
| Entry | Unauth Spring `/actuator/heapdump` + `:8081/feeds/aidx` |
| User | heap → ClickHouse `svc_events` → XXE `file://` in `<Airline>` → Kafka SASL = SSH `svc-infra` → local `su` |
| Root | systemd DLQ timer as root + argv sniff of `clickhouse-client --password` + `GRANT FILE` on the formatter |

> No flags, VPN configs, or live passwords in this tree.

---

## Tree
Stream/
├── README.md · WRITEUP.md · secrets.example.env · .gitignore
└── scripts/
    ├── heap_extract.py · aidx_ingest.py · ch_http.py · xxe_read.py
    ├── ch_file_append.py · replay.sh
    ├── su_brute.py · proc_sniff.py         (target-side)
    └── payloads/
        ├── xxe-file.xml
        └── dlq-malformed.xml
---

## Scripts

**Kali-side**

- `heap_extract.py` — neighbourhood around Hikari setters in the heapdump
- `aidx_ingest.py` — POST AIDX (plain / XXE / malformed → DLQ)
- `ch_http.py` — ClickHouse HTTP Basic
- `xxe_read.py` — ingest XXE + `SELECT flightleg_json.airline`
- `ch_file_append.py` — `INSERT INTO FUNCTION file(...)` append
- `replay.sh` — thin wrapper over the above

**Target-side** (run over an SSH session)

- `su_brute.py` — local `su` against a wordlist (fail2ban on `:22`)
- `proc_sniff.py` — busy-loop `/proc/<pid>/cmdline`

---

## Quick start

```bash
echo '<TARGET_IP> htb-airport.htb api.htb-airport.htb db.htb-airport.htb' | sudo tee -a /etc/hosts
export TARGET=<TARGET_IP>

./scripts/replay.sh heap
export CH_PASS=...          # setPassword next to setUsername svc_events
./scripts/replay.sh xxe /opt/kafka_2.13-4.3.1/config/server.properties
