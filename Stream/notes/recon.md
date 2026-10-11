# Recon — Stream

## Ports
- 22/tcp  SSH (OpenSSH 9.6p1, fail2ban active)
- 80/tcp  nginx 1.24.0 → vhost routing
- 8081/tcp Uvicorn/FastAPI (AIDX ingest)
- 8123/9000/tcp ClickHouse (localhost only, proxied via db vhost)
- 9092/tcp Kafka (localhost only)

## Vhosts
- htb-airport.htb        → 301 to api vhost
- api.htb-airport.htb    → Spring Boot gateway (actuator/heapdump exposed)
- db.htb-airport.htb     → ClickHouse HTTP

## Ingest
- POST /feeds/aidx (application/xml)
- Does NOT parse; substring-matches 4 tags, ships raw to Kafka `aidx.flightleg.raw.v1`
- Required tags: IATA_AIDX_FlightLegNotifRQ, Originator, FlightLeg, LegIdentifier

## Downstream
- Kafka consumer runs lxml with resolve_entities=True (in-band XXE)
- Malformed XML → `aidx.flightleg.dlq.v1` → root drainer timer