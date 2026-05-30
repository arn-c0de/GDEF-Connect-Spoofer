# GDEF-L1NK Sensor

A thin capture worker you install on each server you want to monitor. It sniffs
locally, coalesces connections, and pushes them **gzip-compressed and
Fernet-encrypted** to the central hub's `/api/ingest`. All geo/threat/vendor
enrichment happens on the hub, so the sensor needs no database and no datasets.

Each sensor is one **device** on the hub: it shows up as its own named, coloured
origin on the globe. Sensors are identified by their `DEVICE_ID`, never by IP —
so several sensors behind the same home router (one public IP) stay distinct.

## How it authenticates

The hub issues a per-device **Fernet key**. The sensor encrypts each batch with
it; on the hub a payload that decrypts cleanly is authentic (only the key holder
could produce it). Every batch carries a strictly-increasing sequence number, and
Fernet stamps a timestamp, so replays and stale batches are rejected. This holds
even over plain HTTP on a LAN — though HTTPS to the hub is still recommended.

## 1. Register the device on the hub

In the dashboard: **Devices → Add**, give it a name (e.g. `server1`) and a
colour. The hub shows the `DEVICE_ID` and `DEVICE_KEY` **once** — copy them now.
(Lost it? Use **rotate key** to issue a new one.)

## 2. Deploy

Copy three files to the sensor host: `sensor.py`, plus `capture_core.py` and
`device_crypto.py` from the hub repo root. (Or run from a full repo checkout —
both locations are searched automatically.)

```bash
mkdir -p /opt/connectspoofer-sensor && cd /opt/connectspoofer-sensor
# copy sensor.py, capture_core.py, device_crypto.py, requirements.txt here
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
cp sensor.env.example sensor.env && chmod 600 sensor.env
# edit sensor.env: CENTRAL_URL, DEVICE_ID, DEVICE_KEY, NETWORK_INTERFACE
```

## 3. Run

```bash
sudo -E .venv/bin/python sensor.py      # capture needs CAP_NET_RAW (root)
```

### As a service (systemd)

```bash
sudo cp connectspoofer-sensor.service /etc/systemd/system/
# adjust the paths inside the unit if you deployed elsewhere
sudo systemctl daemon-reload
sudo systemctl enable --now connectspoofer-sensor
journalctl -u connectspoofer-sensor -f
```

The unit grants only `CAP_NET_RAW`/`CAP_NET_ADMIN` instead of full root.

### With Docker

Build from the **repo root** (so the shared modules are in the build context):

```bash
docker build -f sensor/Dockerfile -t connectspoofer-sensor .
docker run --rm --network host --cap-add NET_RAW --cap-add NET_ADMIN \
  --env-file sensor/sensor.env connectspoofer-sensor
```

## Configuration

See `sensor.env.example`. Required: `CENTRAL_URL`, `DEVICE_ID`, `DEVICE_KEY`,
`NETWORK_INTERFACE`. Optional tuning knobs (flush interval, buffer caps, TLS
verification, log level) are documented there.

## Notes

- If the hub is unreachable, the sensor keeps buffering (bounded by
  `SENSOR_MAX_BUFFER_IPS`, oldest dropped beyond that) and resumes when it
  returns — no data loss for short outages.
- The sensor only sends raw connection records (IP, protocol, ports, packet
  counts, bytes, TTL, MAC). It never sends payload contents.
- Monitor only networks and systems you are authorized to assess.
