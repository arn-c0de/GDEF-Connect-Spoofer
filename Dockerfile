# GDEF-L1NK — sniffer + web UI container.
#
# Runs with host networking and NET_RAW/NET_ADMIN so Scapy can capture from the
# physical interface (see docker-compose.yml). Application data lives in
# PostgreSQL (the `db` service); the ./database directory is mounted for the geo
# .mmdb datasets and the generated secrets/config.
FROM python:3.12-slim

# Runtime libraries Scapy needs to capture on a live interface, plus tcpdump for
# diagnostics. libpq is bundled by psycopg[binary], so no libpq-dev is required.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libpcap0.8 \
        tcpdump \
        iproute2 \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python deps first for layer caching.
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Application source.
COPY . .

# Web UI port (host networking, so this is informational).
EXPOSE 8000

# The app waits for PostgreSQL (db.wait_until_ready) before creating its schema.
CMD ["python", "app.py"]
