# GDEF-L1NK sensor image.
# Build from the REPO ROOT so the two shared modules are in context:
#   docker build -f sensor/Dockerfile -t gdef-l1nk-sensor .
# Run with host networking + raw-capture capability:
#   docker run --rm --network host --cap-add NET_RAW --cap-add NET_ADMIN \
#     --env-file sensor/sensor.env gdef-l1nk-sensor
FROM python:3.12-slim

WORKDIR /app
COPY sensor/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Shared with the hub (identical wire format + packet classification).
COPY capture_core.py device_crypto.py ./
COPY sensor/sensor.py ./

CMD ["python", "sensor.py"]
