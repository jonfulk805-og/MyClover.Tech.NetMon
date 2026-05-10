FROM python:3.13-slim

LABEL maintainer="MyClover.Tech"
LABEL description="MyClover.Tech.NetMon Demo Instance"

# Install system deps (ping, DNS utils, net-snmp)
RUN apt-get update && apt-get install -y --no-install-recommends \
    iputils-ping \
    dnsutils \
    snmp \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements and install Python deps
COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn

# Copy application code
COPY app/ .

# Copy demo config and seed script
COPY demo_config.yaml ./config.yaml
COPY demo_seed.py .
COPY demo_simulator.py .
COPY entrypoint.sh .
RUN chmod +x entrypoint.sh

# Create data directory
RUN mkdir -p /app/data

EXPOSE 8080

ENTRYPOINT ["./entrypoint.sh"]
