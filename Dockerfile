FROM python:3.13-slim

LABEL maintainer="MyClover.Tech"
LABEL description="MyClover.Tech.NetMon - Network Monitoring System"
LABEL org.opencontainers.image.source="https://github.com/jonfulk805-og/MyClover.Tech.NetMon"
LABEL org.opencontainers.image.title="MyClover.Tech.NetMon"
LABEL org.opencontainers.image.description="Network monitoring with ICMP, TCP, HTTP, SNMP checks, alerting, dashboards, and more"
LABEL org.opencontainers.image.vendor="MyClover.Tech"

# Install system deps (ping, DNS utils, SNMP)
RUN apt-get update && apt-get install -y --no-install-recommends \
    iputils-ping \
    dnsutils \
    snmp \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements first for Docker layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY netmon.py .
COPY config.yaml ./config.yaml.default
COPY ai_assistant.py .
COPY stripe_handler.py .
COPY stripe_config.yaml ./stripe_config.yaml.default
COPY templates/ ./templates/
COPY plugins/ ./plugins/

# Create data directory for persistent storage
RUN mkdir -p /app/data

# Copy entrypoint
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

# Default environment
ENV NETMON_CONFIG=/app/config.yaml
ENV NETMON_DB_PATH=/app/data/netmon.db

EXPOSE 8080

VOLUME ["/app/data"]

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD curl -f http://localhost:8080/ || exit 1

ENTRYPOINT ["/docker-entrypoint.sh"]
