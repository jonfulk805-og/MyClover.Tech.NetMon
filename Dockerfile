# ============================================================
# MyClover.Tech.NetMon v5.7 — Docker Container
# ============================================================
# Build:  docker build -t myclover/netmon .
# Run:    docker run -d -p 8080:8080 -v netmon-data:/app/data myclover/netmon
# ============================================================

FROM python:3.12-slim AS base

LABEL maintainer="MyClover.Tech <support@myclover.tech>"
LABEL description="MyClover.Tech NetMon — Network Monitoring Dashboard"
LABEL version="5.7"

# Install system deps (SNMP tools for Enterprise deep-polling, ping for ICMP checks)
RUN apt-get update && apt-get install -y --no-install-recommends \
        iputils-ping \
        snmp \
        net-tools \
        curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r netmon && useradd -r -g netmon -d /app -s /sbin/nologin netmon

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir gunicorn

# Copy application code
COPY netmon.py .
COPY generate_key.py .
COPY stripe_handler.py .
COPY templates/ templates/
COPY plugins/ plugins/

# Copy default configs (mount your own at runtime to override)
COPY config.yaml config.yaml.default
COPY stripe_config.yaml stripe_config.yaml.default

# Create data directory for SQLite DB and writable config
RUN mkdir -p /app/data \
    && chown -R netmon:netmon /app

# Startup script: copy default configs if user hasn't mounted their own
RUN cat > /app/entrypoint.sh << 'ENTRY'
#!/bin/bash
set -e

# If no config.yaml in /app/data, copy the default
if [ ! -f /app/data/config.yaml ]; then
    cp /app/config.yaml.default /app/data/config.yaml
    echo "[entrypoint] Created default config.yaml in /app/data/"
fi

# If no stripe_config.yaml in /app/data, copy the default
if [ ! -f /app/data/stripe_config.yaml ]; then
    cp /app/stripe_config.yaml.default /app/data/stripe_config.yaml
    echo "[entrypoint] Created default stripe_config.yaml in /app/data/"
fi

# Symlink configs from data volume into app dir so netmon.py finds them
ln -sf /app/data/config.yaml /app/config.yaml
ln -sf /app/data/stripe_config.yaml /app/stripe_config.yaml

# Ensure DB lives in the data volume
export NETMON_DB_PATH="/app/data/netmon.db"

exec "$@"
ENTRY
RUN chmod +x /app/entrypoint.sh

# Switch to non-root user
USER netmon

# Dashboard port
EXPOSE 8080

# Healthcheck — hit the dashboard
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8080/ || exit 1

# Persistent data (DB + configs)
VOLUME ["/app/data"]

ENTRYPOINT ["/app/entrypoint.sh"]

# Run with gunicorn for production, fall back to built-in Flask server
# Override CMD to use the built-in server: python netmon.py
CMD ["python", "netmon.py"]
