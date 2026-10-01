#!/bin/bash
set -e

echo "=== MyClover.Tech.NetMon Demo Container ==="
echo "Starting at $(date -u)"

# Demo login password: from NETMON_DEMO_PASSWORD (set in /opt/netmon-demo/.env
# by setup.sh). Never stored in the repo. If unset, a random one is generated
# for this container run and printed below (docker logs netmon-demo).
if [ -z "${NETMON_DEMO_PASSWORD:-}" ]; then
    NETMON_DEMO_PASSWORD="$(python -c 'import secrets; print(secrets.token_urlsafe(9))')"
    echo "[WARN] NETMON_DEMO_PASSWORD not set -- generated one for this run: ${NETMON_DEMO_PASSWORD}"
    echo "[WARN] Set it in /opt/netmon-demo/.env so it survives restarts."
fi
NETMON_DEMO_PASSWORD="$NETMON_DEMO_PASSWORD" NETMON_DEMO_LICENSE_KEY="${NETMON_DEMO_LICENSE_KEY:-}" python - <<'PYEOF'
import hashlib, os, secrets, yaml
path = "config.yaml"
with open(path, encoding="utf-8") as f:
    cfg = yaml.safe_load(f) or {}
pw = os.environ["NETMON_DEMO_PASSWORD"]
salt = secrets.token_hex(16)
rounds = 200000
dk = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt.encode("ascii"), rounds)
users = cfg.get("users") or [{"username": "demo", "role": "admin"}]
for u in users:
    if u.get("username") == "demo":
        u.pop("password", None)
        u["password_hash"] = "pbkdf2_sha256$%d$%s$%s" % (rounds, salt, dk.hex())
cfg["users"] = users
# Optional: a signed demo license from the VPS .env (keeps signed keys out of the repo).
lic = os.environ.get("NETMON_DEMO_LICENSE_KEY", "").strip()
if lic:
    cfg["license_key"] = lic
with open(path, "w", encoding="utf-8") as f:
    yaml.safe_dump(cfg, f, sort_keys=False)
print("[OK] Demo login password applied for user 'demo'")
PYEOF
unset NETMON_DEMO_PASSWORD

# Seed the database with demo data
echo "Seeding demo database..."
python demo_seed.py

# Start the simulator in the background
echo "Starting data simulator..."
python demo_simulator.py &
SIMULATOR_PID=$!

# Start netmon with gunicorn for production
echo "Starting NetMon dashboard..."
exec python netmon.py
