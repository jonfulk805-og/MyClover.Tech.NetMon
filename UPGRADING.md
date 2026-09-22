# Upgrading NetMon

## 5.8 - persistence, authorization, SLA accuracy

This release changes where data lives, how credentials are stored and how
uptime is calculated. Read this before replacing a running container.

### 1. Data now lives in the volume (automatic, but verify)

NetMon previously wrote `netmon.db` next to `netmon.py`, so the documented
`/app/data` volume held nothing and every container replacement lost the
database. It now honours:

| Variable | Default (docker) | Holds |
| --- | --- | --- |
| `NETMON_DATA_DIR` | `/app/data` | everything below |
| `NETMON_DB_PATH` | `/app/data/netmon.db` | check results, alerts |
| `NETMON_CONFIG` | `/app/data/config.yaml` | devices, settings, users |
| `NETMON_BACKUP_DIR` | `/app/data/backups` | backup zips |
| `NETMON_SECRET_FILE` | `/app/data/auth_secret.key` | token signing secret |

On first start the old files are **copied** into the data dir if the new
location is empty. Nothing is deleted. If you mounted a config at
`/app/config.yaml`, move the mount to `/app/data/config.yaml`.

**Verify after upgrading:** `docker exec <container> ls -la /app/data` should
show `netmon.db` and `config.yaml`.

### 2. Everyone is logged out once (breaking)

- The signing secret is generated per installation instead of being the fixed
  string that shipped in the public source. Existing tokens are invalid.
- Passwords in `config.yaml` are hashed with PBKDF2-SHA256 on first load and
  the plaintext `password:` field is removed. Keep a copy of your credentials
  before upgrading; hashes cannot be read back.
- Deleting a user or changing a role/password invalidates their tokens.
- New users need a password of at least 8 characters.

### 3. Authorization is on by default for every route

Previously only user-management routes checked the token. Now every route
requires a permission (`read` / `write` / `config` / `users`) unless it is the
dashboard shell, static files or login/logout. With `auth_enabled: false` the
API stays open exactly as before, but you can no longer enable authentication
without an admin user, delete the last admin, or have auth silently fall open
when the user list is empty.

`/api/settings` no longer returns `smtp_password`. It returns
`smtp_password_set: true|false`; submitting a blank password keeps the stored
one.

### 4. HTTPS checks verify certificates (behaviour change)

HTTP checks used `verify=False`, so an expired or invalid certificate reported
healthy. Verification is now on. If a check targets an internal host with a
private CA or a self-signed certificate, set per check:

```yaml
checks:
  - type: http
    url: https://internal.example
    ca_bundle: /app/data/corp-ca.pem   # or: verify_tls: false
```

Account-wide defaults: `http_verify_tls: true`, `http_ca_bundle: ""`.

### 5. SLA reports change shape (expect different numbers)

Availability is now computed from timestamped state transitions per sensor
instead of counting rows and multiplying by the interval. Consequences:

- a healthy sensor no longer cancels out a failing one on the same device
- periods with no observations are reported as `unknown_minutes`, not downtime
- scheduled maintenance is reported as `maintenance_minutes` and excluded
- the device-level rollup is explicit:

```yaml
sla_device_availability: any_sensor_down   # worst_sensor | mean_sensor
```

Reports and the CSV export gain `availability_mode`, `maintenance_minutes`,
`unknown_minutes`, `sensor_count` and a per-sensor breakdown. Historical
reports will not match old ones - the old ones were wrong.

### 6. Scheduler settings

```yaml
max_check_workers: 16   # bounded worker pool, was one thread per check
```

The cycle now starts every `check_interval_seconds` from the previous start
(no drift); overruns are logged. `/api/monitoring-health` reports last cycle,
drift, notification queue depth and a `stale` flag, and `/api/status` marks
each row with `age_seconds` / `stale`.
