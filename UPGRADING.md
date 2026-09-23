# Upgrading NetMon

Two changes land together: the **5.8 hardening release** (persistence,
authorization, SLA accuracy) and the **incident timeline feed** that
SentryLog reads. Both are below. Start with the checklist.

## Upgrade checklist

1. **Back up first.** Copy `netmon.db` and `config.yaml` from wherever your
   current install keeps them (beside `netmon.py`, or `/app/data` if you had
   already moved them). The upgrade rewrites `config.yaml` (see section 2), so
   this copy is also your rollback.
2. **Write down every user's password.** Plaintext passwords get hashed and
   removed from the file on first start. Hashes can't be turned back into
   passwords.
3. **Install the CI workflow** (once per repo). The new file replaces the
   existing one, so use `-f`:
   ```bash
   git mv -f deploy/github-workflow-publish.yml .github/workflows/docker-publish.yml
   git commit -m "CI: run tests before publishing the image" && git push
   ```
   From then on the Docker image is only published when the test suite passes.
4. **Replace the container**, then check persistence:
   ```bash
   docker compose pull && docker compose up -d
   docker exec <container> ls -la /app/data      # netmon.db, config.yaml, auth_secret.key
   docker compose down && docker compose up -d   # destroy and recreate
   ```
   Your devices, users and history must still be there after the second `up`.
5. **Log in again** (everyone is logged out once).
6. **Look at HTTPS checks.** Internal hosts with a self-signed or private-CA
   certificate now report failures until you add `ca_bundle` or
   `verify_tls: false` to them (section 4).
7. **Expect SLA numbers to change.** The old numbers were wrong (section 5).
8. **If you use SentryLog's incident timeline**, set `integration.read_token`
   (section 7). Upgrade NetMon before SentryLog. An older NetMon has no feed,
   and SentryLog shows that as an error on the timeline tab.

**Never delete `/app/data/auth_secret.key`.** It signs login tokens, and
deleting it logs everyone out again.

### Rolling back

Older builds read `netmon.db` / `config.yaml` from beside `netmon.py`, not
from `/app/data`, and they can't read hashed passwords. To roll back, restore
the files you backed up in step 1 to the old location and start the old image.
Data recorded after the upgrade stays in `/app/data`, untouched.

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

`max_cycle_seconds` sets the per-cycle deadline. Checks that are still running
at the deadline are not waited for: their results are picked up by the next
cycle (`checks_recovered_late`). A check still in flight is not submitted again
(`checks_skipped_inflight`).

Cancelling a maintenance window now records `cancelled_at` (a new column,
added automatically on start). A cancelled window excuses downtime only up to
the moment it was cancelled.

## Incident timeline feed (for SentryLog)

### 7. New read-only endpoint: `GET /api/integration/events`

SentryLog's Incident Timeline tab pulls device state changes and alerts from
NetMon and interleaves them with its logs. Nothing changes for installs that
don't use it.

Setting up:

```yaml
# NetMon config.yaml
integration:
  read_token: "<long random string>"
# generate: python -c "import secrets; print(secrets.token_urlsafe(32))"
```

Put the same value in SentryLog's `netmon_integration.read_token`. The token is
sent in the `X-Netmon-Integration-Token` header, and it only works on this one
endpoint, for reads. It can't be replayed against the rest of the API. With
`read_token` left empty the endpoint requires a normal user token, like every
other route.

What it returns: state *transitions* (not every check row) and alerts, oldest
first, each with the device `host`. Also `device_hosts` (name -> host for every
requested device NetMon knows, including healthy ones with no transitions) and
`truncated`. Query parameters: `from`, `to`, `device`, `host`, `limit`
(default 500, max 5000).

### 8. Time contract: UTC on the wire

- NetMon stores check times as naive UTC. The feed emits every timestamp as
  UTC with a trailing `Z`.
- `from` / `to` are ISO-8601. Offsets are honoured, and a bound with no offset
  is read as UTC.
- A bound that can't be parsed returns `400`, not a silently empty result.
- `host` only ever narrows the result. It is matched against each event's
  own host *before* the limit is applied. So after a device changes IP,
  asking for the old IP still returns the events recorded on it. Alerts take
  the host the check was running against when the alert fired.
