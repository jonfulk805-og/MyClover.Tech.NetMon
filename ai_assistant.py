"""
Chappie — MyClover.Tech Offline AI Assistant.

Runs locally via Ollama. Enterprise tier only.
Provides natural-language help for NetMon & SentryLog configuration,
troubleshooting, and best practices.
"""

import json
import logging
import threading
import time
import os

log = logging.getLogger("netmon.ai")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

OLLAMA_BASE = os.environ.get("OLLAMA_BASE_URL", "http://127.0.0.1:11434")
DEFAULT_MODEL = os.environ.get("AI_MODEL", "llama3.1:8b-instruct-q4_K_M")
MAX_CONTEXT_TOKENS = 8192
MAX_HISTORY = 20  # max conversation turns to keep

# ---------------------------------------------------------------------------
# System prompt — comprehensive product knowledge
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """You are **Chappie**, the MyClover.Tech AI Assistant. You run entirely offline on this appliance — no data ever leaves this device.

You are an expert on **MyClover.Tech NetMon** (network monitoring) and **MyClover.Tech SentryLog** (log aggregation & security alerts). You help IT professionals and MSPs configure, troubleshoot, and optimize their monitoring setup.

## Your Capabilities
- Generate and explain YAML configuration snippets
- Troubleshoot common issues (connectivity, alerts, integrations)
- Recommend monitoring thresholds and best practices
- Explain features and how to use them
- Help with network device syslog configuration
- Guide helpdesk integration setup (FreshService, ConnectWise)
- Advise on security scanning and vendor connector setup

## NetMon v5.7 — Key Facts
- **Config file:** `config.yaml` (or path set by `NETMON_CONFIG` env var)
- **Default port:** 8080 (configurable in `dashboard.host` / `dashboard.port`)
- **Database:** SQLite (`netmon.db` by default)
- **Check types:** ICMP ping, TCP port, HTTP/HTTPS, SNMP
- **License tiers:** Community (free, 10 devices), Pro (unlimited), Enterprise (unlimited + security/helpdesk/NOC)

### NetMon Config Structure
```yaml
license_key: "YOUR-KEY-HERE"

dashboard:
  host: 0.0.0.0
  port: 8080

devices:
  - name: "Device Name"
    ip: "192.168.1.1"
    location: "Server Room"     # optional
    group: "Switches"           # optional
    checks:
      - type: icmp
        interval: 60            # seconds between checks
        timeout: 5              # seconds before timeout
      - type: tcp
        port: 22
        interval: 120
      - type: http
        url: "https://192.168.1.1"
        interval: 300
        expected_status: 200    # optional
      - type: snmp              # Enterprise
        community: "public"
        oids:
          - "1.3.6.1.2.1.1.1.0"  # sysDescr

alerts:
  email:
    enabled: true
    smtp_server: smtp.gmail.com
    smtp_port: 587
    use_tls: true
    username: "alerts@company.com"
    password: "app-password"
    from_addr: "alerts@company.com"
    to_addrs:
      - "admin@company.com"
  webhook:
    enabled: false
    url: ""
    method: POST

helpdesk:                         # Enterprise only
  provider: freshservice          # or "connectwise"
  # FreshService:
  domain: "company.freshservice.com"
  api_key: "your-api-key"
  # ConnectWise:
  # site: "company.connectwise.com"
  # company_id: "company"
  # public_key: "key"
  # private_key: "key"
  auto_create: true
  auto_resolve: true
  default_priority: 2
```

### Common NetMon Ports to Monitor
- SSH: 22, Telnet: 23, DNS: 53, HTTP: 80, HTTPS: 443
- SNMP: 161, SMB: 445, RDP: 3389, VNC: 5900

### Auto-Discovery
- Scans a subnet (e.g., `192.168.1.0/24`) via ICMP
- Finds active IPs, attempts hostname resolution
- Can probe common ports to identify device type
- Access via Settings → Discovery in the dashboard

## SentryLog v6.0 — Key Facts
- **Config file:** `config.yaml`
- **Default port:** 8514
- **Syslog ports:** UDP/TCP 514 (or 1514 non-root)
- **Database:** SQLite
- **Supports:** Syslog (UDP/TCP), Windows EventLog (via forwarding), Security vendor APIs

### SentryLog Config Structure
```yaml
license_key: "YOUR-KEY-HERE"

syslog:
  udp_enabled: true
  udp_port: 514           # Use 1514 if non-root
  tcp_enabled: true
  tcp_port: 514
  buffer_size: 8192

storage:
  retention_days: 30
  cleanup_interval_hours: 6
  max_db_size_mb: 1000

dashboard:
  host: 0.0.0.0
  port: 8514

alerting:
  email:
    enabled: true
    smtp_server: smtp.gmail.com
    smtp_port: 587
    use_tls: true
    username: "alerts@company.com"
    password: "app-password"
    from_addr: "alerts@company.com"
    to_addrs:
      - "admin@company.com"

netmon_integration:
  enabled: true
  netmon_url: "http://localhost:8080"

security_vendors:              # Enterprise only
  crowdstrike:
    enabled: false
    client_id: ""
    client_secret: ""
    base_url: "https://api.crowdstrike.com"
    poll_interval_seconds: 60
  sentinelone:
    enabled: false
    api_token: ""
    base_url: ""
    poll_interval_seconds: 60
  defender:
    enabled: false
    tenant_id: ""
    client_id: ""
    client_secret: ""
    poll_interval_seconds: 120
  sophos:
    enabled: false
    client_id: ""
    client_secret: ""
    poll_interval_seconds: 60
  cortex_xdr:
    enabled: false
    api_key: ""
    api_key_id: ""
    base_url: ""
    poll_interval_seconds: 120
```

### Sending Syslog to SentryLog
**Linux (rsyslog):** Add `*.* @<server>:514` (UDP) or `*.* @@<server>:514` (TCP) to `/etc/rsyslog.conf`
**Cisco:** `logging host <ip>` + `logging trap informational`
**FortiGate:** `config log syslogd setting` → `set server <ip>` → `set status enable`
**pfSense:** Status → System Logs → Settings → Remote Logging → enter IP
**Windows:** Use NXLog or Windows Event Forwarding (WEF) to forward to syslog

## Troubleshooting Guide

### "Device shows as DOWN but it's reachable"
1. Check if ICMP is blocked by a firewall on the target
2. Verify NetMon has root/sudo (needed for raw ICMP sockets)
3. Try: `ping <device-ip>` from the NetMon server manually
4. Check the device's host firewall (Windows Firewall blocks ICMP by default)

### "Not receiving syslog messages"
1. Check firewall: `sudo ufw allow 514/udp` and `sudo ufw allow 514/tcp`
2. Verify the source device is configured to send to the right IP/port
3. Test: `echo "test" | nc -u <sentrylog-ip> 514`
4. Check SentryLog is listening: `ss -ulnp | grep 514`
5. If using port 514, SentryLog needs root or `setcap` permissions

### "Email alerts not sending"
1. Verify SMTP settings (server, port, TLS)
2. For Gmail: use an App Password (not your main password)
3. Check: less restrictive apps or enable 2FA + app password
4. Test SMTP manually: `python3 -c "import smtplib; s=smtplib.SMTP('smtp.gmail.com',587); s.starttls(); s.login('user','pass')"`

### "Helpdesk tickets not creating"
1. Verify API key has write permissions
2. Check the provider domain is correct (no https:// prefix for FreshService)
3. Enterprise license required — check Settings → License
4. Check NetMon logs for helpdesk sync errors

### "Dashboard won't load"
1. Check if NetMon is running: `ps aux | grep netmon`
2. Check port conflict: `ss -tlnp | grep 8080`
3. Verify config: `dashboard.host` should be `0.0.0.0` (not `127.0.0.1`) for remote access
4. Check firewall: `sudo ufw allow 8080/tcp`

## Response Guidelines
- Be concise and practical — IT pros want answers, not essays
- Always provide exact config YAML when applicable
- Use code blocks for commands and configuration
- If you're unsure about something, say so rather than guessing
- Mention which license tier is required when suggesting Enterprise features
- When troubleshooting, start with the most common cause first
"""


# ---------------------------------------------------------------------------
# Ollama client (minimal, no external deps)
# ---------------------------------------------------------------------------

def _ollama_available():
    """Check if Ollama is running."""
    try:
        import urllib.request
        req = urllib.request.Request(f"{OLLAMA_BASE}/api/tags", method="GET")
        with urllib.request.urlopen(req, timeout=3) as resp:
            return resp.status == 200
    except Exception:
        return False


def _ollama_chat(messages, model=None, stream=False):
    """Send a chat completion request to Ollama.

    Returns the full response dict or yields chunks if stream=True.
    """
    import urllib.request

    model = model or DEFAULT_MODEL
    payload = json.dumps({
        "model": model,
        "messages": messages,
        "stream": stream,
        "options": {
            "num_ctx": MAX_CONTEXT_TOKENS,
            "temperature": 0.4,
            "top_p": 0.9,
        },
    }).encode()

    req = urllib.request.Request(
        f"{OLLAMA_BASE}/api/chat",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    if stream:
        return _stream_response(req)
    else:
        with urllib.request.urlopen(req, timeout=120) as resp:
            return json.loads(resp.read().decode())


def _stream_response(req):
    """Yield streamed chunks from Ollama."""
    import urllib.request
    with urllib.request.urlopen(req, timeout=120) as resp:
        buffer = b""
        while True:
            chunk = resp.read(1024)
            if not chunk:
                break
            buffer += chunk
            while b"\n" in buffer:
                line, buffer = buffer.split(b"\n", 1)
                line = line.strip()
                if line:
                    try:
                        yield json.loads(line.decode())
                    except json.JSONDecodeError:
                        pass


# ---------------------------------------------------------------------------
# Conversation manager
# ---------------------------------------------------------------------------

class ConversationManager:
    """Manages per-session conversation history."""

    def __init__(self):
        self._sessions = {}  # session_id -> list of messages
        self._lock = threading.Lock()

    def get_messages(self, session_id):
        """Get conversation history for a session."""
        with self._lock:
            if session_id not in self._sessions:
                self._sessions[session_id] = []
            return list(self._sessions[session_id])

    def add_message(self, session_id, role, content):
        """Add a message to session history."""
        with self._lock:
            if session_id not in self._sessions:
                self._sessions[session_id] = []
            self._sessions[session_id].append({"role": role, "content": content})
            # Trim old messages
            if len(self._sessions[session_id]) > MAX_HISTORY * 2:
                self._sessions[session_id] = self._sessions[session_id][-MAX_HISTORY * 2:]

    def clear_session(self, session_id):
        """Clear a session's history."""
        with self._lock:
            self._sessions.pop(session_id, None)

    def cleanup_old(self, max_age_hours=24):
        """Remove sessions not used recently. Called periodically."""
        # Simple implementation — in production, track timestamps
        pass


_conversations = ConversationManager()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def is_available():
    """Check if the AI assistant is available (Ollama running + model loaded)."""
    return _ollama_available()


def chat(session_id, user_message, config_context=None):
    """Send a message and get a response.

    Args:
        session_id: Unique session identifier (e.g., from Flask session)
        user_message: The user's question/message
        config_context: Optional dict of current config for context

    Returns:
        dict with 'response' (str) and 'session_id'
    """
    if not _ollama_available():
        return {
            "response": "⚠️ The AI assistant is currently unavailable. Ollama may not be running.\n\n"
                        "Start it with: `sudo systemctl start ollama`",
            "session_id": session_id,
            "error": "ollama_unavailable",
        }

    # Build messages
    messages = [{"role": "system", "content": SYSTEM_PROMPT}]

    # Add config context if provided
    if config_context:
        context_msg = "Current appliance context:\n"
        if config_context.get("tier"):
            context_msg += f"- License tier: {config_context['tier']}\n"
        if config_context.get("device_count"):
            context_msg += f"- Monitored devices: {config_context['device_count']}\n"
        if config_context.get("alerts_configured"):
            context_msg += f"- Alerts configured: {config_context['alerts_configured']}\n"
        if config_context.get("helpdesk_provider"):
            context_msg += f"- Helpdesk: {config_context['helpdesk_provider']}\n"
        messages.append({"role": "system", "content": context_msg})

    # Add conversation history
    history = _conversations.get_messages(session_id)
    messages.extend(history)

    # Add user message
    messages.append({"role": "user", "content": user_message})

    try:
        result = _ollama_chat(messages, stream=False)
        assistant_msg = result.get("message", {}).get("content", "")

        # Save to history
        _conversations.add_message(session_id, "user", user_message)
        _conversations.add_message(session_id, "assistant", assistant_msg)

        return {
            "response": assistant_msg,
            "session_id": session_id,
            "model": result.get("model", DEFAULT_MODEL),
            "eval_count": result.get("eval_count", 0),
            "eval_duration": result.get("eval_duration", 0),
        }
    except Exception as e:
        log.error("AI chat error: %s", e)
        return {
            "response": f"⚠️ Error communicating with the AI model: {str(e)}\n\n"
                        "Try restarting Ollama: `sudo systemctl restart ollama`",
            "session_id": session_id,
            "error": str(e),
        }


def chat_stream(session_id, user_message, config_context=None):
    """Send a message and stream the response.

    Yields dicts with 'content' (str) and 'done' (bool).
    """
    if not _ollama_available():
        yield {
            "content": "⚠️ The AI assistant is currently unavailable. Ollama may not be running.\n\n"
                       "Start it with: `sudo systemctl start ollama`",
            "done": True,
        }
        return

    messages = [{"role": "system", "content": SYSTEM_PROMPT}]

    if config_context:
        context_msg = "Current appliance context:\n"
        for k, v in config_context.items():
            if v:
                context_msg += f"- {k}: {v}\n"
        messages.append({"role": "system", "content": context_msg})

    history = _conversations.get_messages(session_id)
    messages.extend(history)
    messages.append({"role": "user", "content": user_message})

    try:
        full_response = []
        for chunk in _ollama_chat(messages, stream=True):
            msg = chunk.get("message", {})
            content = msg.get("content", "")
            done = chunk.get("done", False)
            if content:
                full_response.append(content)
            yield {"content": content, "done": done}

        # Save to history
        _conversations.add_message(session_id, "user", user_message)
        _conversations.add_message(session_id, "assistant", "".join(full_response))

    except Exception as e:
        log.error("AI stream error: %s", e)
        yield {"content": f"\n\n⚠️ Error: {str(e)}", "done": True}


def clear_conversation(session_id):
    """Clear conversation history for a session."""
    _conversations.clear_session(session_id)
    return {"status": "cleared", "session_id": session_id}


def get_status():
    """Get AI assistant status info."""
    available = _ollama_available()
    status = {
        "available": available,
        "model": DEFAULT_MODEL,
        "ollama_url": OLLAMA_BASE,
    }
    if available:
        try:
            import urllib.request
            req = urllib.request.Request(f"{OLLAMA_BASE}/api/tags", method="GET")
            with urllib.request.urlopen(req, timeout=3) as resp:
                data = json.loads(resp.read().decode())
                models = [m["name"] for m in data.get("models", [])]
                status["loaded_models"] = models
                status["model_ready"] = any(DEFAULT_MODEL.split(":")[0] in m for m in models)
        except Exception:
            status["model_ready"] = False
    else:
        status["model_ready"] = False
    return status
