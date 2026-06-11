"""
Chappie — MyClover.Tech Offline AI Assistant.

Multi-provider support: Ollama (local), OpenAI-compatible APIs,
and Anthropic Claude. Enterprise tier only.
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
# Provider constants
# ---------------------------------------------------------------------------

PROVIDER_OLLAMA = "ollama"
PROVIDER_OPENAI = "openai"
PROVIDER_ANTHROPIC = "anthropic"

SUPPORTED_PROVIDERS = [PROVIDER_OLLAMA, PROVIDER_OPENAI, PROVIDER_ANTHROPIC]


def _normalize_url(url, default_scheme="http"):
    """Ensure URL has a scheme (http/https). Auto-prepends if missing."""
    url = url.strip().rstrip("/")
    if url and not url.startswith(("http://", "https://")):
        url = f"{default_scheme}://{url}"
    return url


# ---------------------------------------------------------------------------
# Default configuration (overridden by config.yaml at runtime)
# ---------------------------------------------------------------------------

_ai_config = {
    "provider": os.environ.get("AI_PROVIDER", PROVIDER_OLLAMA),
    "ollama": {
        "base_url": os.environ.get("OLLAMA_BASE_URL", "http://127.0.0.1:11434"),
        "model": os.environ.get("AI_MODEL", "llama3.1:8b-instruct-q4_K_M"),
    },
    "openai": {
        "base_url": os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1"),
        "api_key": os.environ.get("OPENAI_API_KEY", ""),
        "model": os.environ.get("OPENAI_MODEL", "gpt-4o-mini"),
    },
    "anthropic": {
        "base_url": os.environ.get("ANTHROPIC_BASE_URL", "https://api.anthropic.com"),
        "api_key": os.environ.get("ANTHROPIC_API_KEY", ""),
        "model": os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-20250514"),
    },
}
_ai_config_lock = threading.Lock()

MAX_CONTEXT_TOKENS = 8192
MAX_HISTORY = 20  # max conversation turns to keep

# ---------------------------------------------------------------------------
# Configuration management
# ---------------------------------------------------------------------------

def get_config():
    """Return a copy of the current AI config."""
    with _ai_config_lock:
        return json.loads(json.dumps(_ai_config))


def update_config(new_cfg):
    """Update AI config from a dict (typically from config.yaml)."""
    with _ai_config_lock:
        if "provider" in new_cfg:
            _ai_config["provider"] = new_cfg["provider"]
        for prov in SUPPORTED_PROVIDERS:
            if prov in new_cfg and isinstance(new_cfg[prov], dict):
                if prov not in _ai_config:
                    _ai_config[prov] = {}
                _ai_config[prov].update(new_cfg[prov])


def _get_active_provider():
    """Return the active provider name."""
    with _ai_config_lock:
        return _ai_config.get("provider", PROVIDER_OLLAMA)


def _get_provider_config(provider=None):
    """Return config dict for the given (or active) provider."""
    with _ai_config_lock:
        prov = provider or _ai_config.get("provider", PROVIDER_OLLAMA)
        return prov, dict(_ai_config.get(prov, {}))


# ---------------------------------------------------------------------------
# System prompt — comprehensive product knowledge
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """You are **Chappie**, the MyClover.Tech AI Assistant. You help IT professionals and MSPs configure, troubleshoot, and optimize their monitoring setup.

You are an expert on **MyClover.Tech NetMon** (network monitoring) and **MyClover.Tech SentryLog** (log aggregation & security alerts).

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
  domain: "company.freshservice.com"
  api_key: "your-api-key"
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
# Ollama client
# ---------------------------------------------------------------------------

def _ollama_available(cfg=None):
    """Check if Ollama is running."""
    if cfg is None:
        _, cfg = _get_provider_config(PROVIDER_OLLAMA)
    base = _normalize_url(cfg.get("base_url", "http://127.0.0.1:11434"))
    try:
        import urllib.request
        req = urllib.request.Request(f"{base}/api/tags", method="GET")
        with urllib.request.urlopen(req, timeout=3) as resp:
            return resp.status == 200
    except Exception:
        return False


def _ollama_chat(messages, cfg=None, stream=False):
    """Send a chat completion request to Ollama."""
    import urllib.request

    if cfg is None:
        _, cfg = _get_provider_config(PROVIDER_OLLAMA)
    base = _normalize_url(cfg.get("base_url", "http://127.0.0.1:11434"))
    model = cfg.get("model", "llama3.1:8b-instruct-q4_K_M")

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
        f"{base}/api/chat",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    if stream:
        return _ollama_stream(req)
    else:
        with urllib.request.urlopen(req, timeout=120) as resp:
            return json.loads(resp.read().decode())


def _ollama_stream(req):
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
# OpenAI-compatible client (works with OpenAI, Azure, local servers, etc.)
# ---------------------------------------------------------------------------

def _openai_available(cfg=None):
    """Check if an OpenAI-compatible endpoint is reachable and configured."""
    if cfg is None:
        _, cfg = _get_provider_config(PROVIDER_OPENAI)
    api_key = cfg.get("api_key", "")
    base_url = cfg.get("base_url", "")
    if not api_key or not base_url:
        return False
    try:
        import urllib.request
        req = urllib.request.Request(
            f"{base_url.rstrip('/')}/models",
            method="GET",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status == 200
    except Exception:
        # Some OpenAI-compatible servers don't support /models — that's OK
        # as long as we have a key and URL, we'll try chat
        return bool(api_key and base_url)


def _openai_chat(messages, cfg=None, stream=False):
    """Send a chat completion to an OpenAI-compatible API."""
    import urllib.request

    if cfg is None:
        _, cfg = _get_provider_config(PROVIDER_OPENAI)
    base_url = cfg.get("base_url", "https://api.openai.com/v1").rstrip("/")
    api_key = cfg.get("api_key", "")
    model = cfg.get("model", "gpt-4o-mini")

    payload = json.dumps({
        "model": model,
        "messages": messages,
        "temperature": 0.4,
        "top_p": 0.9,
        "stream": stream,
    }).encode()

    req = urllib.request.Request(
        f"{base_url}/chat/completions",
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
        method="POST",
    )

    if stream:
        return _openai_stream(req)
    else:
        with urllib.request.urlopen(req, timeout=120) as resp:
            data = json.loads(resp.read().decode())
            return {
                "message": {"content": data["choices"][0]["message"]["content"]},
                "model": data.get("model", model),
                "eval_count": data.get("usage", {}).get("completion_tokens", 0),
            }


def _openai_stream(req):
    """Yield streamed chunks from an OpenAI-compatible API."""
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
                if not line or line == b"data: [DONE]":
                    if line == b"data: [DONE]":
                        yield {"message": {"content": ""}, "done": True}
                    continue
                if line.startswith(b"data: "):
                    try:
                        data = json.loads(line[6:].decode())
                        delta = data.get("choices", [{}])[0].get("delta", {})
                        content = delta.get("content", "")
                        done = data.get("choices", [{}])[0].get("finish_reason") is not None
                        yield {"message": {"content": content}, "done": done}
                    except (json.JSONDecodeError, IndexError, KeyError):
                        pass


# ---------------------------------------------------------------------------
# Anthropic client
# ---------------------------------------------------------------------------

def _anthropic_available(cfg=None):
    """Check if Anthropic API is configured and reachable."""
    if cfg is None:
        _, cfg = _get_provider_config(PROVIDER_ANTHROPIC)
    api_key = cfg.get("api_key", "")
    if not api_key:
        return False
    # Anthropic doesn't have a lightweight status endpoint,
    # so we just verify the key is set
    return True


def _anthropic_chat(messages, cfg=None, stream=False):
    """Send a message to the Anthropic API."""
    import urllib.request

    if cfg is None:
        _, cfg = _get_provider_config(PROVIDER_ANTHROPIC)
    base_url = cfg.get("base_url", "https://api.anthropic.com").rstrip("/")
    api_key = cfg.get("api_key", "")
    model = cfg.get("model", "claude-sonnet-4-20250514")

    # Anthropic uses a separate system param, not in messages array
    system_msg = ""
    chat_messages = []
    for m in messages:
        if m["role"] == "system":
            system_msg += m["content"] + "\n"
        else:
            chat_messages.append({"role": m["role"], "content": m["content"]})

    payload = json.dumps({
        "model": model,
        "max_tokens": 4096,
        "system": system_msg.strip(),
        "messages": chat_messages,
        "stream": stream,
    }).encode()

    req = urllib.request.Request(
        f"{base_url}/v1/messages",
        data=payload,
        headers={
            "Content-Type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
        },
        method="POST",
    )

    if stream:
        return _anthropic_stream(req)
    else:
        with urllib.request.urlopen(req, timeout=120) as resp:
            data = json.loads(resp.read().decode())
            content = ""
            for block in data.get("content", []):
                if block.get("type") == "text":
                    content += block["text"]
            return {
                "message": {"content": content},
                "model": data.get("model", model),
                "eval_count": data.get("usage", {}).get("output_tokens", 0),
            }


def _anthropic_stream(req):
    """Yield streamed chunks from Anthropic."""
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
                if not line:
                    continue
                if line.startswith(b"data: "):
                    try:
                        data = json.loads(line[6:].decode())
                        evt_type = data.get("type", "")
                        if evt_type == "content_block_delta":
                            delta = data.get("delta", {})
                            content = delta.get("text", "")
                            yield {"message": {"content": content}, "done": False}
                        elif evt_type == "message_stop":
                            yield {"message": {"content": ""}, "done": True}
                    except (json.JSONDecodeError, KeyError):
                        pass


# ---------------------------------------------------------------------------
# Provider dispatch
# ---------------------------------------------------------------------------

_PROVIDER_MAP = {
    PROVIDER_OLLAMA: {
        "available": _ollama_available,
        "chat": _ollama_chat,
    },
    PROVIDER_OPENAI: {
        "available": _openai_available,
        "chat": _openai_chat,
    },
    PROVIDER_ANTHROPIC: {
        "available": _anthropic_available,
        "chat": _anthropic_chat,
    },
}


def _dispatch_available():
    """Check if the active provider is available."""
    prov, cfg = _get_provider_config()
    handler = _PROVIDER_MAP.get(prov, _PROVIDER_MAP[PROVIDER_OLLAMA])
    return handler["available"](cfg)


def _dispatch_chat(messages, stream=False):
    """Route chat to the active provider."""
    prov, cfg = _get_provider_config()
    handler = _PROVIDER_MAP.get(prov, _PROVIDER_MAP[PROVIDER_OLLAMA])
    return handler["chat"](messages, cfg=cfg, stream=stream)


# ---------------------------------------------------------------------------
# Conversation manager
# ---------------------------------------------------------------------------

class ConversationManager:
    """Manages per-session conversation history."""

    def __init__(self):
        self._sessions = {}  # session_id -> list of messages
        self._lock = threading.Lock()

    def get_messages(self, session_id):
        with self._lock:
            if session_id not in self._sessions:
                self._sessions[session_id] = []
            return list(self._sessions[session_id])

    def add_message(self, session_id, role, content):
        with self._lock:
            if session_id not in self._sessions:
                self._sessions[session_id] = []
            self._sessions[session_id].append({"role": role, "content": content})
            if len(self._sessions[session_id]) > MAX_HISTORY * 2:
                self._sessions[session_id] = self._sessions[session_id][-MAX_HISTORY * 2:]

    def clear_session(self, session_id):
        with self._lock:
            self._sessions.pop(session_id, None)

    def cleanup_old(self, max_age_hours=24):
        pass


_conversations = ConversationManager()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def is_available():
    """Check if the AI assistant is available."""
    return _dispatch_available()


def chat(session_id, user_message, config_context=None):
    """Send a message and get a response."""
    if not _dispatch_available():
        provider = _get_active_provider()
        if provider == PROVIDER_OLLAMA:
            hint = "Start it with: `sudo systemctl start ollama`"
        elif provider == PROVIDER_OPENAI:
            hint = "Check your API key and endpoint URL in Settings → Chappie AI."
        elif provider == PROVIDER_ANTHROPIC:
            hint = "Check your API key in Settings → Chappie AI."
        else:
            hint = "Configure a provider in Settings → Chappie AI."
        return {
            "response": f"⚠️ The AI assistant is currently unavailable ({provider}).\n\n{hint}",
            "session_id": session_id,
            "error": "provider_unavailable",
        }

    messages = [{"role": "system", "content": SYSTEM_PROMPT}]

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

    history = _conversations.get_messages(session_id)
    messages.extend(history)
    messages.append({"role": "user", "content": user_message})

    try:
        result = _dispatch_chat(messages, stream=False)
        assistant_msg = result.get("message", {}).get("content", "")

        _conversations.add_message(session_id, "user", user_message)
        _conversations.add_message(session_id, "assistant", assistant_msg)

        return {
            "response": assistant_msg,
            "session_id": session_id,
            "model": result.get("model", ""),
            "eval_count": result.get("eval_count", 0),
            "eval_duration": result.get("eval_duration", 0),
        }
    except Exception as e:
        log.error("AI chat error: %s", e)
        provider = _get_active_provider()
        return {
            "response": f"⚠️ Error communicating with {provider}: {str(e)}\n\n"
                        "Check your AI provider settings in Settings → Chappie AI.",
            "session_id": session_id,
            "error": str(e),
        }


def chat_stream(session_id, user_message, config_context=None):
    """Send a message and stream the response."""
    if not _dispatch_available():
        provider = _get_active_provider()
        yield {
            "content": f"⚠️ The AI assistant is currently unavailable ({provider}).\n\n"
                       "Configure your provider in Settings → Chappie AI.",
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
        for chunk in _dispatch_chat(messages, stream=True):
            msg = chunk.get("message", {})
            content = msg.get("content", "")
            done = chunk.get("done", False)
            if content:
                full_response.append(content)
            yield {"content": content, "done": done}

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
    provider = _get_active_provider()
    _, cfg = _get_provider_config()
    available = _dispatch_available()

    status = {
        "available": available,
        "provider": provider,
        "model": cfg.get("model", ""),
    }

    if provider == PROVIDER_OLLAMA:
        status["ollama_url"] = _normalize_url(cfg.get("base_url", "http://127.0.0.1:11434"))
        if available:
            try:
                import urllib.request
                base = _normalize_url(cfg.get("base_url", "http://127.0.0.1:11434"))
                req = urllib.request.Request(f"{base}/api/tags", method="GET")
                with urllib.request.urlopen(req, timeout=3) as resp:
                    data = json.loads(resp.read().decode())
                    models = [m["name"] for m in data.get("models", [])]
                    status["loaded_models"] = models
                    model_name = cfg.get("model", "llama3.1").split(":")[0]
                    status["model_ready"] = any(model_name in m for m in models)
            except Exception:
                status["model_ready"] = False
        else:
            status["model_ready"] = False
    elif provider == PROVIDER_OPENAI:
        status["base_url"] = cfg.get("base_url", "")
        status["model_ready"] = available and bool(cfg.get("api_key"))
        status["has_key"] = bool(cfg.get("api_key"))
    elif provider == PROVIDER_ANTHROPIC:
        status["base_url"] = cfg.get("base_url", "")
        status["model_ready"] = available and bool(cfg.get("api_key"))
        status["has_key"] = bool(cfg.get("api_key"))

    return status


def test_connection(provider=None, config=None):
    """Test connection to a specific provider with given config.

    Returns dict with 'ok' (bool) and 'message' (str).
    """
    prov = provider or _get_active_provider()
    cfg = config or _get_provider_config(prov)[1]

    handler = _PROVIDER_MAP.get(prov)
    if not handler:
        return {"ok": False, "message": f"Unknown provider: {prov}"}

    try:
        if not handler["available"](cfg):
            if prov == PROVIDER_OLLAMA:
                return {"ok": False, "message": "Cannot reach Ollama. Is it running?"}
            else:
                return {"ok": False, "message": "API key or endpoint not configured."}

        # Try a minimal chat to verify end-to-end
        test_messages = [
            {"role": "system", "content": "Reply with exactly: OK"},
            {"role": "user", "content": "Test"},
        ]
        result = handler["chat"](test_messages, cfg=cfg, stream=False)
        content = result.get("message", {}).get("content", "")
        if content:
            model = result.get("model", cfg.get("model", "unknown"))
            return {"ok": True, "message": f"Connected successfully. Model: {model}"}
        else:
            return {"ok": False, "message": "Connected but received empty response."}
    except Exception as e:
        return {"ok": False, "message": f"Connection failed: {str(e)}"}
