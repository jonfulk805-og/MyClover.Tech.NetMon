#!/usr/bin/env python3
"""
MyClover.Tech NetMon - license signing (vendor side ONLY).

License keys are Ed25519 signatures. The PRIVATE key never ships with netmon
and never goes into git; netmon.py only embeds the PUBLIC key, so reading the
public source no longer lets anyone mint a Pro/Enterprise key.

Key format:  TIER-UNIQUEID-SIGNATURE
  TIER       PRO or ENT
  UNIQUEID   8+ uppercase hex chars
  SIGNATURE  base32 (no padding) of Ed25519 over b"NETMON-LICENSE-V2|TIER|UNIQUEID"

Where the private key is read from (first match wins):
  1. NETMON_LICENSE_SIGNING_KEY       env var: PEM text, or base64 of the raw 32-byte seed
  2. NETMON_LICENSE_SIGNING_KEY_FILE  env var: path to a PEM file
  3. license_signing_key.pem next to this file (gitignored)

Create the key pair once with:  python generate_key.py --init
"""
import base64
import os
import re
import secrets
from pathlib import Path

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey, Ed25519PublicKey)
    from cryptography.exceptions import InvalidSignature
    HAS_CRYPTO = True
except ImportError:  # pragma: no cover - exercised only without the dependency
    HAS_CRYPTO = False

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_KEY_FILE = BASE_DIR / "license_signing_key.pem"
NETMON_PY = BASE_DIR / "netmon.py"

SIGNED_PREFIX = b"NETMON-LICENSE-V2|"
VALID_TIERS = ("PRO", "ENT")
_PUBKEY_RE = re.compile(r'^(_LICENSE_PUBLIC_KEY_B64\s*=\s*)"([A-Za-z0-9+/=]*)"',
                        re.MULTILINE)


class LicenseSigningError(RuntimeError):
    """Raised when a license cannot be issued safely."""


def _require_crypto():
    if not HAS_CRYPTO:
        raise LicenseSigningError(
            "The 'cryptography' package is required: pip install cryptography")


def signed_payload(tier_code, unique_id):
    return SIGNED_PREFIX + ("%s|%s" % (tier_code.upper(), unique_id.upper())).encode("ascii")


def encode_signature(sig):
    return base64.b32encode(sig).decode("ascii").rstrip("=")


def decode_signature(text):
    text = text.strip().upper()
    return base64.b32decode(text + "=" * (-len(text) % 8))


def public_key_b64(private_key):
    raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw)
    return base64.b64encode(raw).decode("ascii")


def private_key_pem(private_key):
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption())


def _parse_private_key(text):
    text = text.strip()
    if "BEGIN" in text:
        key = serialization.load_pem_private_key(text.encode("ascii"), password=None)
    else:
        key = Ed25519PrivateKey.from_private_bytes(base64.b64decode(text))
    if not isinstance(key, Ed25519PrivateKey):
        raise LicenseSigningError("License signing key is not an Ed25519 key")
    return key


def load_private_key():
    """Load the vendor signing key or raise LicenseSigningError."""
    _require_crypto()
    env = os.environ.get("NETMON_LICENSE_SIGNING_KEY", "").strip()
    if env:
        try:
            return _parse_private_key(env)
        except LicenseSigningError:
            raise
        except Exception as exc:
            raise LicenseSigningError("NETMON_LICENSE_SIGNING_KEY is invalid: %s" % exc)
    path = Path(os.environ.get("NETMON_LICENSE_SIGNING_KEY_FILE", "").strip()
                or DEFAULT_KEY_FILE)
    if not path.exists():
        raise LicenseSigningError(
            "No license signing key configured. Run 'python generate_key.py --init' "
            "or set NETMON_LICENSE_SIGNING_KEY / NETMON_LICENSE_SIGNING_KEY_FILE.")
    try:
        return _parse_private_key(path.read_text(encoding="utf-8"))
    except LicenseSigningError:
        raise
    except Exception as exc:
        raise LicenseSigningError("Cannot read license signing key %s: %s" % (path, exc))


def embedded_public_key_b64(netmon_path=None):
    """Public key netmon.py ships with: '' if unset, None if netmon.py absent."""
    netmon_path = netmon_path or NETMON_PY
    try:
        text = Path(netmon_path).read_text(encoding="utf-8")
    except OSError:
        return None
    m = _PUBKEY_RE.search(text)
    return m.group(2) if m else None


def write_embedded_public_key(pub_b64, netmon_path=None):
    """Rewrite the _LICENSE_PUBLIC_KEY_B64 constant in netmon.py."""
    path = Path(netmon_path or NETMON_PY)
    text = path.read_text(encoding="utf-8")
    new_text, n = _PUBKEY_RE.subn(lambda m: '%s"%s"' % (m.group(1), pub_b64), text, count=1)
    if n != 1:
        raise LicenseSigningError("_LICENSE_PUBLIC_KEY_B64 not found in %s" % path)
    with open(str(path), "w", encoding="utf-8", newline="") as f:
        f.write(new_text)


def verify_license_key(key, public_b64):
    """Return 'PRO'/'ENT' if key verifies against public_b64, else None."""
    if not HAS_CRYPTO or not public_b64 or not key or not isinstance(key, str):
        return None
    parts = key.strip().upper().split("-")
    if len(parts) != 3:
        return None
    tier_code, unique_id, sig_text = parts
    if tier_code not in VALID_TIERS or not re.fullmatch(r"[0-9A-F]{8,32}", unique_id):
        return None
    try:
        pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_b64))
        pub.verify(decode_signature(sig_text), signed_payload(tier_code, unique_id))
    except (InvalidSignature, ValueError, TypeError):
        return None
    return tier_code


def generate_license_key(tier_code, unique_id=None, private_key=None,
                         check_embedded=True):
    """Sign a license key. Refuses to issue keys netmon would reject."""
    _require_crypto()
    tier_code = tier_code.upper()
    if tier_code not in VALID_TIERS:
        raise LicenseSigningError("Unknown tier %r" % tier_code)
    unique_id = (unique_id or secrets.token_hex(4)).upper()
    if not re.fullmatch(r"[0-9A-F]{8,32}", unique_id):
        raise LicenseSigningError("Unique id must be 8-32 hex characters")
    private_key = private_key or load_private_key()
    sig = private_key.sign(signed_payload(tier_code, unique_id))
    key = "%s-%s-%s" % (tier_code, unique_id, encode_signature(sig))
    if check_embedded:
        embedded = embedded_public_key_b64()
        if embedded is not None and embedded != public_key_b64(private_key):
            raise LicenseSigningError(
                "Signing key does not match the public key embedded in netmon.py "
                "-- customers would receive keys that netmon rejects.")
    return key


def create_key_pair(key_file=None, force=False):
    """Generate a new key pair, save the private key (0600), return it."""
    _require_crypto()
    key_file = Path(key_file or DEFAULT_KEY_FILE)
    if key_file.exists() and not force:
        raise LicenseSigningError(
            "%s already exists. Use --force to replace it (this invalidates every "
            "license key issued so far)." % key_file)
    private_key = Ed25519PrivateKey.generate()
    key_file.parent.mkdir(parents=True, exist_ok=True)
    with open(str(key_file), "wb") as f:
        f.write(private_key_pem(private_key))
    try:
        os.chmod(str(key_file), 0o600)
    except OSError:
        pass
    return private_key
