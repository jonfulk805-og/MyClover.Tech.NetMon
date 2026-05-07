#!/usr/bin/env python3
"""
MyClover.Tech.netmon - License Key Generator

Usage:
    python generate_key.py --tier pro --id CUST001
    python generate_key.py --tier ent --id CUST001
    python generate_key.py --tier pro --batch 10

Generates HMAC-SHA256 license keys that work with netmon's offline validation.
"""
import argparse
import hashlib
import secrets
import sys

# Must match _LICENSE_SECRET in netmon.py
LICENSE_SECRET = b"clovertech-netmon-2026-salt"


def generate_key(tier_code, unique_id):
    """Generate a single license key."""
    payload = "%s-%s" % (tier_code.upper(), unique_id.upper())
    sig = hashlib.sha256(LICENSE_SECRET + payload.encode("utf-8")).hexdigest()[:16]
    return "%s-%s" % (payload, sig.upper())


def generate_unique_id():
    """Generate a random 8-character unique ID."""
    return secrets.token_hex(4).upper()


def main():
    parser = argparse.ArgumentParser(description="Generate netmon license keys")
    parser.add_argument("--tier", required=True, choices=["pro", "ent"],
                        help="License tier: pro or ent (enterprise)")
    parser.add_argument("--id", default=None,
                        help="Unique ID for the key (auto-generated if omitted)")
    parser.add_argument("--batch", type=int, default=1,
                        help="Generate multiple keys")
    args = parser.parse_args()

    tier = args.tier.upper()
    if tier == "ENT":
        tier_label = "Enterprise"
    else:
        tier_label = "Pro"

    keys = []
    for i in range(args.batch):
        uid = args.id or generate_unique_id()
        if args.batch > 1 and not args.id:
            uid = generate_unique_id()
        key = generate_key(tier, uid)
        keys.append(key)

    print("\n  MyClover.Tech.netmon License Key Generator")
    print("  " + "=" * 42)
    print("  Tier: %s" % tier_label)
    print()
    for k in keys:
        print("  %s" % k)
    print()
    print("  Paste into Settings > License > Activate")
    print()


if __name__ == "__main__":
    main()
