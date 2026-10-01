#!/usr/bin/env python3
"""
MyClover.Tech.netmon - License Key Generator (vendor side)

One-time setup (creates the private signing key and embeds the PUBLIC key in
netmon.py -- commit netmon.py afterwards, NEVER the .pem file):
    python generate_key.py --init

Issue keys:
    python generate_key.py --tier pro --id CAFE0001
    python generate_key.py --tier ent
    python generate_key.py --tier pro --batch 10

Keys are Ed25519 signatures (see license_signing.py). The private key is read
from NETMON_LICENSE_SIGNING_KEY, NETMON_LICENSE_SIGNING_KEY_FILE, or
license_signing_key.pem next to this script.
"""
import argparse
import sys

import license_signing as ls


def cmd_init(force):
    try:
        private_key = ls.create_key_pair(force=force)
    except ls.LicenseSigningError as exc:
        print("  [ERROR] %s" % exc)
        return 1
    pub = ls.public_key_b64(private_key)
    ls.write_embedded_public_key(pub)
    print()
    print("  [OK] Private key written to %s" % ls.DEFAULT_KEY_FILE)
    print("       Back it up offline (password manager / vault). Do NOT commit it.")
    print("       Losing it means you cannot issue keys netmon accepts.")
    print("  [OK] Public key embedded in netmon.py: %s" % pub)
    print()
    print("  Next: commit + push netmon.py, rebuild the container,")
    print("        then: python generate_key.py --tier ent --id <YOURID>")
    print()
    return 0


def cmd_issue(tier, uid, batch):
    try:
        private_key = ls.load_private_key()
        keys = [ls.generate_license_key(tier, uid if batch == 1 else None,
                                        private_key=private_key)
                for _ in range(batch)]
    except ls.LicenseSigningError as exc:
        print("  [ERROR] %s" % exc)
        return 1
    print("\n  MyClover.Tech.netmon License Key Generator")
    print("  " + "=" * 42)
    print("  Tier: %s" % ("Enterprise" if tier == "ENT" else "Pro"))
    print()
    for k in keys:
        print("  %s" % k)
    print()
    print("  Paste into Settings > License > Activate")
    print()
    return 0


def main():
    parser = argparse.ArgumentParser(description="Generate netmon license keys")
    parser.add_argument("--init", action="store_true",
                        help="Create the signing key pair and embed the public key")
    parser.add_argument("--force", action="store_true",
                        help="With --init: replace an existing key pair "
                             "(invalidates every key issued so far)")
    parser.add_argument("--tier", choices=["pro", "ent"],
                        help="License tier: pro or ent (enterprise)")
    parser.add_argument("--id", default=None,
                        help="Unique hex ID for the key (8-32 chars, random if omitted)")
    parser.add_argument("--batch", type=int, default=1,
                        help="Generate multiple keys (random IDs)")
    args = parser.parse_args()

    if args.init:
        return cmd_init(args.force)
    if not args.tier:
        parser.error("--tier is required (or use --init)")
    return cmd_issue(args.tier.upper(), args.id, max(1, args.batch))


if __name__ == "__main__":
    sys.exit(main())
