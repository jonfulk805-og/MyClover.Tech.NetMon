#!/usr/bin/env python3
"""
Sample plugin: Check disk space on the local machine.
Usage: python check_disk_space.py --host <host>
Note: This checks the LOCAL machine's disk, not the remote host.
Customize for remote checks via SSH/SNMP.

Output: JSON line with status, message, response_ms
"""
import argparse
import json
import shutil
import time

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="localhost")
    parser.add_argument("--path", default="/")
    parser.add_argument("--warn", type=float, default=80.0, help="Warning threshold %")
    parser.add_argument("--crit", type=float, default=90.0, help="Critical threshold %")
    args = parser.parse_args()

    start = time.time()
    try:
        usage = shutil.disk_usage(args.path)
        pct = 100.0 * usage.used / usage.total
        elapsed = (time.time() - start) * 1000

        if pct >= args.crit:
            status = "CRITICAL"
        elif pct >= args.warn:
            status = "WARNING"
        else:
            status = "OK"

        msg = "Disk %.1f%% used (%.1f GB / %.1f GB)" % (
            pct, usage.used / (1024**3), usage.total / (1024**3))

        print(json.dumps({
            "status": status,
            "message": msg,
            "response_ms": round(elapsed, 2),
        }))
    except Exception as e:
        print(json.dumps({
            "status": "CRITICAL",
            "message": "Error: %s" % e,
            "response_ms": None,
        }))

if __name__ == "__main__":
    main()
