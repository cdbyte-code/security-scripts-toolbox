#!/usr/bin/env python3
"""Summarise SSH authentication failures by source IP and flag
IPs that succeeded after many failures (possible brute-force compromise)."""
import argparse
import re
import sys
from collections import Counter, defaultdict

FAILED = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>[0-9a-fA-F:.]+) port"
)
ACCEPTED = re.compile(
    r"Accepted (?:password|publickey) for (?P<user>\S+) "
    r"from (?P<ip>[0-9a-fA-F:.]+) port"
)


def analyse(path, threshold):
    failures = Counter()
    users = defaultdict(set)
    compromised = []  # (ip, user, failures_before_success)

    with open(path, errors="replace") as fh:
        for line in fh:
            m = FAILED.search(line)
            if m:
                failures[m["ip"]] += 1
                users[m["ip"]].add(m["user"])
                continue
            m = ACCEPTED.search(line)
            if m and failures[m["ip"]] >= threshold:
                compromised.append((m["ip"], m["user"], failures[m["ip"]]))
    return failures, users, compromised


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("logfile", help="path to auth.log")
    ap.add_argument("-t", "--threshold", type=int, default=5,
                    help="failures before a success counts as suspicious")
    args = ap.parse_args()

    try:
        failures, users, compromised = analyse(args.logfile, args.threshold)
    except OSError as e:
        sys.exit(f"Error: {e}")

    print(f"{'Failures':>8}  {'Source IP':<18} Accounts targeted")
    for ip, n in failures.most_common():
        print(f"{n:>8}  {ip:<18} {', '.join(sorted(users[ip]))}")

    print()
    if compromised:
        for ip, user, n in compromised:
            print(f"[!] {ip} logged in as '{user}' after {n} failures "
                  f"-> possible compromise, escalate")
    else:
        print("No success-after-failures pattern found.")


if __name__ == "__main__":
    main()
