#!/usr/bin/env python3
"""Lab 15 - Part 3A: SSH authentication-log analysis.

Reads an sshd auth log (syslog format) and reports:
  A. IPs with more than THRESHOLD failed logins, sorted descending.
  B. The set of usernames attackers are guessing (both "Failed password for
     <user>" and "Failed password for invalid user <user>").
  C. The overall failed:successful ratio.
  D. Every address that logged in SUCCESSFULLY after a run of failures
     (the highest-value finding: the guessing may have worked).

Usage:
    python3 auth_analysis.py auth.log [--threshold 10]

Standard library only.
"""
import argparse
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

# "invalid user" is OPTIONAL. A pattern that omits it silently ignores exactly
# the attempts that guess nonexistent accounts.
FAIL_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)
# sshd logs successes as "Accepted password" or "Accepted publickey".
OK_RE = re.compile(
    r"Accepted \w+ for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)


def analyze(path: str, threshold: int) -> dict:
    fails_by_ip: Counter = Counter()
    users: Counter = Counter()
    total_fail = 0
    total_ok = 0
    # Per-IP ordered event stream so we can spot "success after failures".
    events: dict[str, list[str]] = defaultdict(list)

    for line in Path(path).open(encoding="utf-8", errors="replace"):
        m = FAIL_RE.search(line)
        if m:
            total_fail += 1
            fails_by_ip[m.group("ip")] += 1
            users[m.group("user")] += 1
            events[m.group("ip")].append("fail")
            continue
        m = OK_RE.search(line)
        if m:
            total_ok += 1
            events[m.group("ip")].append("ok")

    # A. brute-force sources
    brute = [
        {"ip": ip, "failures": n}
        for ip, n in fails_by_ip.most_common()
        if n > threshold
    ]

    # D. success preceded by at least one failure, from the same address
    breached = []
    for ip, seq in events.items():
        if "ok" in seq:
            first_ok = seq.index("ok")
            if "fail" in seq[:first_ok]:
                breached.append(
                    {"ip": ip, "failures_before_success": seq[:first_ok].count("fail")}
                )

    ratio = (total_fail / total_ok) if total_ok else float("inf")

    return {
        "brute_force_ips": brute,
        "targeted_usernames": users.most_common(),
        "failed_logins": total_fail,
        "successful_logins": total_ok,
        "failed_to_success_ratio": round(ratio, 2) if total_ok else None,
        "success_after_failures": breached,
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="SSH auth-log analysis (Lab 15, Part 3A)")
    ap.add_argument("logfile", help="path to auth.log")
    ap.add_argument("--threshold", type=int, default=10,
                    help="failed-login threshold for brute force (default 10)")
    ap.add_argument("--json", action="store_true", help="print raw JSON instead of a report")
    args = ap.parse_args()

    r = analyze(args.logfile, args.threshold)

    if args.json:
        print(json.dumps(r, indent=2))
        return

    print(f"=== SSH auth analysis: {args.logfile} ===\n")
    print(f"Failed logins: {r['failed_logins']}   Successful: {r['successful_logins']}"
          f"   Ratio (fail:ok): {r['failed_to_success_ratio']}\n")

    print(f"Brute-force sources (> {args.threshold} failures):")
    if r["brute_force_ips"]:
        for row in r["brute_force_ips"]:
            print(f"  {row['ip']:<16} {row['failures']} failures")
    else:
        print("  (none)")

    print("\nTargeted usernames (guess count):")
    for user, n in r["targeted_usernames"]:
        print(f"  {user:<16} {n}")

    print("\n[!] Successful login after a run of failures (highest-value finding):")
    if r["success_after_failures"]:
        for row in r["success_after_failures"]:
            print(f"  {row['ip']:<16} after {row['failures_before_success']} failures")
    else:
        print("  (none)")


if __name__ == "__main__":
    main()
