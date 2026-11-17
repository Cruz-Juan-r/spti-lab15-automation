#!/usr/bin/env python3
"""Lab 15 - Part 0/3 (ENGINEER): plant findings into the baseline logs.

Reads base-auth.log and base-access.log, appends the planted activity, sorts
each file by time (every line is the same day, so a plain text sort orders
them) and writes auth.log and access.log. Also writes planted.json (the answer
key the engineer keeps to score the analyst).

    python3 make-attack-logs.py

Standard library only. Change ONLY the marked parameters.
"""
import json
import random

# ----------------------- ENGINEER: change everything below -----------------
ATTACKERS = {"185.220.101.5": 60, "45.33.32.156": 35}  # attacker IP -> failed logins
INVALID_SHARE = 0.4          # share of failures that target nonexistent accounts
BREACHED = "185.220.101.5"   # this attacker finishes with a successful login
SPIKE_HOUR = 3               # hour of the traffic spike (0-23)
SPIKE_SIZE = 900             # extra requests in that hour
SPIKE_IP = "198.51.100.99"   # source of the spike
ATTACKS = [                  # one of each family, percent-encoded
    "/?id=1'%20UNION%20SELECT%201,2,3--",
    "/admin/..%2f..%2f..%2fetc/passwd",
    "/search?q=%3Cscript%3Ealert(1)%3C/script%3E",
    "/cgi-bin/test.cgi?cmd=id%3Bcat%20/etc/passwd",
    # --- custom payloads of your own (meant to defeat a first-draft pattern) ---
    "/p?q=1%2527%2520UNION%2520SELECT%2520password--",   # double-encoded SQLi
    "/s?q=1+UN/**/ION+SeLeCt+1,2",                        # comment-split + mixed case + "+"
]
CUSTOM = [ATTACKS[-2], ATTACKS[-1]]   # which ones to flag as custom in planted.json
# --------------------------- end of parameters -----------------------------


def stamp() -> str:
    return f"{random.randint(0,23):02d}:{random.randint(0,59):02d}:{random.randint(0,59):02d}"


def main() -> None:
    # ---- auth.log ----
    auth = open("base-auth.log").read().splitlines()
    invalid_lines = 0
    for ip, n in ATTACKERS.items():
        for _ in range(n):
            if random.random() < INVALID_SHARE:
                who = f"invalid user {random.choice(['test', 'oracle', 'admin1'])}"
                invalid_lines += 1
            else:
                who = "root"
            auth.append(
                f"Mar 15 {stamp()} kali sshd[2200]: Failed password for {who} "
                f"from {ip} port {random.randint(40000,60000)} ssh2"
            )
    auth.append(
        f"Mar 15 23:50:00 kali sshd[2201]: Accepted password for root "
        f"from {BREACHED} port 51000 ssh2"
    )
    with open("auth.log", "w") as f:
        f.write("\n".join(sorted(auth)) + "\n")

    # ---- access.log ----
    web = open("base-access.log").read().splitlines()
    for _ in range(SPIKE_SIZE):
        t = f"{SPIKE_HOUR:02d}:{random.randint(0,59):02d}:{random.randint(0,59):02d}"
        web.append(
            f'{SPIKE_IP} - - [15/Mar/2025:{t} +0000] "GET / HTTP/1.1" 200 '
            f'{random.randint(200,5000)}'
        )
    for p in ATTACKS:
        for ip in ATTACKERS:
            web.append(
                f'{ip} - - [15/Mar/2025:{stamp()} +0000] "GET {p} HTTP/1.1" '
                f'{random.choice([200,403,500])} {random.randint(200,900)}'
            )
    with open("access.log", "w") as f:
        f.write("\n".join(sorted(web)) + "\n")

    # ---- planted.json (answer key) ----
    planted = {
        "attacker_ips": ATTACKERS,
        "invalid_user_lines_added": invalid_lines,
        "breached_ip": BREACHED,
        "spike_hour": f"{SPIKE_HOUR:02d}:00",
        "spike_ip": SPIKE_IP,
        "attack_paths": ATTACKS,
        "custom_payloads": CUSTOM,
    }
    with open("planted.json", "w") as f:
        json.dump(planted, f, indent=2)

    print(f"auth.log, access.log, planted.json written "
          f"({invalid_lines} invalid-user lines, spike hour {SPIKE_HOUR:02d}:00)")


if __name__ == "__main__":
    main()
