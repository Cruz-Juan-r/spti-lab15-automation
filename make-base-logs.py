#!/usr/bin/env python3
"""Generate the Lab 15 baseline logs (instructor-side, standard library only).

Usage: python3 make-base-logs.py [seed]     (default seed: 15)

Writes base-auth.log and base-access.log in the current directory. The logs describe a single
day (15 Mar 2025) of ordinary activity on a small server:

- No attacker has more than 3 failed logins, so nothing crosses the ">10 failures" threshold.
- Failures include both "Failed password for <user>" and "Failed password for invalid user <user>".
- No SQL injection, traversal, XSS or command-injection payloads. A few benign percent-encoded
  requests (%20, %2F) are included so naive "contains %" rules produce false positives.
- Hourly request counts follow a mild daily cycle (about 40 at night, about 130 at midday), so a
  3-sigma detector stays quiet until the engineer injects a spike.

Give each pair a different seed if you want to rule out diffing against a shared baseline.
"""
import random
import sys

seed = int(sys.argv[1]) if len(sys.argv) > 1 else 15
rng = random.Random(seed)
DAY_AUTH = "Mar 15"
DAY_WEB = "15/Mar/2025"


def hms(hour):
    return f"{hour:02d}:{rng.randint(0, 59):02d}:{rng.randint(0, 59):02d}"


# ---- auth.log ----
auth = []
users = ["root", "admin", "ubuntu", "daniel"]
ghosts = ["test", "oracle", "postgres", "guest", "git"]
for _ in range(45):  # scattered background noise: every address fails at most 3 times
    ip = f"{rng.choice([45, 91, 103, 185, 203])}.{rng.randint(1, 254)}.{rng.randint(1, 254)}.{rng.randint(1, 254)}"
    for _ in range(rng.randint(1, 3)):
        who = f"invalid user {rng.choice(ghosts)}" if rng.random() < 0.3 else rng.choice(users)
        auth.append((hms(rng.randint(0, 23)),
                     f"kali sshd[{rng.randint(1000, 9999)}]: Failed password for {who} from {ip} port {rng.randint(40000, 60000)} ssh2"))
for _ in range(20):  # legitimate logins
    h = rng.randint(7, 19)
    auth.append((hms(h),
                 f"kali sshd[{rng.randint(1000, 9999)}]: Accepted publickey for daniel from 192.168.1.1 port {rng.randint(40000, 60000)} ssh2"))
for _ in range(25):  # lines that are neither failures nor successes
    auth.append((hms(rng.randint(0, 23)),
                 f"kali sshd[{rng.randint(1000, 9999)}]: Connection closed by 192.168.1.1 port {rng.randint(40000, 60000)} [preauth]"))
auth.sort()
with open("base-auth.log", "w") as f:
    for t, msg in auth:
        f.write(f"{DAY_AUTH} {t} {msg}\n")

# ---- access.log ----
web = []
ips = ["10.0.0.1", "192.168.1.50", "192.168.1.51", "66.249.66.1", "203.0.113.20", "198.51.100.7"]
weights = [30, 25, 15, 10, 12, 8]
paths = ["/", "/index.html", "/about", "/contact", "/static/main.css", "/static/app.js",
         "/search?q=network%20security", "/docs%2Fintro", "/blog/post-1", "/favicon.ico"]
for hour in range(24):
    base = 40 + 90 * max(0.0, 1 - abs(hour - 13) / 9)  # peak at 13:00, low overnight
    for _ in range(int(base * rng.uniform(0.85, 1.15))):
        status = rng.choices([200, 304, 404, 301], weights=[80, 10, 7, 3])[0]
        web.append((hms(hour),
                    f'{rng.choices(ips, weights)[0]} - - [{DAY_WEB}:{{t}} +0000] "GET {rng.choice(paths)} HTTP/1.1" {status} {rng.randint(200, 5000)}'))
web.sort()
with open("base-access.log", "w") as f:
    for t, line in web:
        f.write(line.format(t=t) + "\n")

print(f"seed={seed}: {len(auth)} auth lines, {len(web)} access lines")
