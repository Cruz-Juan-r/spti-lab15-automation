#!/usr/bin/env python3
"""Lab 15 - Part 3 B/C/D: web access-log analysis + 3-sigma anomaly detection.

Reads an Apache/Nginx combined-ish access log and reports:
  B/C. Requests matching SQL injection, path traversal, XSS or command-injection
       patterns (the request path is DECODED before matching, so %2e%2e%2f and
       double-encoded / mixed-case payloads are caught too).
  C.   Top 5 IPs by request volume, and the HTTP status-code distribution.
  D.   Hourly-count anomalies via the 3-sigma rule, reporting each z-score.
  E.   Combine A-D into report.md (--report).

Usage:
    python3 log_analysis.py access.log --report report.md
    python3 log_analysis.py access.log --json

Standard library only.
"""
import argparse
import json
import re
import statistics
from collections import Counter
from pathlib import Path
from urllib.parse import unquote

LOG_RE = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<day>\d{2})/(?P<mon>\w+)/(?P<year>\d{4}):'
    r'(?P<hour>\d{2}):\d{2}:\d{2}[^\]]*\] '
    r'"(?P<method>\S+) (?P<path>\S+) [^"]*" (?P<status>\d{3}) (?P<size>\S+)'
)

# Starting point from the theory section, EXTENDED to catch the evasions the
# engineer is asked to plant (comment-split keywords, mixed case via IGNORECASE,
# etc.). Matching happens on the DECODED + normalised path.
ATTACK_RE = re.compile(
    r"(union\s*select"            # SQL injection (incl. UN/**/ION after comment strip)
    r"|select\s+.*\s+from"
    r"|insert\s+into"
    r"|drop\s+table"
    r"|'\s*or\s+'?1"              # ' OR 1 / ' OR '1
    r"|or\s+1\s*=\s*1"
    r"|\.\./|\.\.\\"             # path traversal
    r"|<script|onerror\s*=|javascript:"   # XSS
    r"|;\s*cat\s|;\s*id\b|\|\s*id\b"      # command injection
    r"|cmd=|exec=|shell=|/bin/sh"
    r")",
    re.IGNORECASE,
)


def normalise(path: str) -> str:
    """Decode a request path so evasions reduce to their plain form."""
    p = unquote(unquote(path))   # double pass: %252e -> %2e -> .
    p = p.replace("+", " ")       # + is a space in query strings
    p = re.sub(r"/\*.*?\*/", "", p)  # strip SQL inline comments: UN/**/ION -> UNION
    return p


def analyze(path: str) -> dict:
    ip_counts: Counter = Counter()
    status_counts: Counter = Counter()
    hourly: Counter = Counter()
    suspicious: list[dict] = []
    total = 0
    unparsed = 0

    for line in Path(path).open(encoding="utf-8", errors="replace"):
        line = line.rstrip("\n")
        if not line:
            continue
        m = LOG_RE.match(line)
        if not m:
            unparsed += 1
            continue
        total += 1
        ip = m.group("ip")
        ip_counts[ip] += 1
        status_counts[m.group("status")] += 1
        hourly[f"{m.group('hour')}:00"] += 1

        decoded = normalise(m.group("path"))
        if ATTACK_RE.search(decoded):
            suspicious.append({
                "ip": ip,
                "path": m.group("path"),
                "decoded": decoded,
                "status": m.group("status"),
            })

    anomalies = detect_spikes(hourly)

    return {
        "total_requests": total,
        "unparsed_lines": unparsed,
        "top_ips": ip_counts.most_common(5),
        "status_distribution": dict(sorted(status_counts.items())),
        "suspicious_requests": suspicious,
        "hourly_counts": dict(sorted(hourly.items())),
        "anomalies": anomalies,
    }


def detect_spikes(hourly: Counter) -> list[dict]:
    """3-sigma rule on hourly request counts. Reports each anomalous hour's z."""
    counts = list(hourly.values())
    if len(counts) < 2:
        return []
    mean = statistics.mean(counts)
    stdev = statistics.stdev(counts)
    if stdev == 0:
        return []
    threshold = mean + 3 * stdev
    out = []
    for hour, count in sorted(hourly.items()):
        if count > threshold:
            out.append({
                "hour": hour,
                "count": count,
                "z": round((count - mean) / stdev, 1),
                "threshold": round(threshold, 1),
            })
    return out


def write_report(r: dict, src: str, dest: str) -> None:
    lines = [f"# Web log analysis report", "", f"Source: `{src}`  ",
             f"Total requests parsed: {r['total_requests']} "
             f"(unparsed lines: {r['unparsed_lines']})", ""]

    lines += ["## Suspicious requests (decoded before matching)", ""]
    if r["suspicious_requests"]:
        by_ip = Counter(s["ip"] for s in r["suspicious_requests"])
        lines.append(f"{len(r['suspicious_requests'])} hits from {len(by_ip)} address(es):")
        lines.append("")
        lines.append("| IP | status | request path |")
        lines.append("|----|--------|--------------|")
        for s in r["suspicious_requests"]:
            lines.append(f"| {s['ip']} | {s['status']} | `{s['path']}` |")
    else:
        lines.append("None found.")
    lines.append("")

    lines += ["## Top 5 IPs by request volume", ""]
    for ip, n in r["top_ips"]:
        lines.append(f"- {ip} — {n} requests")
    lines.append("")

    lines += ["## HTTP status distribution", ""]
    for status, n in r["status_distribution"].items():
        lines.append(f"- {status}: {n}")
    lines.append("")

    lines += ["## Traffic anomalies (3-sigma on hourly counts)", ""]
    if r["anomalies"]:
        for a in r["anomalies"]:
            lines.append(f"- [ANOMALY] {a['hour']} — {a['count']} requests "
                         f"(z≈{a['z']}σ, threshold={a['threshold']}σ-equivalent)")
    else:
        lines.append("No hour exceeded the 3-sigma threshold.")
    lines.append("")

    Path(dest).write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    ap = argparse.ArgumentParser(description="Web access-log analysis (Lab 15, Part 3 B-E)")
    ap.add_argument("logfile", help="path to access.log")
    ap.add_argument("--report", help="write a Markdown report to this path")
    ap.add_argument("--json", action="store_true", help="print raw JSON")
    args = ap.parse_args()

    r = analyze(args.logfile)

    if args.json:
        print(json.dumps(r, indent=2))
    else:
        print(f"Parsed {r['total_requests']} requests ({r['unparsed_lines']} unparsed)")
        print(f"Suspicious: {len(r['suspicious_requests'])}  Anomalous hours: {len(r['anomalies'])}")
        for a in r["anomalies"]:
            print(f"  [ANOMALY] {a['hour']} {a['count']} req (z≈{a['z']}σ)")
        print("Top IPs:", ", ".join(f"{ip}({n})" for ip, n in r["top_ips"]))

    if args.report:
        write_report(r, args.logfile, args.report)
        print(f"report -> {args.report}")


if __name__ == "__main__":
    main()
