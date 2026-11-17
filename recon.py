#!/usr/bin/env python3
"""Lab 15 - Part 4: integrated reconnaissance tool.

Performs multi-stage ACTIVE reconnaissance on a domain or IP and writes a
structured report. Only run it against hosts you are authorised to test
(the address in scope.txt, or a domain you own / example.com).

    python3 recon.py example.com
    python3 recon.py 192.168.1.10 --mode ip --verbose

Output directory (default ./recon_<target>_<timestamp>/) contains:
    audit.log      every command run, its outcome and a timestamp
    results.json   all findings in one dict keyed by tool name
    report.md      human-readable summary

Standard library only.
"""
import argparse
import json
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

AUDIT_PATH: Path | None = None
VERBOSE = False


# --------------------------------------------------------------------------
# Handoff 5 (analyst -> engineer): the audited command runner.
# Every stage calls this instead of subprocess.run directly, which is what
# makes the audit log complete.
# --------------------------------------------------------------------------
def run_logged(cmd: list[str], timeout: int = 60) -> str:
    started = datetime.now().isoformat(timespec="seconds")
    outcome, output = "success", ""
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        output = proc.stdout
        if proc.returncode != 0:
            outcome = f"nonzero_exit:{proc.returncode}"
    except FileNotFoundError:
        outcome = "error:command_not_found"
    except subprocess.TimeoutExpired:
        outcome = "error:timeout"
    except OSError as e:
        outcome = f"error:{e.errno}"

    line = f"{started} | {outcome} | {' '.join(cmd)}\n"
    if AUDIT_PATH is not None:
        with AUDIT_PATH.open("a", encoding="utf-8") as f:
            f.write(line)
    if VERBOSE:
        print(f"[recon] {outcome}: {' '.join(cmd)}", file=sys.stderr)
    return output


# --------------------------------------------------------------------------
# Engineer's stages (requirements 1, 3, 4): whois / dig / curl / nmap
# Each stage is wrapped so a failure in one never stops the others.
# --------------------------------------------------------------------------
def stage_whois_domain(target: str) -> dict:
    out = run_logged(["whois", target])
    fields = {"registrar": None, "creation_date": None,
              "expiry_date": None, "registrant_org": None}
    patterns = {
        "registrar": r"(?im)^\s*Registrar:\s*(.+)$",
        "creation_date": r"(?im)^\s*Creation Date:\s*(.+)$",
        "expiry_date": r"(?im)^\s*(?:Registry Expiry Date|Expiration Date):\s*(.+)$",
        "registrant_org": r"(?im)^\s*Registrant Organization:\s*(.+)$",
    }
    for k, pat in patterns.items():
        m = re.search(pat, out)
        if m:
            fields[k] = m.group(1).strip()
    return fields


def stage_dig_records(target: str) -> dict:
    records = {}
    for rtype in ("A", "MX", "NS", "TXT"):
        out = run_logged(["dig", "+short", target, rtype])
        records[rtype] = [ln.strip() for ln in out.splitlines() if ln.strip() and not ln.startswith(";")]
    return records


def stage_curl_headers(target: str) -> dict:
    out = run_logged(["curl", "-sSI", "--max-time", "15", f"http://{target}"])
    wanted = ["Server", "X-Powered-By", "Content-Security-Policy",
              "Strict-Transport-Security", "X-Frame-Options"]
    headers = {h: None for h in wanted}
    for line in out.splitlines():
        if ":" in line:
            name, _, value = line.partition(":")
            name = name.strip()
            for h in wanted:
                if name.lower() == h.lower():
                    headers[h] = value.strip()
    return headers


def stage_nmap_ip(target: str, outdir: Path) -> dict:
    xml_path = outdir / "scan.xml"
    run_logged(["nmap", "-sV", "--open", "--top-ports", "100",
                "-oX", str(xml_path), target], timeout=300)
    open_ports = []
    try:
        root = ET.parse(xml_path).getroot()
        for port in root.findall(".//port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = port.find("service")
            open_ports.append({
                "port": int(port.get("portid")),
                "service": svc.get("name") if svc is not None else None,
                "version": (f'{svc.get("product","")} {svc.get("version","")}'.strip()
                            if svc is not None else None) or None,
            })
    except (ET.ParseError, FileNotFoundError):
        pass
    return {"open_ports": open_ports}


def stage_reverse_dns(target: str) -> dict:
    out = run_logged(["dig", "+short", "-x", target])
    return {"ptr": [ln.strip() for ln in out.splitlines() if ln.strip() and not ln.startswith(";")]}


def stage_whois_ip(target: str) -> dict:
    out = run_logged(["whois", target])
    org = re.search(r"(?im)^\s*(?:OrgName|org-name|owner):\s*(.+)$", out)
    country = re.search(r"(?im)^\s*Country:\s*(.+)$", out)
    return {"organization": org.group(1).strip() if org else None,
            "country": country.group(1).strip() if country else None}


# --------------------------------------------------------------------------
# Analyst's stages (requirements 2, 5, 6): results.json + report.md
# --------------------------------------------------------------------------
def detect_mode(target: str) -> str:
    return "ip" if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", target) else "domain"


def build_report(results: dict, target: str, mode: str) -> str:
    L = [f"# Recon report: {target}", "", f"- Mode: **{mode}**",
         f"- Generated: {datetime.now().isoformat(timespec='seconds')}", "",
         "## Summary", "", "| Stage | Result |", "|-------|--------|"]
    for tool, data in results.items():
        if isinstance(data, dict):
            filled = sum(1 for v in data.values() if v)
            L.append(f"| {tool} | {filled}/{len(data)} fields populated |")
        else:
            L.append(f"| {tool} | — |")
    L.append("")

    if mode == "ip":
        L += ["## Open ports", ""]
        ports = results.get("nmap", {}).get("open_ports", [])
        if ports:
            L += ["| port | service | version |", "|------|---------|---------|"]
            L += [f"| {p['port']} | {p.get('service') or ''} | {p.get('version') or ''} |"
                  for p in ports]
        else:
            L.append("None found (or nmap unavailable).")
        L.append("")
        rev = results.get("reverse_dns", {}).get("ptr", [])
        L += ["## Reverse DNS", "", (", ".join(rev) if rev else "No PTR record."), ""]
        who = results.get("whois", {})
        L += ["## Ownership", "",
              f"- Organization: {who.get('organization') or 'unknown'}",
              f"- Country: {who.get('country') or 'unknown'}", ""]
    else:
        dns = results.get("dig", {})
        L += ["## DNS records", ""]
        for rtype in ("A", "MX", "NS", "TXT"):
            vals = dns.get(rtype, [])
            L.append(f"- **{rtype}**: {', '.join(vals) if vals else '(none)'}")
        L.append("")
        who = results.get("whois", {})
        L += ["## Registration", "",
              f"- Registrar: {who.get('registrar') or 'unknown'}",
              f"- Created: {who.get('creation_date') or 'unknown'}",
              f"- Expires: {who.get('expiry_date') or 'unknown'}",
              f"- Registrant org: {who.get('registrant_org') or 'unknown'}", ""]

    # Missing security headers (both modes may have curl results)
    headers = results.get("curl", {})
    if headers:
        L += ["## Security headers", ""]
        for h in ("Content-Security-Policy", "Strict-Transport-Security", "X-Frame-Options"):
            present = headers.get(h)
            L.append(f"- {h}: {'present' if present else '**MISSING**'}")
        L.append("")
    return "\n".join(L)


# --------------------------------------------------------------------------
def main() -> None:
    global AUDIT_PATH, VERBOSE
    ap = argparse.ArgumentParser(description="Integrated recon tool (Lab 15, Part 4)")
    ap.add_argument("target", help="domain name or IP address")
    ap.add_argument("--mode", choices=["domain", "ip"], help="auto-detected if omitted")
    ap.add_argument("--output", help="output directory")
    ap.add_argument("--verbose", action="store_true", help="print progress to stderr")
    args = ap.parse_args()

    VERBOSE = args.verbose
    mode = args.mode or detect_mode(args.target)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    outdir = Path(args.output) if args.output else Path(f"./recon_{args.target}_{ts}")
    outdir.mkdir(parents=True, exist_ok=True)
    AUDIT_PATH = outdir / "audit.log"
    AUDIT_PATH.write_text(
        f"# recon audit log for {args.target} ({mode}) started "
        f"{datetime.now().isoformat(timespec='seconds')}\n", encoding="utf-8")

    results: dict = {}
    if mode == "domain":
        results["whois"] = stage_whois_domain(args.target)
        results["dig"] = stage_dig_records(args.target)
        results["curl"] = stage_curl_headers(args.target)
    else:
        results["nmap"] = stage_nmap_ip(args.target, outdir)
        results["reverse_dns"] = stage_reverse_dns(args.target)
        results["whois"] = stage_whois_ip(args.target)

    (outdir / "results.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    (outdir / "report.md").write_text(build_report(results, args.target, mode), encoding="utf-8")

    print(f"Done. Output in {outdir}/ (results.json, report.md, audit.log)")


if __name__ == "__main__":
    main()
