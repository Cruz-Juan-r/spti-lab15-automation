#!/usr/bin/env python3
"""Lab 15 - Part 2: parse nmap XML and enrich with SSH host-key type.

Pipeline:
  1. nmap -sV --open -oX scan.xml <analyst-ip>   (run by hand, see README)
  2. python3 parse_scan.py --input scan.xml --output hosts.json

For every live host it produces a dict like:
  {
    "ip": "192.168.1.10",
    "hostname": "gateway.local",
    "open_ports": [
      {"port": 22, "service": "ssh", "version": "OpenSSH 8.9"},
      {"port": 80, "service": "http", "version": "Apache httpd 2.4.54"}
    ],
    "ssh_host_key_type": "ssh-ed25519"   # only when port 22 is open
  }

Standard library only (xml.etree.ElementTree, subprocess).
"""
import argparse
import json
import subprocess
import sys
import xml.etree.ElementTree as ET


def parse_nmap_xml(path: str) -> list[dict]:
    """Turn an nmap XML file into a list of host dicts."""
    tree = ET.parse(path)
    root = tree.getroot()
    hosts = []

    for host in root.findall("host"):
        # Skip hosts nmap marked as down.
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue

        # Select the IPv4 address by addrtype, not position.
        addr_el = host.find("address[@addrtype='ipv4']")
        if addr_el is None:
            continue
        ip = addr_el.get("addr")

        hostname = None
        hn = host.find("hostnames/hostname")
        if hn is not None:
            hostname = hn.get("name")

        open_ports = []
        for port in host.findall(".//port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            entry = {"port": int(port.get("portid")), "service": None, "version": None}
            svc = port.find("service")
            if svc is not None:
                entry["service"] = svc.get("name")
                product = svc.get("product")
                version = svc.get("version")
                if product and version:
                    entry["version"] = f"{product} {version}"
                elif product:
                    entry["version"] = product
            open_ports.append(entry)

        hosts.append({"ip": ip, "hostname": hostname, "open_ports": open_ports})

    return hosts


def ssh_key_type(ip: str, timeout: int = 10) -> str | None:
    """Return the SSH host-key type via ssh-keyscan, or None on failure/timeout."""
    try:
        result = subprocess.run(
            ["ssh-keyscan", "-T", str(timeout), ip],
            capture_output=True, text=True, timeout=timeout + 5,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None
    for line in result.stdout.splitlines():
        parts = line.split()
        # Format: <host> <key-type> <base64-key>
        if len(parts) >= 3 and not line.startswith("#"):
            return parts[1]
    return None


def enrich(hosts: list[dict]) -> list[dict]:
    for host in hosts:
        if any(p["port"] == 22 for p in host["open_ports"]):
            host["ssh_host_key_type"] = ssh_key_type(host["ip"])
    return hosts


def main() -> None:
    ap = argparse.ArgumentParser(description="Parse nmap XML and enrich (Lab 15, Part 2)")
    ap.add_argument("--input", required=True, help="nmap XML file (from -oX)")
    ap.add_argument("--output", required=True, help="JSON output file")
    args = ap.parse_args()

    try:
        hosts = parse_nmap_xml(args.input)
    except (ET.ParseError, FileNotFoundError) as e:
        print(f"error reading {args.input}: {e}", file=sys.stderr)
        sys.exit(1)

    hosts = enrich(hosts)

    with open(args.output, "w") as f:
        json.dump(hosts, f, indent=2)
    print(f"{len(hosts)} host(s) -> {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
