#!/usr/bin/env python3
"""Lab 15 - Part 1: concurrent TCP port scanner.

Only scans the single authorised address from scope.txt. Scanning a host you
are not authorised to scan is illegal, regardless of intent.

Three engines are implemented so you can compare them:
  - sequential : one port at a time (baseline, for timing)
  - threads    : concurrent.futures.ThreadPoolExecutor (I/O-bound friendly)
  - asyncio    : single-thread event loop + asyncio.Semaphore (high concurrency)

The default engine is asyncio. Example:
    python3 scanner.py 127.0.0.1 --ports 1-1024 --rate 200 --output scan.json
    python3 scanner.py 127.0.0.1 --ports 22,80,443 --engine threads

Standard library only.
"""
import argparse
import asyncio
import json
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime


# --------------------------------------------------------------------------
# Port-range parsing: accepts "1-1024" and "22,80,443" (and a mix: "1-100,443")
# --------------------------------------------------------------------------
def parse_ports(spec: str) -> list[int]:
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = part.split("-", 1)
            lo, hi = int(lo), int(hi)
            if lo > hi:
                lo, hi = hi, lo
            ports.update(range(lo, hi + 1))
        else:
            ports.add(int(part))
    return sorted(p for p in ports if 1 <= p <= 65535)


# --------------------------------------------------------------------------
# Engine 1: sequential (baseline)
# --------------------------------------------------------------------------
def scan_sequential(host: str, ports: list[int], timeout: float) -> list[int]:
    open_ports = []
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            try:
                s.connect((host, port))
                open_ports.append(port)
            except (socket.timeout, ConnectionRefusedError, OSError):
                pass
    return sorted(open_ports)


# --------------------------------------------------------------------------
# Engine 2: ThreadPoolExecutor
# --------------------------------------------------------------------------
def _probe(args: tuple[str, int, float]) -> int | None:
    host, port, timeout = args
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        try:
            s.connect((host, port))
            return port
        except (socket.timeout, ConnectionRefusedError, OSError):
            return None


def scan_threads(host: str, ports: list[int], timeout: float, rate: int) -> list[int]:
    with ThreadPoolExecutor(max_workers=rate) as executor:
        results = executor.map(_probe, [(host, p, timeout) for p in ports])
    return sorted(p for p in results if p is not None)


# --------------------------------------------------------------------------
# Engine 3: asyncio + Semaphore (caps concurrency, not rate)
# --------------------------------------------------------------------------
async def _probe_async(host: str, port: int, timeout: float) -> int | None:
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        writer.close()
        try:
            await writer.wait_closed()
        except (ConnectionResetError, OSError):
            pass
        return port
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return None


async def scan_asyncio(host: str, ports: list[int], timeout: float, rate: int) -> list[int]:
    semaphore = asyncio.Semaphore(rate)

    async def limited(port: int) -> int | None:
        async with semaphore:
            return await _probe_async(host, port, timeout)

    results = await asyncio.gather(*[limited(p) for p in ports])
    return sorted(p for p in results if p is not None)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def main() -> None:
    ap = argparse.ArgumentParser(description="Concurrent TCP port scanner (Lab 15, Part 1)")
    ap.add_argument("target", help="IP address to scan (must match scope.txt)")
    ap.add_argument("--ports", default="1-1024",
                    help="Port range or list, e.g. 1-1024 or 22,80,443 (default 1-1024)")
    ap.add_argument("--rate", type=int, default=200,
                    help="Max concurrent connections (default 200)")
    ap.add_argument("--timeout", type=float, default=0.5,
                    help="Per-port timeout in seconds (default 0.5)")
    ap.add_argument("--engine", choices=["sequential", "threads", "asyncio"],
                    default="asyncio", help="Scan engine (default asyncio)")
    ap.add_argument("--output", default="-",
                    help="JSON output file, or - for stdout (default -)")
    args = ap.parse_args()

    ports = parse_ports(args.ports)
    if not ports:
        ap.error("no valid ports parsed from --ports")

    start = time.perf_counter()
    if args.engine == "sequential":
        open_ports = scan_sequential(args.target, ports, args.timeout)
    elif args.engine == "threads":
        open_ports = scan_threads(args.target, ports, args.timeout, args.rate)
    else:
        open_ports = asyncio.run(scan_asyncio(args.target, ports, args.timeout, args.rate))
    elapsed = time.perf_counter() - start

    result = {
        "target": args.target,
        "engine": args.engine,
        "ports_scanned": len(ports),
        "rate": args.rate,
        "scan_time_seconds": round(elapsed, 2),
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "open_ports": open_ports,
    }

    text = json.dumps(result, indent=2)
    if args.output == "-":
        print(text)
    else:
        with open(args.output, "w") as f:
            f.write(text + "\n")
        print(f"{len(open_ports)} open ports -> {args.output} ({elapsed:.1f}s)", file=sys.stderr)


if __name__ == "__main__":
    main()
