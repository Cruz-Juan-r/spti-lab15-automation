# Lab 15 — Automation (SPTI)

A multi-stage reconnaissance and log-analysis toolkit, built in two roles
(scanner engineer + log analyst). Everything scans only the authorised address
in `scope.txt`; scanning a host you are not authorised to scan is illegal
regardless of intent.

## Requirements

- Python **3.10+** (tested on 3.13), **standard library only** — no `pip install` needed.
- External CLI tools used by the scripts (present on Kali): `nmap`, `ssh-keyscan`,
  `whois`, `dig`, `curl`. Only needed when you actually run the recon/scan stages.

## How to run each script

```bash
# Part 1 — concurrent port scanner (asyncio by default)
python3 scanner.py <scope-ip> --ports 1-1024 --rate 200  --output scan_rate200.json
python3 scanner.py <scope-ip> --ports 1-1024 --rate 2000 --output scan_rate2000.json
python3 scanner.py <scope-ip> --ports 22,80,443 --engine threads
python3 scanner.py <scope-ip> --engine sequential          # baseline timing

# Part 2 — nmap XML parser + ssh-keyscan enrichment
nmap -sV --open -oX scan.xml <scope-ip>
python3 parse_scan.py --input scan.xml --output hosts.json

# Part 3 — engineer plants findings, analyst analyses
python3 make-attack-logs.py                 # engineer: writes auth.log, access.log, planted.json
python3 auth_analysis.py auth.log           # analyst: brute force + breach
python3 log_analysis.py access.log --report report.md   # analyst: attacks + 3-sigma

# Part 4 — integrated recon tool
python3 recon.py <scope-ip>  --mode ip      --verbose
python3 recon.py example.com --mode domain  --verbose
```

## What each script does (and why the design is sound)

- **scanner.py** — three engines (sequential / `ThreadPoolExecutor` / `asyncio`+`Semaphore`)
  so you can compare them. Network scanning is I/O-bound (mostly waiting), so both
  threads and asyncio give big speedups despite the GIL. The `Semaphore` caps
  concurrency to stay gentle on the target and quieter to an IDS. Output is JSON so
  the analyst can diff open ports against the answer key.
- **parse_scan.py** — drives nmap through `subprocess` and parses its `-oX` XML with
  `ElementTree`. Selects the IPv4 address by `addrtype` (not position), skips `down`
  hosts and non-`open` ports, and enriches port-22 hosts with their SSH host-key type.
  XML is parsed, never regex'd, because structured output is the point of `-oX`.
- **auth_analysis.py** — regex over sshd lines where **`invalid user` is optional**
  (a pattern that omits it silently ignores guesses at nonexistent accounts).
  Counts failures per IP, distinct usernames, the fail:ok ratio, and — the
  highest-value finding — any success that follows a run of failures from the same IP.
- **log_analysis.py** — **decodes** each request path before matching (double
  `unquote`, `+`→space, strips `/**/` comments), so double-encoded / mixed-case /
  comment-split payloads are caught and benign `%20` requests are not false-positived.
  Also: top-5 IPs, status distribution, and a 3-sigma detector that reports each
  anomalous hour's z-score.
- **make-attack-logs.py** — engineer-side: appends planted activity to the baseline
  logs, sorts by time, and writes the `planted.json` answer key.
- **recon.py** — single-file tool. `run_logged()` wraps every external command and
  writes command + outcome + timestamp to `audit.log` (non-negotiable for a pentest
  engagement). Each stage is independent: a failure in one never stops the others.
  Writes `results.json` (structured, keyed by tool) and a readable `report.md`.

## Who did what

| File | Role |
|------|------|
| `scanner.py` | Engineer (Part 1) |
| `parse_scan.py` | Engineer (Part 2) |
| `make-attack-logs.py`, `planted.json` | Engineer (Part 0/3 planting) |
| `auth_analysis.py`, `log_analysis.py`, `report.md` | Analyst (Part 3) |
| `findings_score.md` | Engineer scores the analyst (Part 3) |
| `recon.py` | Engineer stages 1/3/4 + Analyst stages 2/5/6, merged (Part 4) |
| `scope.txt` | Analyst (Part 0) |

Handoff files that crossed between the pair: `scope.txt` (analyst→engineer),
planted `auth.log`/`access.log` (engineer→analyst), `scan_rate200.json` /
`scan_rate2000.json` (engineer→analyst), `report.md` (analyst→engineer),
`run_logged()` (analyst→engineer), `results.json` (engineer→analyst).

---

# Lab questions — answers

**Part 1 — false negatives at high concurrency.** At `--rate 2000` the process
holds thousands of sockets at once. Each socket is a file descriptor, and the
soft limit (`ulimit -n`, often 1024) plus the finite local-port pool mean new
`connect()` calls raise `OSError` ("Too many open files") or time out — the
target's SYN backlog filling or a rate-limiting firewall produce the same
silence. The scanner catches those and returns "closed", turning *"I could not
ask"* into *"the answer is no"* — a false negative. So **"the scanner did not
detect it" ≠ "the port is closed."** Interpret any tool's result, nmap included,
as only as complete as its error count: re-scan unknowns at lower concurrency and
report the error count beside the open ports.

**Part 2 — version strings.** A product+version string (e.g. `Samba 3.0.20`)
replaces an attacker's guesswork with a lookup: straight to the CVE record, its
severity and known exploits. `Apache httpd 2.4.54` hands the attacker a precise
CVE search; a server returning **no version** forces fingerprinting by behaviour
instead — slower and less certain. But hiding the version doesn't remove the
vulnerability, and distributions backport patches without bumping the version, so
a visible version can even *overstate* the real exposure.

**Part 3 — periodicity breaks a single global baseline.** Web traffic has a daily
cycle (busy by day, quiet overnight). One global mean+stdev averages noon and
3 a.m. together, so a normal midday volume can look anomalous and a real 3 a.m.
spike can hide under the inflated global stdev — false positives and false
negatives at once. Fix: compare each hour against the **same hour on previous
days** (or a rolling per-hour window), and use the **median + MAD** instead of
mean + stdev so one spike can't inflate the baseline it's judged against.

**Part 3 (theory) — why ≤8 counts can't trigger 3σ.** The spike raises both the
mean and the standard deviation it is measured against. With `n` samples and one
outlier, the largest attainable z using the sample stdev is `(n-1)/√n`. For
`n=8` that is `7/√8 ≈ 2.47 < 3`, so eight hourly counts can never reach three
sigma however large the final count. (24 hourly counts cap near 4.7σ.)

**Part 4 — active vs passive recon.** `recon.py` is **active**: it sends packets,
so it appears in the target's firewall/IDS/host logs — more detectable, but
current and able to reach internal hosts Shodan never saw. **Shodan is passive**:
it already scanned the internet, so querying it touches the target with *zero*
packets — undetectable to the defender (the only trace is Shodan's own earlier
indexing probe, which looks like background noise), but possibly stale and
limited to internet-exposed services. For a defender with network monitoring,
passive is far harder to detect. Use passive for quiet early footprinting; use
active when you need current, authoritative, or internal detail — and only within
an authorised scope.

**OPSEC — leaked API key.** Rotate (revoke) the key immediately and issue a new
one. The removal commit doesn't help because git history and every fork/clone
still contain the key, and automated scrapers harvest new commits within seconds
of the push — so it must be treated as compromised the moment it was pushed.

**Best practices — `except Exception: pass` + "scan complete".** It violates
**fail loudly** (errors are swallowed, so incomplete results are reported as
complete) and **the classified-outcome design** (every error is collapsed to
"not open", hiding false negatives). First fix: stop bare-excepting — classify
outcomes (open/closed/filtered/error), count the errors, and report them beside
the open ports so "complete" actually means complete.
