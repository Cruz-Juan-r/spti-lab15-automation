# Findings score — planted.json vs report.md

Engineer compares the analyst's `report.md` against `planted.json`. This is a
worked example from one run (seed-dependent values will differ for your pair).

## Planted items — was each detected?

| Planted item | Value | Detected? |
|--------------|-------|-----------|
| Attacker IP #1 (brute force) | 185.220.101.5 (60 failures) | ✅ yes |
| Attacker IP #2 (brute force) | 45.33.32.156 (35 failures) | ✅ yes |
| invalid-user lines present | 40 lines | ✅ yes (oracle/test/admin1 in username list) |
| Breached IP (success after failures) | 185.220.101.5 | ✅ yes |
| Traffic spike hour | 03:00 | ✅ yes (z≈4.6σ) |
| SQLi payload | `/?id=1'%20UNION%20SELECT...` | ✅ yes |
| Path-traversal payload | `/admin/..%2f..%2f..` | ✅ yes |
| XSS payload | `%3Cscript%3E...` | ✅ yes |
| Command-injection payload | `cmd=id%3Bcat...` | ✅ yes |
| Custom #1 (double-encoded SQLi) | `%2527%2520UNION...` | ✅ yes (double unquote) |
| Custom #2 (comment-split + mixed case + `+`) | `UN/**/ION+SeLeCt` | ✅ yes (comment strip + IGNORECASE) |

## Report items — any false positives (reported but not planted)?

None. The benign baseline requests (`/search?q=network%20security`,
`/docs%2Fintro`) do not match after decoding, so the analyzer reports 0
suspicious requests on the base log.

## Misses and fixes

No misses in this run. The two likely-miss custom payloads were caught because
the analyzer was hardened up front:

- **Double-encoded (`%252e`, `%2527`)** → `normalise()` runs `unquote` twice.
- **Mixed case (`SeLeCt`)** → `re.IGNORECASE` on the attack pattern.
- **Comment-split (`UN/**/ION`)** → `re.sub(r"/\*.*?\*/", "", path)` strips inline comments.
- **`+` as space** → `path.replace("+", " ")` before matching.

If a future payload still slips through, record the fix here in one line, e.g.:
`- Missed "%00"-null-byte traversal → added null-byte strip to normalise().`
