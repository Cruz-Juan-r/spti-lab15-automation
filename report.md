# Web log analysis report

Source: `access.log`  
Total requests parsed: 2678 (unparsed lines: 0)

## Suspicious requests (decoded before matching)

12 hits from 2 address(es):

| IP | status | request path |
|----|--------|--------------|
| 185.220.101.5 | 403 | `/?id=1'%20UNION%20SELECT%201,2,3--` |
| 185.220.101.5 | 200 | `/p?q=1%2527%2520UNION%2520SELECT%2520password--` |
| 185.220.101.5 | 200 | `/admin/..%2f..%2f..%2fetc/passwd` |
| 185.220.101.5 | 200 | `/cgi-bin/test.cgi?cmd=id%3Bcat%20/etc/passwd` |
| 185.220.101.5 | 500 | `/s?q=1+UN/**/ION+SeLeCt+1,2` |
| 185.220.101.5 | 403 | `/search?q=%3Cscript%3Ealert(1)%3C/script%3E` |
| 45.33.32.156 | 403 | `/cgi-bin/test.cgi?cmd=id%3Bcat%20/etc/passwd` |
| 45.33.32.156 | 403 | `/search?q=%3Cscript%3Ealert(1)%3C/script%3E` |
| 45.33.32.156 | 500 | `/s?q=1+UN/**/ION+SeLeCt+1,2` |
| 45.33.32.156 | 200 | `/?id=1'%20UNION%20SELECT%201,2,3--` |
| 45.33.32.156 | 403 | `/admin/..%2f..%2f..%2fetc/passwd` |
| 45.33.32.156 | 403 | `/p?q=1%2527%2520UNION%2520SELECT%2520password--` |

## Top 5 IPs by request volume

- 198.51.100.99 — 900 requests
- 10.0.0.1 — 499 requests
- 192.168.1.50 — 425 requests
- 192.168.1.51 — 276 requests
- 203.0.113.20 — 229 requests

## HTTP status distribution

- 200: 2318
- 301: 53
- 304: 173
- 403: 6
- 404: 126
- 500: 2

## Traffic anomalies (3-sigma on hourly counts)

- [ANOMALY] 03:00 — 939 requests (z≈4.6σ, threshold=649.9σ-equivalent)
