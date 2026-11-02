# Defensive Security Assessment Report: Student Portal (Lab)

**Assessor:** Bharath Kumar L
**Track:** Cyber Security, Task 4 (Defensive Security Assessment Capstone)
**Result:** 10 findings in v1, all 10 retests pass in v2

---

## 1. Scope, authorization and rules of engagement

### Scope
| Item | Detail |
|---|---|
| Target | A fictional student portal written by me for this exercise (`app_v1_vulnerable/app.py`) |
| Environment | My own machine, bound to `127.0.0.1:5001` only. No cloud, no third-party services |
| In scope | Configuration, authentication, input validation, dependencies, logging |
| Out of scope | Any system I do not own, the network, the host OS, denial-of-service testing, social engineering |

### Authorization statement
I wrote and run this application myself, and I am the sole owner and tester. I authorize myself to assess
it on localhost for learning and portfolio purposes. No third party's systems or data are involved.

### Rules of engagement
1. Test only `127.0.0.1` / `localhost`. `assess.py` refuses any other host.
2. Use synthetic data only: fake students ("Alice Example") and lab-only demo passwords. No real credentials or personal data.
3. Keep checks non-destructive: low request counts (8 login attempts), no data modification, no persistence.
4. Do not scan external systems or reuse these payloads elsewhere.
5. Record evidence as text output; redact anything that looks like a secret before sharing.

---

## 2. Method

A small script (`assess.py`) runs 10 repeatable checks across the five required areas against a running
instance. I ran it against v1 (before), fixed the issues, then ran the same script against v2 (after).
Evidence is in `evidence/before.txt` and `evidence/after.txt`; run `./run_assessment.sh` to reproduce.

## 3. Threat model (summary)

| Asset / owner | Entry point | Threat scenario | Existing control (v1) | Risk |
|---|---|---|---|---|
| Student records / registrar | `/student?id=` | Attacker alters the query and reads all records | None | High |
| User accounts / IT | `/login` | Guessing common passwords with no limit | None | High |
| Config and secrets / IT | `/debug-info` | Anyone reads the signing key and routes | None | High |
| Users' browsers | `/search?q=` | Script injected through a crafted link | None | Medium |
| Audit trail / security team | Auth events | Attacks go unnoticed | None | Medium |

## 4. Findings

Severity uses likelihood x impact on this lab app. Reproduction uses only the local lab and synthetic values.

| ID | Area | Finding | Severity | Reproduce (localhost) | Fix in v2 | Retest |
|---|---|---|---|---|---|---|
| V2 | Validation | SQL built by string concatenation; `id=1 OR 1=1` returns all 3 rows | **High** | `GET /student?id=1 OR 1=1` | Parameterized query + numeric check | 400, 0 rows |
| A1 | Authentication | Weak default credentials (`admin/admin`) accepted; passwords stored in plaintext | **High** | `POST /login admin/admin` | Salted hashes (`generate_password_hash`), strong lab passwords | Rejected |
| A2 | Authentication | No throttling: unlimited failed logins | **High** | 8 bad logins, all return 401 | Max 5 failures / 60 s per IP, then 429 | 429 on attempt 6 |
| C1 | Configuration | `/debug-info` exposes the secret key, debug flag and routes | **High** | `GET /debug-info` returns 200 | Endpoint removed, `DEBUG=False`, random secret from env | 404 |
| V3 | Validation | Malformed input returns a 500 with stack trace / DB error | Medium | `GET /student?id=1'` | Input validation + generic error handler | 400 |
| V1 | Validation | Search term reflected without encoding | Medium | `GET /search?q=<x-probe>` echoed raw | Output escaping | Encoded |
| L1 | Logging | Failed logins not logged | Medium | Check for a log after bad logins: none | `auth_success/failure/locked` events with time and IP | Events present |
| C2 | Configuration | Missing CSP, nosniff, X-Frame-Options | Low | Inspect response headers | `after_request` security headers | Present |
| C3 | Configuration | Session cookie lacks `SameSite` | Low | Inspect `Set-Cookie` | `SameSite=Lax` (and `HttpOnly`) | Set |
| D1 | Dependencies | `requirements.txt` unpinned (`flask`), so builds are not reproducible or auditable | Low | Read the file | `flask==3.1.3` | Pinned |

Notes:
- The v1 weaknesses were introduced deliberately so there was something to assess; they are common real-world patterns.
- In v2, `SESSION_COOKIE_SECURE` stays `False` because the lab runs on plain HTTP. Behind HTTPS it must be `True`.

## 5. Before / after results

| | v1 (before) | v2 (after) |
|---|---|---|
| Checks passed | 0 / 10 | 10 / 10 |

Full output: `evidence/before.txt` and `evidence/after.txt`.

## 6. Limitations and next steps
- The rate limiter is in-memory and per-IP; a real deployment needs a shared store and per-account limits.
- Dependency review here is limited to pinning; run `pip-audit` against the pinned set for known CVEs.
- Not covered: CSRF tokens, session fixation, authorization (role) checks, HTTPS configuration.
- Retest checks are targeted regression tests, not a full penetration test.
