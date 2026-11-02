"""Scripted assessment checks for the LOCAL lab portal only.

Refuses any target that is not 127.0.0.1 / localhost.
Usage: python assess.py http://127.0.0.1:5001 [--log path/to/auth.log] [--requirements path]
"""
import argparse
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from http.client import HTTPResponse

ALLOWED_HOSTS = {"127.0.0.1", "localhost"}
WEAK_CREDS = [("admin", "admin"), ("student1", "password123")]  # synthetic lab defaults
results = []


def record(cid, area, title, passed, detail):
    results.append((cid, area, title, passed, detail))
    print(f"[{'PASS' if passed else 'FAIL'}] {cid} {area}: {title} -- {detail}")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


opener = urllib.request.build_opener(NoRedirect)


def req(base, path, data=None):
    body = urllib.parse.urlencode(data).encode() if data is not None else None
    r = urllib.request.Request(base + path, data=body)
    try:
        resp: HTTPResponse = opener.open(r, timeout=5)
    except urllib.error.HTTPError as e:
        resp = e
    return resp.status if hasattr(resp, "status") else resp.code, resp.headers, resp.read().decode(errors="replace")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("base")
    ap.add_argument("--log")
    ap.add_argument("--requirements")
    ap.add_argument("--lab-pass", default="password123",
                    help="synthetic lab password for student1 (used only to inspect the session cookie)")
    a = ap.parse_args()
    host = urllib.parse.urlparse(a.base).hostname
    if host not in ALLOWED_HOSTS:
        sys.exit(f"Refusing to test {host}: out of scope (localhost only).")
    base = a.base.rstrip("/")
    print(f"Target: {base}\n")

    # --- Configuration
    s, h, b = req(base, "/debug-info")
    record("C1", "Configuration", "Debug/info endpoint not exposed", s in (404, 405),
           f"GET /debug-info -> HTTP {s}" + (" (leaks config)" if s == 200 else ""))
    s, h, b = req(base, "/")
    need = ["Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options"]
    missing = [x for x in need if x not in h]
    record("C2", "Configuration", "Security headers present", not missing,
           "missing: " + ", ".join(missing) if missing else "all expected headers set")
    s, h, b = req(base, "/login", {"username": "student1", "password": a.lab_pass})
    sc = h.get("Set-Cookie", "")
    record("C3", "Configuration", "Session cookie has HttpOnly + SameSite",
           bool(sc) and "HttpOnly" in sc and "SameSite" in sc,
           ("flags: " + sc.split(";", 1)[1].strip()) if sc else f"no cookie issued (login HTTP {s}), cannot verify")

    # --- Authentication
    weak = []
    for u, p in WEAK_CREDS:
        s, _, _ = req(base, "/login", {"username": u, "password": p})
        if s == 200:
            weak.append(u)
    record("A1", "Authentication", "Weak default credentials rejected", not weak,
           "accepted: " + ", ".join(weak) if weak else "none of the synthetic weak pairs accepted")
    codes = [req(base, "/login", {"username": "student1", "password": f"wrong{i}"})[0] for i in range(8)]
    record("A2", "Authentication", "Brute-force throttling / lockout", 429 in codes,
           f"8 bad attempts -> {sorted(set(codes))}")

    # --- Input validation
    marker = "<x-probe>"
    s, h, b = req(base, "/search?q=" + urllib.parse.quote(marker))
    record("V1", "Validation", "Reflected input is output-encoded", marker not in b,
           "marker returned raw" if marker in b else "marker encoded")
    s, h, b = req(base, "/student?id=" + urllib.parse.quote("1 OR 1=1"))
    rows = b.count("Example")
    record("V2", "Validation", "Numeric id parameter resists SQL injection", rows <= 1 and s in (400, 200),
           f"id='1 OR 1=1' -> HTTP {s}, {rows} student rows returned")
    s, h, b = req(base, "/student?id=" + urllib.parse.quote("1'"))
    leak = bool(re.search(r"Traceback|sqlite3|OperationalError|werkzeug", b, re.I))
    record("V3", "Validation", "Errors do not leak internals", not leak and s != 500,
           f"id=1' -> HTTP {s}" + (", stack trace / DB error leaked" if leak else ""))

    # --- Dependencies
    if a.requirements and os.path.exists(a.requirements):
        lines = [l.strip() for l in open(a.requirements) if l.strip() and not l.startswith("#")]
        unpinned = [l for l in lines if "==" not in l]
        record("D1", "Dependencies", "Requirements are pinned", not unpinned,
               "unpinned: " + ", ".join(unpinned) if unpinned else f"{len(lines)} pinned")
    else:
        record("D1", "Dependencies", "Requirements are pinned", False, "no requirements file found")

    # --- Logging
    logged = False
    if a.log and os.path.exists(a.log):
        logged = "auth_failure" in open(a.log).read()
    record("L1", "Logging", "Failed logins are logged", logged,
           "auth_failure events found" if logged else "no auth log / no failure events")

    p = sum(1 for r in results if r[3])
    print(f"\nSummary: {p}/{len(results)} checks passed")


if __name__ == "__main__":
    main()
