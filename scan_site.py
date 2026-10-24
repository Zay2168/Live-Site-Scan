#!/usr/bin/env python3
"""Crawl a deployed website and flag exposed secrets, sensitive files and risky links.

Standard library only, so it runs anywhere Python 3.8+ is installed.

Usage:
    python scan_site.py https://example.com
    python scan_site.py https://example.com --max-pages 200 --strict

Exit codes:
    0  nothing high-severity found
    1  high-severity finding (or any finding when --strict is set)
    2  could not reach the site at all
"""
import argparse
import re
import sys
from html.parser import HTMLParser
from urllib.error import HTTPError, URLError
from urllib.parse import urldefrag, urljoin, urlparse
from urllib.request import Request, urlopen

USER_AGENT = "secret-scan-bot/1.0 (self-audit)"
MAX_BYTES = 2_000_000
TEXT_TYPES = ("text/", "application/javascript", "application/json", "application/xml",
              "application/x-javascript", "application/ecmascript")

# (name, severity, regex). "high" = almost certainly a real credential format.
# "review" = might be intentional (e.g. a restricted public key) so a human should look.
SECRET_PATTERNS = [
    ("AWS access key ID", "high", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("Private key block", "high", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("Stripe live secret key", "high", re.compile(r"\b(?:sk|rk)_live_[0-9a-zA-Z]{20,}\b")),
    ("Anthropic API key", "high", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b")),
    ("OpenAI API key", "high", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{32,}\b")),
    ("GitHub token", "high", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("Slack token", "high", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("SendGrid API key", "high", re.compile(r"\bSG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}\b")),
    ("Google API key", "review", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("JSON Web Token", "review", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b")),
    ("Hard-coded credential assignment", "review", re.compile(
        r"""(?i)(?:api[_-]?key|secret|token|passwd|password|client[_-]?secret|private[_-]?key)["']?\s*[:=]\s*["']([A-Za-z0-9_\-/+=]{16,})["']""")),
]

# Files that should never be publicly reachable.
PROBE_PATHS = [
    "/.env", "/.env.local", "/.env.production", "/.git/config", "/.git/HEAD",
    "/config.json", "/config.js", "/secrets.json", "/firebase-config.json",
    "/serviceAccountKey.json", "/.htpasswd", "/.DS_Store", "/backup.zip",
    "/backup.sql", "/wp-config.php.bak", "/package.json",
]

RISKY_LINK = re.compile(r"(?i)(?:^|[/.\-_])(?:admin|staging|internal|localhost|127\.0\.0\.1|ngrok|dev-only)(?:$|[/.\-_:?])")


class LinkParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        for key in ("href", "src", "action", "data-src"):
            if attrs.get(key):
                self.links.append(attrs[key])


def fetch(url, force_text=False):
    """Return (status, content_type, text) or (None, None, None) on network failure.

    force_text=True decodes the body even when the server labels it as a generic binary
    type (dotfiles like .env are often served as application/octet-stream).
    """
    req = Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urlopen(req, timeout=15) as resp:
            ctype = resp.headers.get("Content-Type", "").lower()
            body = resp.read(MAX_BYTES)
            if force_text:
                if b"\x00" in body[:1024]:  # genuinely binary (zip, images, ...)
                    return resp.status, ctype, None
            elif not ctype.startswith(TEXT_TYPES) and not url.split("?")[0].endswith((".js", ".json", ".map", ".css", ".txt", ".html")):
                return resp.status, ctype, None
            return resp.status, ctype, body.decode("utf-8", errors="replace")
    except HTTPError as e:
        return e.code, "", None
    except (URLError, TimeoutError, ValueError):
        return None, None, None


def redact(value):
    value = value.strip()
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}...{value[-2:]} ({len(value)} chars)"


def scan_text(text, where, findings):
    for name, severity, pattern in SECRET_PATTERNS:
        for match in pattern.finditer(text):
            raw = match.group(1) if match.groups() else match.group(0)
            findings.append((severity, name, where, redact(raw)))


def looks_like_html(text):
    head = text.lstrip()[:200].lower()
    return head.startswith("<!doctype html") or head.startswith("<html") or "<head" in head


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("url", help="Site to scan, e.g. https://example.com")
    ap.add_argument("--max-pages", type=int, default=100, help="Max URLs to fetch (default 100)")
    ap.add_argument("--strict", action="store_true", help="Fail on 'review' findings too")
    args = ap.parse_args()

    start = args.url if "://" in args.url else "https://" + args.url
    host = urlparse(start).netloc
    queue, seen, flagged_links = [start], set(), set()
    findings, fetched = [], 0

    status, _, _ = fetch(start)
    if status is None:
        print(f"ERROR: could not reach {start}")
        return 2

    while queue and fetched < args.max_pages:
        url = urldefrag(queue.pop(0))[0]
        if url in seen:
            continue
        seen.add(url)
        status, ctype, text = fetch(url)
        if status is None or status >= 400 or text is None:
            continue
        fetched += 1
        scan_text(text, url, findings)

        if "html" in (ctype or "") or url.endswith(".html") or looks_like_html(text):
            parser = LinkParser()
            try:
                parser.feed(text)
            except Exception:
                pass
            for link in parser.links:
                if link.startswith(("mailto:", "tel:", "javascript:", "data:")):
                    continue
                absolute = urldefrag(urljoin(url, link))[0]
                # For same-site links only the path matters; for outside links check the whole URL.
                parsed = urlparse(absolute)
                target = parsed.path if parsed.netloc == host else absolute
                if RISKY_LINK.search(target) and absolute not in flagged_links:
                    flagged_links.add(absolute)
                    findings.append(("review", "Risky-looking link", url, absolute))
                if urlparse(absolute).netloc == host and absolute not in seen:
                    queue.append(absolute)

        # Source maps can leak original source, comments and keys.
        if url.split("?")[0].endswith(".js"):
            queue.append(url.split("?")[0] + ".map")

    # Probe for files that should never be public.
    base = f"{urlparse(start).scheme}://{host}"
    for path in PROBE_PATHS:
        url = base + path
        status, ctype, text = fetch(url, force_text=True)
        if status == 200 and text is not None and not looks_like_html(text) and text.strip():
            findings.append(("high", "Sensitive file publicly reachable", url, f"{len(text)} chars"))
            scan_text(text, url, findings)

    # De-duplicate while keeping order.
    unique, marker = [], set()
    for f in findings:
        if f not in marker:
            marker.add(f)
            unique.append(f)

    print(f"Scanned {fetched} URLs on {host}\n")
    if not unique:
        print("No findings.")
        return 0

    order = {"high": 0, "review": 1}
    for severity, name, where, detail in sorted(unique, key=lambda f: order[f[0]]):
        print(f"[{severity.upper():6}] {name}\n         where:  {where}\n         detail: {detail}\n")

    highs = sum(1 for f in unique if f[0] == "high")
    reviews = len(unique) - highs
    print(f"Summary: {highs} high, {reviews} to review")
    if highs or (args.strict and reviews):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
