# Security Header Checker

A simple Python tool that scans a website's HTTP response headers and flags missing security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy), along with the real-world risk each missing header introduces.

Built as a learning project while getting hands-on with web security fundamentals and preparing for bug bounty hunting.

## What it does

- Sends a request to a given URL and follows any redirect chain
- Checks for the presence of key security headers
- For each missing header, explains what it does and what risk its absence introduces
- Supports scanning multiple URLs in one run, with a summary comparison at the end

## Usage

```bash
pip install -r requirements.txt
python header_checker.py
```

You'll be prompted to enter one or more URLs (comma-separated for multiple).

> 🇹🇷 A Turkish-language version is also available: [`header_checker_tr.py`](header_checker_tr.py)

## Example output

```
=== http://google.com ===
Status code: 200
🔀 Redirect chain (1 step(s)):
   [301] http://google.com/
   → Final URL: http://www.google.com/
✅ Present headers (1):
   X-Frame-Options: SAMEORIGIN
❌ Missing headers (5):
   Content-Security-Policy — Restricts which sources content (scripts, styles, etc.) can be loaded from, mitigating XSS and injection attacks.
      ⚠️  Risk: If the site has an XSS vulnerability, an injected script can run without any restriction.
   Strict-Transport-Security — Forces the browser to only connect to the site over HTTPS.
      ⚠️  Risk: On an untrusted network (e.g. public wifi), the first HTTP connection could be intercepted before the browser upgrades to HTTPS.
   ...
```

## Why I built this

I'm a software engineering student exploring cybersecurity, particularly bug bounty hunting. This project was a way to learn Python by building something with real security relevance, rather than doing generic exercises.

## License

MIT
