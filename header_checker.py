"""
Security Header Checker
Sends a request to a URL, inspects the response headers, and reports
whether key security-related headers are present or missing.
"""

import requests


# Security headers to check, each with a short description of what it does
# and the real-world risk that arises when it's missing.
SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "description": "Restricts which sources content (scripts, styles, etc.) can be loaded from, mitigating XSS and injection attacks.",
        "risk": "If the site has an XSS vulnerability, an injected script can run without any restriction.",
    },
    "X-Frame-Options": {
        "description": "Prevents the site from being embedded in an iframe on another site (clickjacking protection).",
        "risk": "An attacker could embed the site in an invisible iframe and trick users into performing actions on the real site without realizing it.",
    },
    "Strict-Transport-Security": {
        "description": "Forces the browser to only connect to the site over HTTPS.",
        "risk": "On an untrusted network (e.g. public wifi), the first HTTP connection could be intercepted before the browser upgrades to HTTPS.",
    },
    "X-Content-Type-Options": {
        "description": "Prevents the browser from 'guessing' a file's type (MIME sniffing).",
        "risk": "A file that looks harmless (e.g. an image) could be interpreted and executed as a script by the browser.",
    },
    "Referrer-Policy": {
        "description": "Controls how much referrer information is shared when a user navigates to another site.",
        "risk": "If the URL contains sensitive data (e.g. a token), it could leak to the destination site via the referrer.",
    },
    "Permissions-Policy": {
        "description": "Restricts which sources can access browser features like camera and microphone.",
        "risk": "Embedded third-party content (ads, iframes) could attempt to access the user's camera/microphone without permission.",
    },
}


def check_headers(url: str) -> dict:
    """
    Sends a GET request to the given URL and checks whether the
    security headers above are present.

    Returns: {"status_code", "final_url", "redirect_chain", "present", "missing"}
    """
    # A timeout matters — if the server never responds, the script shouldn't hang forever.
    response = requests.get(url, timeout=10)

    # response.history: the list of intermediate redirects that were followed (301, 302, etc.)
    # Empty means no redirect happened; the response went straight to the requested page.
    redirect_chain = []
    for step in response.history:
        redirect_chain.append((step.status_code, step.url))

    # requests allows case-insensitive access to header names
    # (HTTP header names are case-insensitive by spec, so this is correct behavior).
    present = []
    missing = []

    for header_name, info in SECURITY_HEADERS.items():
        if header_name in response.headers:
            present.append((header_name, response.headers[header_name]))
        else:
            missing.append((header_name, info["description"], info["risk"]))

    return {
        "status_code": response.status_code,
        "final_url": response.url,  # the address actually reached after redirects
        "redirect_chain": redirect_chain,
        "present": present,
        "missing": missing,
    }


def print_report(url: str, result: dict) -> None:
    """Prints the results in a readable format."""
    print(f"\n=== {url} ===")
    print(f"Status code: {result['status_code']}")

    if result["redirect_chain"]:
        print(f"\n🔀 Redirect chain ({len(result['redirect_chain'])} step(s)):")
        for status, step_url in result["redirect_chain"]:
            print(f"   [{status}] {step_url}")
        print(f"   → Final URL: {result['final_url']}")
    else:
        print("\n🔀 No redirect, reached this address directly.")

    print()

    print(f"✅ Present headers ({len(result['present'])}):")
    for name, value in result["present"]:
        print(f"   {name}: {value}")

    print(f"\n❌ Missing headers ({len(result['missing'])}):")
    for name, description, risk in result["missing"]:
        print(f"   {name} — {description}")
        print(f"      ⚠️  Risk: {risk}")


if __name__ == "__main__":
    # Supports multiple URLs: the user can separate them with commas.
    # e.g. https://google.com, https://github.com, https://example.com
    raw_input_text = input(
        "URL(s) to check (comma-separated for multiple): "
    ).strip()

    # Clean up each part in case of inconsistent spacing like "a, b,c".
    urls = [u.strip() for u in raw_input_text.split(",") if u.strip()]

    # Collect results to print a short summary at the end.
    summary = []

    for url in urls:
        try:
            result = check_headers(url)
            print_report(url, result)
            summary.append((url, len(result["missing"])))
        except requests.exceptions.RequestException as e:
            # If one URL fails, keep scanning the rest —
            # one bad address shouldn't stop the whole scan.
            print(f"\n=== {url} ===\nRequest failed: {e}")
            summary.append((url, None))

    # If more than one site was scanned, show a short comparison at the end.
    if len(urls) > 1:
        print("\n" + "=" * 40)
        print("SUMMARY")
        print("=" * 40)
        for url, missing_count in summary:
            if missing_count is None:
                print(f"{url}: failed")
            else:
                print(f"{url}: {missing_count} header(s) missing")
