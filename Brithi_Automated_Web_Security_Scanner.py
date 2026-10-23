#!/usr/bin/env python3
"""
Automated Web Security Scanner (educational, non-invasive checks only).

Use only on websites you own or have explicit permission to assess.
This tool sends ordinary HTTP GET requests and checks response headers/cookie flags.
It does not exploit vulnerabilities, brute-force, crawl, or run intrusive tests.
"""
import argparse
import json
import sys
from datetime import datetime, timezone
from html import escape
from urllib.parse import urlparse

try:
    import requests
except ImportError:
    print("Missing dependency. Install it with: python -m pip install -r requirements.txt")
    sys.exit(1)

SECURITY_HEADERS = {
    "Strict-Transport-Security": (
        "High", "Helps browsers enforce HTTPS connections.",
        "Configure HSTS on HTTPS sites after confirming all required subdomains support HTTPS."
    ),
    "Content-Security-Policy": (
        "High", "Restricts which sources a browser may load content from.",
        "Define a policy appropriate to the application; start in report-only mode if needed."
    ),
    "X-Content-Type-Options": (
        "Medium", "Reduces MIME-type sniffing by browsers.",
        "Set X-Content-Type-Options: nosniff."
    ),
    "X-Frame-Options": (
        "Medium", "Helps reduce clickjacking risk in older browsers.",
        "Set X-Frame-Options: DENY or SAMEORIGIN, or use CSP frame-ancestors."
    ),
    "Referrer-Policy": (
        "Low", "Controls how much referrer information browsers send.",
        "Consider strict-origin-when-cross-origin or a policy suitable for the site."
    ),
    "Permissions-Policy": (
        "Low", "Restricts access to selected browser features.",
        "Set a policy that disables features the application does not need."
    ),
}

def normalize_url(raw):
    raw = raw.strip()
    if not raw:
        raise ValueError("Please provide a URL.")
    if "://" not in raw:
        raw = "https://" + raw
    parsed = urlparse(raw)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("URL must use http:// or https:// and include a hostname.")
    if parsed.username or parsed.password:
        raise ValueError("Do not include usernames or passwords in the URL.")
    return raw

def scan(url, timeout=10):
    parsed = urlparse(url)
    result = {
        "target": url,
        "scanned_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": "completed",
        "http_status": None,
        "final_url": None,
        "https_used": parsed.scheme == "https",
        "findings": [],
        "notes": [
            "This is a lightweight header/configuration review, not a penetration test.",
            "A missing header is not proof that a site is vulnerable; assess application context."
        ],
    }
    try:
        response = requests.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            headers={"User-Agent": "EducationalWebSecurityScanner/1.0"},
        )
    except requests.RequestException as exc:
        result["status"] = "error"
        result["error"] = f"{type(exc).__name__}: {exc}"
        return result

    result["http_status"] = response.status_code
    result["final_url"] = response.url
    result["https_used"] = urlparse(response.url).scheme == "https"
    headers = {k.lower(): v for k, v in response.headers.items()}

    if urlparse(response.url).scheme != "https":
        result["findings"].append({
            "severity": "High",
            "title": "Final URL does not use HTTPS",
            "evidence": response.url,
            "recommendation": "Serve the site over HTTPS and redirect HTTP traffic to HTTPS."
        })

    for header, (severity, purpose, recommendation) in SECURITY_HEADERS.items():
        value = headers.get(header.lower())
        if value:
            result["findings"].append({
                "severity": "Info",
                "title": f"{header} present",
                "evidence": value,
                "recommendation": f"Review whether this value is appropriate. Purpose: {purpose}"
            })
        else:
            result["findings"].append({
                "severity": severity,
                "title": f"Missing {header}",
                "evidence": "Response did not include this header.",
                "recommendation": recommendation
            })

    server = headers.get("server")
    if server:
        result["findings"].append({
            "severity": "Low",
            "title": "Server header disclosed",
            "evidence": server,
            "recommendation": "Consider minimizing unnecessary product/version disclosure."
        })

    set_cookie_headers = response.raw.headers.getlist("Set-Cookie") if hasattr(response.raw.headers, "getlist") else []
    if not set_cookie_headers and "set-cookie" in headers:
        set_cookie_headers = [headers["set-cookie"]]
    for index, cookie in enumerate(set_cookie_headers, start=1):
        low = cookie.lower()
        missing = []
        if "secure" not in low:
            missing.append("Secure")
        if "httponly" not in low:
            missing.append("HttpOnly")
        if "samesite" not in low:
            missing.append("SameSite")
        if missing:
            result["findings"].append({
                "severity": "Medium",
                "title": f"Cookie {index} may be missing security attributes",
                "evidence": ", ".join(missing) + " attribute(s) not detected",
                "recommendation": "Review cookie purpose and set Secure (HTTPS), HttpOnly (where JavaScript access is unnecessary), and an appropriate SameSite value."
            })

    result["summary"] = {
        "high": sum(1 for f in result["findings"] if f["severity"] == "High"),
        "medium": sum(1 for f in result["findings"] if f["severity"] == "Medium"),
        "low": sum(1 for f in result["findings"] if f["severity"] == "Low"),
        "info": sum(1 for f in result["findings"] if f["severity"] == "Info"),
    }
    return result

def write_html(result, path):
    findings = result.get("findings", [])
    rows = []
    for f in findings:
        rows.append(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
                escape(str(f.get("severity", ""))),
                escape(str(f.get("title", ""))),
                escape(str(f.get("evidence", ""))),
                escape(str(f.get("recommendation", ""))),
            )
        )
    summary = result.get("summary", {})
    html = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Web Security Scan Report</title>
<style>

body{{font-family:Arial,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem;color:#202124}}
h1{{color:#17365d}} .meta{{background:#f2f5f8;padding:1rem;border-radius:8px}}
table{{border-collapse:collapse;width:100%;margin-top:1rem}}th,td{{border:1px solid #d5dbe1;padding:.65rem;text-align:left;vertical-align:top}}
th{{background:#eaf0f6}} .note{{color:#555;font-size:.92rem}}

</style></head><body>
<h1>Automated Web Security Scanner Report</h1>
<div class="meta">
<p><b>Target:</b> {target}</p><p><b>Scan time (UTC):</b> {scanned}</p>
<p><b>Status:</b> {status} | <b>HTTP status:</b> {http_status}</p>
<p><b>Final URL:</b> {final_url}</p>
<p><b>Summary:</b> High: {high} · Medium: {medium} · Low: {low} · Informational: {info}</p>
</div>
{error}
<table><thead><tr><th>Severity</th><th>Finding</th><th>Evidence</th><th>Recommendation</th></tr></thead>
<tbody>{rows}</tbody></table>
<h2>Scope and limitations</h2><ul>{notes}</ul>
<p class="note">Educational use only. Scan only systems you own or are authorized to assess. This report checks a limited set of HTTP response configuration signals and does not establish that a site is secure or insecure.</p>
</body></html>""".format(
        target=escape(str(result.get("target", ""))),
        scanned=escape(str(result.get("scanned_at_utc", ""))),
        status=escape(str(result.get("status", ""))),
        http_status=escape(str(result.get("http_status", "N/A"))),
        final_url=escape(str(result.get("final_url", "N/A"))),
        high=summary.get("high", 0), medium=summary.get("medium", 0),
        low=summary.get("low", 0), info=summary.get("info", 0),
        error=("<p><b>Error:</b> " + escape(result["error"]) + "</p>") if result.get("error") else "",
        rows="".join(rows),
        notes="".join("<li>" + escape(n) + "</li>" for n in result.get("notes", [])),
    )
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)

def main():
    parser = argparse.ArgumentParser(description="Lightweight web security header scanner")
    parser.add_argument("url", help="Target URL, e.g. https://example.com")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")
    parser.add_argument("--out", default="scan_report", help="Output filename prefix (default: scan_report)")
    args = parser.parse_args()

    try:
        url = normalize_url(args.url)
    except ValueError as exc:
        parser.error(str(exc))

    print("Scanning one URL with non-invasive GET/header checks...")
    print("Only scan sites you own or have explicit permission to assess.")
    result = scan(url, timeout=max(1, min(args.timeout, 30)))

    json_path = args.out + ".json"
    html_path = args.out + ".html"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    write_html(result, html_path)

    print(f"\nStatus: {result['status']}")
    if result.get("error"):
        print("Error:", result["error"])
    else:
        print("HTTP status:", result.get("http_status"))
        print("Findings:", len(result.get("findings", [])))
        for key, value in result.get("summary", {}).items():
            print(f"  {key.title()}: {value}")
    print(f"Reports saved: {json_path}, {html_path}")

if __name__ == "__main__":
    main()
