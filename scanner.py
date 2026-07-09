"""Core scanning logic for the vulnerability analyzer."""

import socket
import ssl
import re
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

SECURITY_HEADERS = {
    "Strict-Transport-Security": "Forces HTTPS, blocks downgrade attacks.",
    "Content-Security-Policy": "Restricts script/style sources, mitigates XSS.",
    "X-Frame-Options": "Prevents clickjacking via iframe embedding.",
    "X-Content-Type-Options": "Blocks MIME-sniffing attacks.",
    "Referrer-Policy": "Limits referrer information leakage.",
    "Permissions-Policy": "Restricts browser feature access (camera, geo...).",
}

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 80: "HTTP",
    110: "POP3", 143: "IMAP", 443: "HTTPS", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt",
}

TECH_PATTERNS = {
    r"wp-content|wp-includes": "WordPress",
    r"Drupal\.settings": "Drupal",
    r"joomla": "Joomla",
    r"__NEXT_DATA__": "Next.js",
    r"ng-version": "Angular",
    r"data-vue-": "Vue.js",
    r"react": "React",
}


def scan_target(url: str) -> dict:
    """Run the full scan pipeline against a target URL and return results."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    hostname = urlparse(url).hostname

    report = {"url": url, "hostname": hostname, "score": 100}

    try:
        response = requests.get(url, timeout=8, allow_redirects=True)
    except requests.RequestException as exc:
        report["headers"] = {"error": str(exc)}
        report["tech"] = []
    else:
        report["headers"] = _check_headers(response, report)
        report["tech"] = _detect_tech(response)

    report["ssl"] = _check_ssl(hostname, report)
    report["ports"] = _scan_ports(hostname)
    report["score"] = max(report["score"], 0)
    return report


def _check_headers(response, report: dict) -> dict:
    missing = [
        {"name": h, "desc": d}
        for h, d in SECURITY_HEADERS.items() if h not in response.headers
    ]
    report["score"] -= len(missing) * 8
    return {
        "status_code": response.status_code,
        "server": response.headers.get("Server", "hidden"),
        "present": [h for h in SECURITY_HEADERS if h in response.headers],
        "missing": missing,
    }


def _check_ssl(hostname: str, report: dict) -> dict:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
    except Exception as exc:
        report["score"] -= 20
        return {"error": str(exc)}

    not_after = datetime.strptime(
        cert["notAfter"], "%b %d %H:%M:%S %Y %Z"
    ).replace(tzinfo=timezone.utc)
    days_left = (not_after - datetime.now(timezone.utc)).days
    issuer = dict(x[0] for x in cert.get("issuer", []))

    if days_left <= 0:
        report["score"] -= 25
    elif days_left < 30:
        report["score"] -= 10

    return {
        "valid": days_left > 0,
        "issuer": issuer.get("organizationName", issuer.get("commonName", "unknown")),
        "expires": not_after.strftime("%Y-%m-%d"),
        "days_left": days_left,
    }


def _scan_ports(hostname: str) -> dict:
    try:
        ip = socket.gethostbyname(hostname)
    except socket.gaierror as exc:
        return {"error": str(exc)}

    open_ports = []
    for port, service in COMMON_PORTS.items():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.7)
            if s.connect_ex((ip, port)) == 0:
                open_ports.append({"port": port, "service": service})
    return {"ip": ip, "open": open_ports}


def _detect_tech(response) -> list:
    found = set()
    for pattern, name in TECH_PATTERNS.items():
        if re.search(pattern, response.text, re.IGNORECASE):
            found.add(name)
    if response.headers.get("X-Powered-By"):
        found.add(response.headers["X-Powered-By"])
    return sorted(found)
