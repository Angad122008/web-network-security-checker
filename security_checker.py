#!/usr/bin/env python3
"""
Basic web and network security checker.
Use only on systems you are authorized to test.
"""

import argparse
import socket
import ssl
from urllib.parse import urljoin, urlparse

import requests

TIMEOUT = 3

SECURITY_HEADERS = {
    "Content-Security-Policy": "Helps mitigate XSS and content injection",
    "Strict-Transport-Security": "Enforces HTTPS in supporting browsers",
    "X-Content-Type-Options": "Helps prevent MIME-type sniffing",
    "X-Frame-Options": "Helps mitigate clickjacking",
    "Referrer-Policy": "Controls referrer information leakage",
}

SENSITIVE_PATHS = [
    ".env",
    ".git/HEAD",
    "backup.zip",
    "server-status",
]

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    80: "HTTP",
    443: "HTTPS",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP alternate",
}


def check_web(url):
    print(f"\n[WEB CHECK] {url}")

    try:
        response = requests.get(
            url,
            timeout=TIMEOUT,
            allow_redirects=True,
        )
    except requests.RequestException as exc:
        print(f"[ERROR] Could not access website: {exc}")
        return

    print(f"[INFO] HTTP status: {response.status_code}")
    print(f"[INFO] Final URL: {response.url}")

    if urlparse(response.url).scheme != "https":
        print("[WARN] Page did not finish on HTTPS")
    else:
        print("[OK] Page finished on HTTPS; certificate validated")

    print("\n-- Security headers --")
    for header, explanation in SECURITY_HEADERS.items():
        if header in response.headers:
            print(f"[OK] {header} is present")
        else:
            print(f"[WARN] Missing {header}: {explanation}")

    print("\n-- Cookies --")
    cookies = response.headers.get("Set-Cookie", "")
    if not cookies:
        print("[INFO] No Set-Cookie header in initial response")
    else:
        # requests combines cookie handling; inspect cookie objects
        for cookie in response.cookies:
            print(f"[INFO] Cookie: {cookie.name}")
            if not cookie.secure:
                print(f"[WARN] {cookie.name}: missing Secure")
            if not cookie.has_nonstandard_attr("HttpOnly"):
                print(f"[INFO] Check HttpOnly for {cookie.name}")
            if not cookie.has_nonstandard_attr("SameSite"):
                print(f"[INFO] Check SameSite for {cookie.name}")

    print("\n-- Common exposed paths --")
    base = response.url.rstrip("/") + "/"

    for path in SENSITIVE_PATHS:
        target = urljoin(base, path)
        try:
            r = requests.get(
                target,
                timeout=TIMEOUT,
                allow_redirects=False,
            )
            if r.status_code == 200:
                print(
                    f"[REVIEW] {path} returned HTTP 200 "
                    "(verify exposure manually)"
                )
            elif r.status_code in (401, 403):
                print(f"[OK] {path} returned HTTP {r.status_code}")
            else:
                print(f"[INFO] {path}: HTTP {r.status_code}")
        except requests.RequestException:
            print(f"[INFO] Could not check {path}")


def check_ports(host, ports):
    print(f"\n[NETWORK CHECK] {host}")

    try:
        addresses = socket.getaddrinfo(
            host, None, type=socket.SOCK_STREAM
        )
        ip = addresses[0][4][0]
        print(f"[INFO] Resolved address: {ip}")
    except socket.gaierror as exc:
        print(f"[ERROR] DNS lookup failed: {exc}")
        return

    for port in ports:
        try:
            with socket.create_connection(
                (host, port), timeout=TIMEOUT
            ):
                print(
                    f"[OPEN] TCP {port} "
                    f"({COMMON_PORTS.get(port, 'Unknown service')})"
                )
        except (socket.timeout, ConnectionRefusedError, OSError):
            print(f"[CLOSED/FILTERED] TCP {port}")


def main():
    parser = argparse.ArgumentParser(
        description="Basic authorized web/network security checks"
    )
    parser.add_argument(
        "--url",
        help="Website URL, e.g. https://example.com",
    )
    parser.add_argument(
        "--host",
        help="Authorized hostname or IP for TCP port checks",
    )
    parser.add_argument(
        "--ports",
        help="Comma-separated ports, e.g. 22,80,443,3306",
    )
    args = parser.parse_args()

    if not args.url and not args.host:
        parser.error("Provide --url, --host, or both")

    if args.url:
        parsed = urlparse(args.url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            parser.error("--url must be a valid HTTP(S) URL")
        check_web(args.url)

    if args.host:
        ports = (
            [int(p.strip()) for p in args.ports.split(",")]
            if args.ports
            else list(COMMON_PORTS)
        )
        if any(p < 1 or p > 65535 for p in ports):
            parser.error("Ports must be between 1 and 65535")
        check_ports(args.host, ports)


if __name__ == "__main__":
    main()
