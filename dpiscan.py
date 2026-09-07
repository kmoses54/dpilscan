#!/usr/bin/env python3
"""
DPI Bypass Host Scanner
- Discovers IPs that accept arbitrary / zero-rated SNIs
- Tests TLS handshake acceptance (SNI injection candidates)
- Collects cert SANs + non-CDN IPs
- Flags potential free-data / obfuscation front hosts
"""

import ssl
import socket
import json
import re
import sys
import argparse
import concurrent.futures
from urllib.request import urlopen, Request
from urllib.parse import quote
from datetime import datetime

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
except ImportError:
    print("[!] pip install cryptography")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

CF_PREFIXES = (
    "103.21.244.", "103.22.200.", "103.31.4.", "104.16.", "104.17.",
    "104.18.", "104.19.", "104.20.", "104.21.", "104.22.", "104.23.",
    "104.24.", "104.25.", "104.26.", "104.27.", "108.162.", "131.0.72.",
    "141.101.64.", "162.158.", "172.64.", "172.65.", "172.66.", "172.67.",
    "173.245.48.", "188.114.", "190.93.240.", "197.234.240.", "198.41.128."
)

DEFAULT_FREE_SNIS = [
    "digicel.ada.support",
    "apps.apple.com",
    "music.itune.com",
    "events.mixpanel.com",
    "topup.digicelgroup.com",
    "digicelgroup.com",
    "pusher.com",
]

# ---------------------------------------------------------------------------
# Core functions
# ---------------------------------------------------------------------------

def is_cf(ip: str) -> bool:
    return any(ip.startswith(p) for p in CF_PREFIXES)

def resolve(host: str):
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None

def get_cert_raw(host_or_ip: str, sni: str, port: int = 443, timeout: float = 5.0):
    """Connect to host_or_ip while presenting the given SNI. Return cert + TLS version or error."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host_or_ip, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=sni) as ssock:
                der = ssock.getpeercert(binary_form=True)
                cert = x509.load_der_x509_certificate(der, default_backend())
                return {
                    "ok": True,
                    "tls": ssock.version(),
                    "cert": cert,
                    "sni_used": sni,
                    "ip": host_or_ip,
                }
    except Exception as e:
        return {"ok": False, "error": str(e), "sni_used": sni, "ip": host_or_ip}

def parse_cert(cert):
    if not cert:
        return {}
    subj = {a.oid._name: a.value for a in cert.subject}
    issuer = {a.oid._name: a.value for a in cert.issuer}
    sans = []
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans = [n.value for n in ext.value]
    except x509.ExtensionNotFound:
        pass
    return {
        "subject": subj.get("commonName") or str(subj),
        "issuer": issuer.get("commonName") or str(issuer),
        "sans": sans,
        "not_after": cert.not_valid_after_utc.isoformat(),
        "fp": cert.fingerprint(hashes.SHA256()).hex()[:16] + "...",
    }

def crt_sh(domain: str, limit: int = 50):
    url = f"https://crt.sh/?q={quote(domain)}&output=json"
    req = Request(url, headers={"User-Agent": "Mozilla/5.0"})
    try:
        with urlopen(req, timeout=12) as r:
            data = json.loads(r.read().decode())
            names = set()
            for entry in data[:limit]:
                for n in entry.get("name_value", "").split("\n"):
                    n = n.strip().lower()
                    if n and "*" not in n and not n.startswith("www."):
                        names.add(n)
            return sorted(names)
    except Exception:
        return []

def probe_sni(ip: str, sni: str, port: int):
    res = get_cert_raw(ip, sni, port)
    if not res["ok"]:
        return None
    info = parse_cert(res["cert"])
    return {
        "ip": ip,
        "sni": sni,
        "tls": res["tls"],
        "subject": info.get("subject"),
        "sans": info.get("sans", [])[:6],
        "issuer": info.get("issuer"),
        "fp": info.get("fp"),
        "cf": is_cf(ip),
    }

# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

def scan(target: str, free_snis: list, port: int = 443, workers: int = 12, deep: bool = False):
    print(f"\n[+] Target domain : {target}")
    print(f"[+] Free SNIs     : {free_snis}")
    print(f"[+] Port          : {port}")
    print("-" * 60)

    # 1. Direct resolution + cert
    direct_ip = resolve(target)
    if direct_ip:
        print(f"[+] Resolved     : {direct_ip}  {'(Cloudflare)' if is_cf(direct_ip) else ''}")
        res = get_cert_raw(direct_ip, target, port)
        if res["ok"]:
            info = parse_cert(res["cert"])
            print(f"[+] Direct cert  : {info.get('subject')}")
            print(f"    SANs         : {info.get('sans')}")
            print(f"    Issuer       : {info.get('issuer')}")
    else:
        print("[-] Direct resolve failed")

    # 2. Collect candidate IPs from crt.sh + target
    candidates = set()
    if direct_ip and not is_cf(direct_ip):
        candidates.add(direct_ip)

    print("[*] Querying crt.sh ...")
    related = crt_sh(target)
    print(f"[+] Related names : {len(related)}")
    for name in related[:30]:
        ip = resolve(name)
        if ip and not is_cf(ip):
            candidates.add(ip)

    print(f"[+] Non-CF IPs to probe : {len(candidates)}")
    if not candidates:
        print("[-] No usable IPs found")
        return

    # 3. SNI acceptance matrix
    print(f"[*] Probing SNI acceptance ({len(candidates)} IPs × {len(free_snis)} SNIs) ...")
    results = []
    tasks = [(ip, sni) for ip in candidates for sni in free_snis]

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as exe:
        futures = {exe.submit(probe_sni, ip, sni, port): (ip, sni) for ip, sni in tasks}
        for fut in concurrent.futures.as_completed(futures):
            r = fut.result()
            if r:
                results.append(r)
                cf_tag = "CF" if r["cf"] else "OK"
                print(f"  [HIT] {r['ip']:15}  SNI={r['sni']:<22}  TLS={r['tls']}  [{cf_tag}]")
                print(f"         Subject: {r['subject']}")
                if r["sans"]:
                    print(f"         SANs   : {r['sans']}")

    # 4. Summary
    print("\n" + "=" * 60)
    print(f"[+] Working SNI combinations : {len(results)}")
    if results:
        print("\nUsable hosts for DPI / SNI injection:")
        seen = set()
        for r in results:
            key = (r["ip"], r["sni"])
            if key in seen:
                continue
            seen.add(key)
            print(f"  {r['ip']}  ←  SNI {r['sni']}  (TLS {r['tls']})")
    else:
        print("[-] No SNI acceptance found on non-CF IPs")

    if deep and results:
        print("\n[*] Deep mode: also testing free SNIs against the original target IP")
        if direct_ip:
            for sni in free_snis:
                r = probe_sni(direct_ip, sni, port)
                if r:
                    print(f"  [HIT] {direct_ip} accepts SNI {sni}")

def main():
    ap = argparse.ArgumentParser(description="DPI Bypass / SNI Host Scanner")
    ap.add_argument("target", help="domain to start from")
    ap.add_argument("-p", "--port", type=int, default=443)
    ap.add_argument("-w", "--workers", type=int, default=12)
    ap.add_argument("--sni", nargs="+", default=DEFAULT_FREE_SNIS,
                    help="list of SNIs to test (default: common zero-rate domains)")
    ap.add_argument("--deep", action="store_true", help="extra probes")
    args = ap.parse_args()

    scan(args.target, args.sni, args.port, args.workers, args.deep)

if __name__ == "__main__":
    main()
