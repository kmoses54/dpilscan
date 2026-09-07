#!/usr/bin/env python3
"""
Advanced DPI Bypass Host Scanner v2
Upgrades implemented:
  1. Full HTTP validation after TLS handshake
  2. Multi-port scanning
  3. Payload export (HTTP Injector + basic Xray/VLESS style)
  4. Result scoring
  5. Clean JSON + CSV output
"""

import ssl
import socket
import json
import csv
import time
import random
import argparse
import concurrent.futures
from datetime import datetime
from urllib.request import urlopen, Request
from urllib.parse import quote
from collections import defaultdict

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
except ImportError:
    print("[!] pip install cryptography")
    exit(1)

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

DEFAULT_PORTS = [443, 8443, 2053, 2083, 2087, 2096, 8880]
DEFAULT_FREE_SNIS = [
    "pusher.com",
    "digicel.ada.support",
    "apps.apple.com",
    "music.itune.com",
    "digicelgroup.com",
    "mixpanel.com",
    "events.mixpanel.com",
]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def is_cf(ip: str) -> bool:
    return any(ip.startswith(p) for p in CF_PREFIXES)

def resolve(host: str):
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None

def crt_sh(domain: str, limit: int = 40):
    url = f"https://crt.sh/?q={quote(domain)}&output=json"
    req = Request(url, headers={"User-Agent": "Mozilla/5.0"})
    try:
        with urlopen(req, timeout=12) as r:
            data = json.loads(r.read().decode())
            names = set()
            for entry in data[:limit]:
                for n in entry.get("name_value", "").split("\n"):
                    n = n.strip().lower()
                    if n and "*" not in n:
                        names.add(n)
            return sorted(names)
    except Exception:
        return []

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
        "cn": subj.get("commonName", ""),
        "issuer": issuer.get("commonName", ""),
        "sans": sans[:8],
        "fp": cert.fingerprint(hashes.SHA256()).hex()[:20],
    }

def create_ctx():
    """Slightly varied context (basic fingerprint variation)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    # mild variation
    try:
        ctx.set_ciphers("DEFAULT:@SECLEVEL=1")
    except Exception:
        pass
    return ctx

# ---------------------------------------------------------------------------
# Core probe (TLS + HTTP validation)
# ---------------------------------------------------------------------------

def probe(ip: str, sni: str, port: int, timeout: float = 5.0):
    start = time.time()
    ctx = create_ctx()
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=sni) as ssock:
                # TLS ok
                der = ssock.getpeercert(binary_form=True)
                cert = x509.load_der_x509_certificate(der, default_backend())
                cert_info = parse_cert(cert)
                tls_ver = ssock.version()

                # Full HTTP validation
                http_ok = False
                status = 0
                server_hdr = ""
                try:
                    req = f"GET / HTTP/1.1\r\nHost: {sni}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
                    ssock.sendall(req.encode())
                    data = ssock.recv(2048).decode(errors="ignore")
                    if data.startswith("HTTP/"):
                        line = data.split("\r\n")[0]
                        parts = line.split()
                        if len(parts) >= 2:
                            status = int(parts[1])
                            http_ok = status in (200, 301, 302, 303, 307, 308, 403, 404)
                        for h in data.split("\r\n"):
                            if h.lower().startswith("server:"):
                                server_hdr = h[7:].strip()
                                break
                except Exception:
                    pass

                latency = round((time.time() - start) * 1000)

                # Scoring
                score = 0
                if http_ok:
                    score += 40
                if status == 200:
                    score += 20
                if not is_cf(ip):
                    score += 25
                if latency < 400:
                    score += 10
                if tls_ver in ("TLSv1.3", "TLSv1.2"):
                    score += 5

                return {
                    "ok": True,
                    "ip": ip,
                    "port": port,
                    "sni": sni,
                    "tls": tls_ver,
                    "status": status,
                    "http_ok": http_ok,
                    "server": server_hdr,
                    "latency_ms": latency,
                    "score": score,
                    "cf": is_cf(ip),
                    "cert": cert_info,
                }
    except Exception as e:
        return {
            "ok": False,
            "ip": ip,
            "port": port,
            "sni": sni,
            "error": str(e)[:80],
        }

# ---------------------------------------------------------------------------
# Payload generators
# ---------------------------------------------------------------------------

def make_http_injector(ip, port, sni):
    return f"""[Payload]
CONNECT {sni}:443 HTTP/1.1[crlf]Host: {sni}[crlf][crlf]
# or raw
Payload = CONNECT [host_port] HTTP/1.1[crlf]Host: {sni}[crlf][crlf]
ProxyIP = {ip}
ProxyPort = {port}
SNI = {sni}
"""

def make_xray_snippet(ip, port, sni):
    return f"""// Xray / VLESS style outbound (adjust UUID & path)
{{
  "protocol": "vless",
  "settings": {{
    "vnext": [{{
      "address": "{ip}",
      "port": {port},
      "users": [{{"id": "YOUR-UUID", "encryption": "none"}}]
    }}]
  }},
  "streamSettings": {{
    "network": "tcp",
    "security": "tls",
    "tlsSettings": {{
      "serverName": "{sni}",
      "allowInsecure": true
    }}
  }}
}}
"""

# ---------------------------------------------------------------------------
# Main scan logic
# ---------------------------------------------------------------------------

def scan(target, free_snis, ports, workers=16, timeout=5.0, out_json=None, out_csv=None):
    print(f"\n[+] Target        : {target}")
    print(f"[+] Free SNIs     : {free_snis}")
    print(f"[+] Ports         : {ports}")
    print(f"[+] Workers       : {workers}")
    print("-" * 64)

    candidates = set()
    direct_ip = resolve(target)
    if direct_ip and not is_cf(direct_ip):
        candidates.add(direct_ip)
        print(f"[+] Direct IP     : {direct_ip}")

    print("[*] Fetching related names from crt.sh ...")
    related = crt_sh(target)
    for name in related[:35]:
        ip = resolve(name)
        if ip and not is_cf(ip):
            candidates.add(ip)
    print(f"[+] Non-CF candidate IPs : {len(candidates)}")

    if not candidates:
        print("[-] No usable IPs found")
        return

    tasks = [(ip, sni, port) for ip in candidates for sni in free_snis for port in ports]
    print(f"[*] Total probes   : {len(tasks)}")
    print("[*] Running ...\n")

    hits = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as exe:
        futs = {exe.submit(probe, ip, sni, port, timeout): (ip, sni, port) for ip, sni, port in tasks}
        for fut in concurrent.futures.as_completed(futs):
            r = fut.result()
            if r.get("ok") and r.get("http_ok"):
                hits.append(r)
                tag = "CF" if r["cf"] else "OK"
                print(f"[HIT] {r['ip']}:{r['port']:<5}  SNI={r['sni']:<22}  "
                      f"HTTP={r['status']:<3}  {r['latency_ms']:>4}ms  score={r['score']}  [{tag}]")

    # Sort by score
    hits.sort(key=lambda x: x["score"], reverse=True)

    print("\n" + "=" * 64)
    print(f"[+] Valid hits (HTTP + TLS) : {len(hits)}")

    if not hits:
        print("[-] No working combinations found")
        return

    print("\nTop results:")
    for h in hits[:15]:
        print(f"  {h['ip']}:{h['port']}  SNI={h['sni']}  score={h['score']}  "
              f"HTTP={h['status']}  {h['latency_ms']}ms")

    # Payload export for top hits
    print("\n" + "-" * 64)
    print("[+] Example payloads for top 3 hits:\n")
    for h in hits[:3]:
        print(f"### {h['ip']}:{h['port']}  SNI={h['sni']}  (score {h['score']})")
        print(make_http_injector(h["ip"], h["port"], h["sni"]))
        print(make_xray_snippet(h["ip"], h["port"], h["sni"]))
        print()

    # Save reports
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    if out_json is None:
        out_json = f"dpi_hits_{target}_{ts}.json"
    if out_csv is None:
        out_csv = f"dpi_hits_{target}_{ts}.csv"

    with open(out_json, "w") as f:
        json.dump(hits, f, indent=2)
    print(f"[+] JSON saved → {out_json}")

    with open(out_csv, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "ip", "port", "sni", "status", "latency_ms", "score", "tls", "cf", "server"
        ])
        writer.writeheader()
        for h in hits:
            writer.writerow({
                "ip": h["ip"],
                "port": h["port"],
                "sni": h["sni"],
                "status": h["status"],
                "latency_ms": h["latency_ms"],
                "score": h["score"],
                "tls": h["tls"],
                "cf": h["cf"],
                "server": h.get("server", ""),
            })
    print(f"[+] CSV  saved → {out_csv}")

def main():
    ap = argparse.ArgumentParser(description="Advanced DPI Bypass Host Scanner")
    ap.add_argument("target", help="starting domain")
    ap.add_argument("--sni", nargs="+", default=DEFAULT_FREE_SNIS)
    ap.add_argument("--ports", nargs="+", type=int, default=DEFAULT_PORTS)
    ap.add_argument("-w", "--workers", type=int, default=16)
    ap.add_argument("-t", "--timeout", type=float, default=5.0)
    ap.add_argument("--json", help="custom json output path")
    ap.add_argument("--csv", help="custom csv output path")
    args = ap.parse_args()

    scan(
        target=args.target,
        free_snis=args.sni,
        ports=args.ports,
        workers=args.workers,
        timeout=args.timeout,
        out_json=args.json,
        out_csv=args.csv,
    )

if __name__ == "__main__":
    main()
