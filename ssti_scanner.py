#!/usr/bin/env python3
print('[SSTI Scanner - Server-Side Template Injection Detection]')
import requests, sys, os, re
requests.packages.urllib3.disable_warnings()

BANNER = '''
SSTI Scanner - Server-Side Template Injection
Detects: Jinja2, Twig, Freemarker, Velocity, Jade/Pug, Mako
'''

TEST_PAYLOADS = {
    "jinja2": "{{7*7}}",
    "twig": "{{7*7}}",
    "freemarker": "${7*7}",
    "velocity": "#set($x=7*7)$x",
    "jade": "=7*7",
    "mako": "${7*7}",
}

def scan_ssti(target):
    base = f"https://{target}" if not target.startswith("http") else target
    base = base.rstrip("/")
    results = {"target": target, "vulnerable": False, "findings": []}
    
    for engine, payload in TEST_PAYLOADS.items():
        try:
            r = requests.get(f"{base}?name={requests.utils.quote(payload)}", timeout=10, verify=False)
            if "49" in r.text or r.elapsed.total_seconds() > 2:
                results["vulnerable"] = True
                results["findings"].append(f"[SSTI] {engine} - {payload} → '49' in response")
        except: pass
    return results

def main():
    print(BANNER)
    if len(sys.argv) < 2:
        print("Usage: python3 ssti_scanner.py <target|file>")
        sys.exit(1)
    targets = [sys.argv[1]] if not os.path.isfile(sys.argv[1]) else [l.strip() for l in open(sys.argv[1])]
    for t in targets:
        r = scan_ssti(t)
        if r["vulnerable"]:
            print(f"[!!] {t}")
            for f in r["findings"]: print(f"     {f}")

if __name__ == "__main__":
    main()
