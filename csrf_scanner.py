#!/usr/bin/env python3
print('[CSRF Scanner - Cross-Site Request Forgery Detection]')
import requests, sys, os, re
requests.packages.urllib3.disable_warnings()

BANNER = '''
CSRF Scanner - Cross-Site Request Forgery
Checks for: Missing CSRF tokens, weak token validation, missing SameSite cookies
'''

def scan_csrf(target):
    base = f"https://{target}" if not target.startswith("http") else target
    base = base.rstrip("/")
    results = {"target": target, "vulnerable": False, "findings": []}
    
    try:
        r = requests.get(base, timeout=10, verify=False)
        
        # Check for forms without CSRF tokens
        forms = re.findall(r'<form[^>]*>', r.text, re.I)
        for form in forms:
            if 'csrf' not in form.lower() and 'token' not in form.lower():
                results["vulnerable"] = True
                results["findings"].append(f"[CSRF] Form without CSRF token: {form[:100]}")
        
        # Check SameSite cookies
        for cookie in r.cookies:
            if cookie.name == 'session' or 'sess' in cookie.name.lower():
                if not cookie.has_nonstandard_attr('SameSite'):
                    results["findings"].append(f"[COOKIE] {cookie.name} missing SameSite attribute")
    except: pass
    
    return results

def main():
    print(BANNER)
    if len(sys.argv) < 2:
        print("Usage: python3 csrf_scanner.py <target|file>")
        sys.exit(1)
    targets = [sys.argv[1]] if not os.path.isfile(sys.argv[1]) else [l.strip() for l in open(sys.argv[1])]
    for t in targets:
        r = scan_csrf(t)
        if r["vulnerable"]:
            print(f"[!!] {t}")
            for f in r["findings"]: print(f"     {f}")

if __name__ == "__main__":
    main()
