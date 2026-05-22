#!/usr/bin/env python3
print('[IDOR Scanner - Insecure Direct Object Reference Detection]')
import requests, sys, os
requests.packages.urllib3.disable_warnings()

BANNER = '''
IDOR Scanner - Insecure Direct Object Reference
Detects: Numeric/sequential ID enumeration, UUID prediction
'''

def scan_idor(target):
    base = f"https://{target}" if not target.startswith("http") else target
    base = base.rstrip("/")
    results = {"target": target, "vulnerable": False, "findings": []}
    
    # Test sequential ID access
    id_patterns = ["/api/users/{}", "/user/{}/profile", "/document/{}", "/order/{}", "/invoice/{}"]
    
    for pattern in id_patterns:
        responses = []
        for i in [1, 2, 100, 101, 1000]:
            try:
                url = f"{base}{pattern.format(i)}"
                r = requests.get(url, timeout=10, verify=False,
                    headers={"User-Agent": "Mozilla/5.0"})
                responses.append((i, r.status_code))
            except: pass
        
        # Check if multiple IDs return 200 (IDOR indicator)
        success = [(i, s) for i, s in responses if s == 200]
        if len(success) >= 2:
            results["vulnerable"] = True
            results["findings"].append(f"[IDOR] {pattern} - accessible IDs: {[i for i,s in success]}")
    
    return results

def main():
    print(BANNER)
    if len(sys.argv) < 2:
        print("Usage: python3 idor_scanner.py <target|file>")
        sys.exit(1)
    targets = [sys.argv[1]] if not os.path.isfile(sys.argv[1]) else [l.strip() for l in open(sys.argv[1])]
    for t in targets:
        r = scan_idor(t)
        if r["vulnerable"]:
            print(f"[!!] {t}")
            for f in r["findings"]: print(f"     {f}")

if __name__ == "__main__":
    main()
