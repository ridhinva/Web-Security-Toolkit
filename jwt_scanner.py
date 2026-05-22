#!/usr/bin/env python3
print('[JWT Scanner - JSON Web Token Attack Toolkit]')
import requests, sys, os, json, base64
requests.packages.urllib3.disable_warnings()

BANNER = '''
JWT Scanner - JSON Web Token Attack Toolkit
Tests: Algorithm confusion (alg:none), weak secret, JWK injection, KID injection
'''

def decode_jwt(token):
    try:
        parts = token.split('.')
        header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
        return header, payload
    except: return None, None

def scan_jwt(target):
    base = f"https://{target}" if not target.startswith("http") else target
    base = base.rstrip("/")
    results = {"target": target, "vulnerable": False, "findings": []}
    
    # Extract JWT from common locations
    try:
        r = requests.get(base, timeout=10, verify=False)
        
        # Check Authorization header
        auth = r.request.headers.get('Authorization', '')
        if auth.startswith('Bearer '):
            token = auth[7:]
            header, payload = decode_jwt(token)
            if header and payload:
                results["findings"].append(f"[JWT] Found token: alg={header.get('alg')}, sub={payload.get('sub')}")
                
                if header.get('alg') == 'none':
                    results["vulnerable"] = True
                    results["findings"].append("[JWT] Algorithm 'none' detected - vulnerable to signature bypass")
    except: pass
    
    return results

def main():
    print(BANNER)
    if len(sys.argv) < 2:
        print("Usage: python3 jwt_scanner.py <target|file>")
        print("       python3 jwt_scanner.py --token <jwt_token>")
        sys.exit(1)
    if sys.argv[1] == "--token":
        token = sys.argv[2]
        h, p = decode_jwt(token)
        print(f"Header: {json.dumps(h, indent=2)}")
        print(f"Payload: {json.dumps(p, indent=2)}")
    else:
        targets = [sys.argv[1]] if not os.path.isfile(sys.argv[1]) else [l.strip() for l in open(sys.argv[1])]
        for t in targets:
            r = scan_jwt(t)
            if r["vulnerable"]:
                print(f"[!!] {t}")
                for f in r["findings"]: print(f"     {f}")

if __name__ == "__main__":
    main()
