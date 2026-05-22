<p align="center">
  <img src="https://img.shields.io/badge/Web%20Security-Toolkit-blue" />
  <img src="https://img.shields.io/badge/Tools-8-green" />
  <img src="https://img.shields.io/badge/Language-Python-yellow" />
</p>

# Web Security Toolkit 🕸️

**8 web vulnerability scanners** in one repository. Covers the OWASP Top 10 and beyond — SQLi, XSS, SSRF, SSTI, CMDi, IDOR, CSRF, and JWT attacks.

## Tools Included

| Tool | Vulnerability | Detection Methods |
|------|--------------|-------------------|
| `sqli_scanner.py` | SQL Injection | Time-based, Boolean, Error, Union |
| `xss_scanner.py` | Cross-Site Scripting | Reflected, Stored, DOM, Blind |
| `ssrf_scanner.py` | Server-Side Request Forgery | Blind (collaborator), Internal IP access |
| `ssti_scanner.py` | Server-Side Template Injection | Jinja2, Twig, Freemarker, Velocity |
| `cmdi_scanner.py` | Command Injection | Time-based, Output reflection |
| `idor_scanner.py` | Insecure Direct Object Reference | Sequential ID enumeration |
| `csrf_scanner.py` | Cross-Site Request Forgery | Missing tokens, SameSite cookies |
| `jwt_scanner.py` | JWT Attacks | Algorithm confusion, Weak secret |

## Installation

```bash
git clone https://github.com/ridhinva/Web-Security-Toolkit.git
cd Web-Security-Toolkit
pip install requests
```

## Usage

Each tool works independently. Basic pattern:

```bash
# Scan single target
python3 sqli_scanner.py https://example.com

# Mass scan from file
python3 xss_scanner.py targets.txt

# Custom options
python3 sqli_scanner.py https://example.com --threads 20
```

### SQLi Scanner
```bash
python3 sqli_scanner.py https://target.com/page?id=1
python3 sqli_scanner.py targets.txt --threads 15
```

### XSS Scanner
```bash
python3 xss_scanner.py https://target.com/search?q=test
python3 xss_scanner.py urls.txt
```

### SSRF Scanner
```bash
python3 ssrf_scanner.py https://target.com
python3 ssrf_scanner.py list.txt
```

### SSTI Scanner
```bash
python3 ssti_scanner.py https://target.com?name=test
```

### CMDi Scanner
```bash
python3 cmdi_scanner.py https://target.com?cmd=ls
```

### IDOR Scanner
```bash
python3 idor_scanner.py https://target.com
```

### CSRF Scanner
```bash
python3 csrf_scanner.py https://target.com
```

### JWT Scanner
```bash
# Decode a JWT token
python3 jwt_scanner.py --token eyJhbGciOiJIUzI1NiJ9...

# Scan target for JWT
python3 jwt_scanner.py https://target.com
```

## How Each Scanner Works

### SQLi Scanner
Sends parameterized payloads to common injection points and measures response time and content. **Time-based detection** uses `SLEEP()`/`pg_sleep()`/`WAITFOR DELAY` to identify blind injection. **Boolean-based** compares response size between TRUE/FALSE conditions. **Error-based** triggers SQL errors and looks for database error messages. **Union-based** attempts to extract data directly via UNION SELECT.

### XSS Scanner
Injects JavaScript payloads into URL parameters and form fields. Checks if the payload is **reflected** in the response HTML without sanitization. Tests multiple contexts: HTML element content, attributes, JavaScript strings, and event handlers.

### SSRF Scanner
Forces the server to make requests to user-supplied URLs. Tests for **blind SSRF** by pointing to external collaborators, and **internal SSRF** by targeting cloud metadata endpoints (AWS `169.254.169.254`, Azure, GCP) and localhost services.

### SSTI Scanner
Tests template engines by injecting expression syntax like `{{7*7}}` and `${7*7}`. If the server evaluates `7*7=49` and reflects "49" in the response, the engine is vulnerable. Different payloads target Jinja2, Twig, Freemarker, Velocity, and Mako.

### CMDi Scanner
Injects OS command separators (`;`, `|`, `$()`, `` ` ``) followed by time-delay commands (`sleep`, `ping`). **Time-based detection** measures response delay. **Output-based** checks if command output appears in the response.

### IDOR Scanner
Enumerates sequential object IDs (1, 2, 100, 101, 1000) across common endpoints like `/api/users/{id}`, `/order/{id}`, `/invoice/{id}`. If multiple IDs return 200 with user data, the endpoint is vulnerable to IDOR.

### CSRF Scanner
Parses HTML forms and checks for missing anti-CSRF tokens. Also inspects session cookies for missing `SameSite` attribute. Detects state-changing forms that can be submitted cross-origin.

### JWT Scanner
Decodes JWT tokens and inspects the header for dangerous algorithms like `alg: none` or `alg: HS256` when the server expects RS256. Tests for weak secret brute-force and JWK header injection vulnerabilities.

## Input File Format

```
https://target1.com
https://target2.com
target3.com
```

## References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)

## Author

**Ridhin V A** ([@c_y_p_h3r](https://x.com/c_y_p_h3r))

## Disclaimer

For authorized security testing and educational purposes only.


## Disclaimer

For authorized security testing and educational purposes only.
