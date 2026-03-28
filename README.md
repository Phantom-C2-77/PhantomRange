# PhantomShop

```
   ___  __                __             ____  __
  / _ \/ /  ___ ____  ___/ /____  __ _  / __/ / /  ___  ___
 / ___/ _ \/ _ '/ _ \/ __/ __/ _ \/  ' \_\ \ / _ \/ _ \/ _ \
/_/  /_//_/\_,_/_//_/\__/\__/\___/_/_/_/___//_//_/\___/ .__/
                                                      /_/
```

**A realistic vulnerable e-commerce application for penetration testing practice.** Not isolated challenges — a real shopping website with 22 vulnerabilities embedded naturally.

## Quick Start

```bash
git clone https://github.com/Phantom-C2-77/PhantomRange.git
cd PhantomRange
go run ./cmd/server/
# Open http://localhost:8080
```

## The Store

PhantomShop is a fashion store selling shoes, clothing, and accessories. Every feature has at least one vulnerability:

- Product catalog with search (SQLi, XSS)
- User registration and login (Auth bypass, brute force)
- Shopping cart and checkout (Business logic)
- Product reviews (Stored XSS)
- User profiles with avatars (IDOR, file upload)
- Admin panel (Command injection, XXE)
- REST API (CORS, IDOR)
- Newsletter (SSRF)
- Contact form (CRLF)
- Password reset (Weak crypto)

## Vulnerabilities (22 flags across 10 categories)

| Category | Vulns | Points | Where |
|----------|-------|--------|-------|
| SQL Injection | 3 | 500 | Login, search, orders |
| XSS | 3 | 450 | Search, reviews, profile |
| Command Injection | 1 | 200 | Admin invoice |
| Authentication | 3 | 600 | Login, password reset, 2FA |
| IDOR | 3 | 300 | Orders, profiles, API |
| SSRF | 1 | 200 | Newsletter |
| File Upload | 1 | 200 | Avatar |
| Business Logic | 3 | 700 | Prices, coupons, quantities |
| CORS/CRLF/XXE | 3 | 700 | API, contact, import |
| Crypto | 1 | 200 | Reset tokens |
| **Total** | **22** | **4,050** | |

## Walkthroughs

See [docs/walkthroughs/](docs/walkthroughs/) for solutions.

## Disclaimer

**Intentionally vulnerable.** Do NOT expose to the internet.

## Author

**Opeyemi Kolawole** — [GitHub](https://github.com/Phantom-C2-77)
