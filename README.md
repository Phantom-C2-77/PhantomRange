<p align="center">
  <img src="docs/assets/screenshot-homepage.png" alt="PhantomShop" width="700">
</p>

<h1 align="center">PhantomShop</h1>

<p align="center">
  <strong>A realistic vulnerable e-commerce application for penetration testing training</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/vulnerabilities-50-red?style=flat-square" alt="50 Vulnerabilities">
  <img src="https://img.shields.io/badge/categories-18-purple?style=flat-square" alt="18 Categories">
  <img src="https://img.shields.io/badge/points-10%2C400-blue?style=flat-square" alt="10,400 Points">
  <img src="https://img.shields.io/badge/language-Go-00ADD8?style=flat-square&logo=go&logoColor=white" alt="Go">
  <img src="https://img.shields.io/badge/license-BSD--3-green?style=flat-square" alt="License">
  <img src="https://img.shields.io/badge/docker-ready-2496ED?style=flat-square&logo=docker&logoColor=white" alt="Docker">
</p>

---

PhantomShop is a fully functional online fashion store with **50 hidden security vulnerabilities** across **18 categories**. Built for security professionals, students, and CTF enthusiasts who want hands-on practice exploiting real-world web application flaws — not contrived textbook examples.

Every vulnerability is embedded naturally into working e-commerce features: product search, checkout, user profiles, admin panels, APIs, and more.

## Screenshots

<p align="center">
  <img src="docs/assets/screenshot-products.png" alt="Products" width="48%">
  <img src="docs/assets/screenshot-vulns.png" alt="Vulnerabilities" width="48%">
</p>
<p align="center">
  <img src="docs/assets/screenshot-scoreboard.png" alt="Scoreboard" width="48%">
</p>

## Quick Start

### Docker (recommended)

```bash
git clone https://github.com/Phantom-C2-77/PhantomRange.git
cd PhantomRange
docker compose up -d
# Open http://localhost:9000
```

### From Source

```bash
git clone https://github.com/Phantom-C2-77/PhantomRange.git
cd PhantomRange
make run
# Or: go run ./cmd/server/
```

### Using Make

```bash
make build          # Compile binary
make run            # Build and run
make docker-build   # Build Docker image
make docker-run     # Start with Docker Compose
make docker-stop    # Stop containers
make reset-db       # Wipe database (re-seeds on restart)
```

**Requirements:** Go 1.22+ or Docker

---

## Features

**Realistic E-Commerce Store**
- Product browsing, search, and category filtering
- User registration, login, profiles, and avatars
- Shopping cart, checkout, and coupon system
- Product reviews and ratings
- Admin panel with invoice generation
- REST API endpoints
- Newsletter, contact form, gift cards

**Security Training Platform**
- 50 flags hidden across the application
- Built-in vulnerability tracker at `/vulns`
- Live scoreboard with progress tracking at `/scoreboard`
- Difficulty ratings: Easy, Medium, Hard
- 10,400 total points to earn

---

## Vulnerability Categories

| Category | Flags | Description |
|----------|-------|-------------|
| SQL Injection | 6 | Login bypass, UNION, blind, time-based, stacked queries |
| Cross-Site Scripting | 6 | Reflected, stored, DOM-based, SVG, href, CSP bypass |
| Authentication | 4 | Brute force, default creds, password leak, session tampering |
| IDOR | 4 | Order access, profile enumeration, review deletion, mass assignment |
| Business Logic | 6 | Price manipulation, negative discounts, race conditions, gift card forgery |
| SSRF | 3 | Internal services, cloud metadata, file protocol |
| File Upload | 4 | Shell upload, extension bypass, magic bytes, SVG XSS |
| Command Injection | 1 | OS command injection via invoice generator |
| Path Traversal | 2 | Image path traversal, export file download |
| Open Redirect | 2 | Login redirect, checkout callback |
| Information Disclosure | 3 | Debug endpoint, stack traces, exposed git config |
| Insecure Deserialization | 2 | Cookie manipulation, JSON injection |
| HTTP Security | 3 | Clickjacking, method tampering, CRLF injection |
| Cryptography | 1 | Predictable password reset tokens |
| CORS | 1 | Wildcard origin misconfiguration |
| XXE | 1 | XML external entity in product import |
| File Inclusion | 1 | Local file inclusion in template rendering |
| 2FA Bypass | 1 | Cookie-based 2FA bypass |

---

## How It Works

Every flag follows the format:

```
FLAG{s0m3th1ng_h3r3}
```

**Find flags** by exploiting vulnerabilities in the application. **Submit flags** via the scoreboard UI or API:

```bash
curl -X POST http://localhost:9000/flag \
  -H "Content-Type: application/json" \
  -d '{"flag":"FLAG{...}"}'
```

Track your progress at `http://localhost:9000/scoreboard`.

### Difficulty Breakdown

| Difficulty | Flags | What to Expect |
|-----------|-------|----------------|
| Easy | 12 | Foundational attacks, minimal tooling |
| Medium | 24 | Requires tools and technique chaining |
| Hard | 14 | Advanced exploitation, creative thinking |

---

## Recommended Tools

- [Burp Suite](https://portswigger.net/burp) — HTTP proxy and scanner
- [curl](https://curl.se/) — Command-line HTTP client
- [sqlmap](https://sqlmap.org/) — SQL injection automation
- [ffuf](https://github.com/ffuf/ffuf) — Web fuzzer
- [Python](https://python.org) — Scripting exploits
- Browser DevTools — Inspect requests, cookies, DOM

---

## Tips

- Explore every feature as a normal user first
- Check all input fields, URL parameters, cookies, and headers
- Look at HTTP responses carefully — errors and headers reveal information
- Not every vulnerability is on a web page — check the API too
- Some flags require chaining multiple vulnerabilities
- The admin panel exists, but you need to find your way in

---

## Architecture

```
PhantomRange/
  cmd/server/         Entry point
  internal/
    db/               SQLite database, schema, seed data
    shop/             HTTP handlers, routes, templates, static assets
  data/               Database file (auto-created)
  docs/               Screenshots
```

Single binary, zero config. Uses Go standard library + SQLite (pure Go driver). Database auto-seeds on first run with test users, products, coupons, and all 50 flags.

---

## Disclaimer

**This application is intentionally vulnerable.** Do NOT deploy it on a public network. Run it locally or in an isolated environment for training purposes only.

---

## Author

**Opeyemi Kolawole** — Penetration Tester

- GitHub: [Phantom-C2-77](https://github.com/Phantom-C2-77)

## License

BSD 3-Clause
