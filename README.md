# PhantomRange

```
    ___  __                __               ___
   / _ \/ /  ___ ____  ___/ /____  __ _    / _ \___ ____  ___ ____
  / ___/ _ \/ _ '/ _ \/ __/ __/ _ \/  ' \  / , _/ _ '/ _ \/ _ '/ -_)
 /_/  /_//_/\_,_/_//_/\__/\__/\___/_/_/_/ /_/|_|\_,_/_//_/\_, /\__/
                                                          /___/
```

**A vulnerable training environment for penetration testers.** Practice real-world web vulnerabilities with guided challenges, flags, and walkthroughs.

---

## Quick Start

```bash
git clone https://github.com/Phantom-C2-77/PhantomRange.git
cd PhantomRange
go run ./cmd/server/
```

Open **http://localhost:8080** and start hacking.

## Challenges

### SQL Injection (4 challenges)
| # | Challenge | Difficulty | Points |
|---|-----------|-----------|--------|
| 1 | Login Bypass | Easy | 100 |
| 2 | Data Exfiltration (UNION) | Easy | 150 |
| 3 | Blind SQL Injection | Medium | 250 |
| 4 | Second-Order SQLi | Hard | 350 |

### Cross-Site Scripting (4 challenges)
| # | Challenge | Difficulty | Points |
|---|-----------|-----------|--------|
| 1 | Reflected XSS | Easy | 100 |
| 2 | Stored XSS (Guestbook) | Easy | 150 |
| 3 | DOM-Based XSS | Medium | 200 |
| 4 | XSS Filter Bypass | Hard | 300 |

### Command Injection (3 challenges)
| # | Challenge | Difficulty | Points |
|---|-----------|-----------|--------|
| 1 | Basic Command Injection | Easy | 100 |
| 2 | Blind Command Injection | Medium | 200 |
| 3 | Filtered Command Injection | Hard | 300 |

**Total: 11 challenges, 1750 points**

More categories coming: Authentication, IDOR, SSRF, File Upload, Cryptography

## Features

- **Zero dependencies** — single Go binary, everything embedded
- **11 challenges** across 3 categories with 3 difficulty levels
- **Real flags** — `FLAG{...}` hidden in each challenge
- **Scoreboard** — track your progress and points
- **Hints** — available for each challenge
- **Walkthroughs** — step-by-step solutions in `docs/walkthroughs/`
- **Reset** — clear all progress with one click

## Walkthroughs

See [docs/walkthroughs/](docs/walkthroughs/) for step-by-step solutions.

## Disclaimer

**This application is intentionally vulnerable.** Do NOT expose it to the internet. Run it locally or in an isolated environment for training purposes only.

## Author

**Opeyemi Kolawole** — [GitHub](https://github.com/Phantom-C2-77)

## License

BSD 3-Clause
