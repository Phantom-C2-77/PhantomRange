package shop

import (
	"crypto/md5"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/Phantom-C2-77/PhantomRange/internal/db"
)

// ══════════════════════════════════════════
//  HOMEPAGE
// ══════════════════════════════════════════

func handleHome(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	rows, _ := db.DB.Query("SELECT id, name, price, category, image FROM products LIMIT 8")
	defer rows.Close()

	var products string
	for rows.Next() {
		var id int
		var name, cat, img string
		var price float64
		rows.Scan(&id, &name, &price, &cat, &img)
		products += fmt.Sprintf(`
		<a href="/product/%d" class="product-card">
			<div class="product-img">%s</div>
			<div class="product-info">
				<div class="product-cat">%s</div>
				<h3>%s</h3>
				<div class="product-price">$%.2f</div>
			</div>
		</a>`, id, img, cat, name, price)
	}

	render(w, "PhantomShop", fmt.Sprintf(`
	<section class="hero">
		<div class="hero-content">
			<h1>PhantomShop</h1>
			<p>Premium fashion & accessories. <em>Intentionally vulnerable.</em></p>
			<div class="hero-btns">
				<a href="/products" class="btn">Shop Now</a>
				<a href="/vulns" class="btn btn-outline">View Vulnerabilities</a>
			</div>
		</div>
	</section>

	<section class="section">
		<div class="section-header">
			<h2>Featured Products</h2>
			<a href="/products" class="link">View All →</a>
		</div>
		<div class="product-grid">%s</div>
	</section>

	<section class="section">
		<div class="categories">
			<a href="/products?cat=Shoes" class="cat-card"><span>👟</span>Shoes</a>
			<a href="/products?cat=Clothing" class="cat-card"><span>👕</span>Clothing</a>
			<a href="/products?cat=Accessories" class="cat-card"><span>👜</span>Accessories</a>
		</div>
	</section>
	`, products))
}

// ══════════════════════════════════════════
//  PRODUCTS & SEARCH (SQLi, XSS)
// ══════════════════════════════════════════

func handleProducts(w http.ResponseWriter, r *http.Request) {
	cat := r.URL.Query().Get("cat")

	var rows interface{ Next() bool; Scan(...interface{}) error; Close() error }
	var err error
	if cat != "" {
		rows, err = db.DB.Query("SELECT id, name, price, category, image, description FROM products WHERE category = ?", cat)
	} else {
		rows, err = db.DB.Query("SELECT id, name, price, category, image, description FROM products")
	}
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer rows.Close()

	var products string
	for rows.Next() {
		var id int
		var name, categ, img, desc string
		var price float64
		rows.Scan(&id, &name, &price, &categ, &img, &desc)
		products += fmt.Sprintf(`
		<a href="/product/%d" class="product-card">
			<div class="product-img">%s</div>
			<div class="product-info">
				<div class="product-cat">%s</div>
				<h3>%s</h3>
				<div class="product-price">$%.2f</div>
			</div>
		</a>`, id, img, categ, name, price)
	}

	title := "All Products"
	if cat != "" {
		title = cat
	}

	render(w, title, fmt.Sprintf(`
	<section class="section">
		<div class="section-header"><h2>%s</h2></div>
		<div class="search-bar">
			<form method="GET" action="/search">
				<input type="text" name="q" placeholder="Search products..." class="search-input">
				<button type="submit" class="btn">Search</button>
			</form>
		</div>
		<div class="product-grid">%s</div>
	</section>`, title, products))
}

func handleSearch(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")

	if q == "" {
		http.Redirect(w, r, "/products", 302)
		return
	}

	// VULN: SQL Injection — direct string concatenation
	query := fmt.Sprintf("SELECT id, name, price, category, image FROM products WHERE name LIKE '%%%s%%' OR description LIKE '%%%s%%'", q, q)
	rows, err := db.DB.Query(query)

	var products string
	if err != nil {
		products = fmt.Sprintf(`<div class="alert alert-danger">Error: %s</div>`, err.Error())
	} else {
		defer rows.Close()
		for rows.Next() {
			var id int
			var name, cat, img string
			var price float64
			rows.Scan(&id, &name, &price, &cat, &img)
			products += fmt.Sprintf(`
			<a href="/product/%d" class="product-card">
				<div class="product-img">%s</div>
				<div class="product-info">
					<div class="product-cat">%s</div>
					<h3>%s</h3>
					<div class="product-price">$%.2f</div>
				</div>
			</a>`, id, img, cat, name, price)
		}
	}

	if products == "" {
		products = `<div class="empty-state"><p>No products found.</p></div>`
	}

	// Detect flags
	flags := ""
	qLower := strings.ToLower(q)
	if strings.Contains(qLower, "union") && strings.Contains(qLower, "select") {
		flags += `<div class="flag-box">🚩 FLAG{un10n_s3l3ct_pr0ducts}</div>`
	}
	if strings.Contains(qLower, "<script") || strings.Contains(qLower, "onerror") || strings.Contains(qLower, "onload") || strings.Contains(qLower, "javascript:") {
		flags += `<div class="flag-box">🚩 FLAG{r3fl3ct3d_xss_sh0p}</div>`
	}

	// VULN: Reflected XSS — search term reflected without encoding
	render(w, "Search Results", fmt.Sprintf(`
	<section class="section">
		<div class="section-header"><h2>Search results for: %s</h2></div>
		<div class="search-bar">
			<form method="GET" action="/search">
				<input type="text" name="q" value="%s" class="search-input">
				<button type="submit" class="btn">Search</button>
			</form>
		</div>
		%s
		<div class="product-grid">%s</div>
	</section>`, q, q, flags, products)) // VULN: q is unescaped (XSS + SQLi)
}

func handleProductDetail(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/product/")
	id, _ := strconv.Atoi(idStr)

	var name, desc, cat, img string
	var price float64
	var stock int
	err := db.DB.QueryRow("SELECT name, description, price, category, image, stock FROM products WHERE id = ?", id).
		Scan(&name, &desc, &price, &cat, &img, &stock)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	// Get reviews
	rows, _ := db.DB.Query("SELECT username, rating, comment, created_at FROM reviews WHERE product_id = ? ORDER BY created_at DESC", id)
	defer rows.Close()

	var reviews string
	for rows.Next() {
		var user, comment, created string
		var rating int
		rows.Scan(&user, &rating, &comment, &created)
		stars := strings.Repeat("⭐", rating)
		// VULN: Stored XSS — comment not escaped
		reviews += fmt.Sprintf(`<div class="review"><div class="review-header"><strong>%s</strong> %s</div><p>%s</p></div>`, user, stars, comment)
	}

	if reviews == "" {
		reviews = `<p class="muted">No reviews yet. Be the first!</p>`
	}

	render(w, name, fmt.Sprintf(`
	<section class="product-detail">
		<div class="pd-img">%s</div>
		<div class="pd-info">
			<div class="product-cat">%s</div>
			<h1>%s</h1>
			<div class="product-price-lg">$%.2f</div>
			<p class="pd-desc">%s</p>
			<p class="stock">In stock: %d</p>

			<form method="POST" action="/cart/add" class="add-to-cart">
				<input type="hidden" name="product_id" value="%d">
				<input type="hidden" name="price" value="%.2f">
				<div class="qty-row">
					<label>Qty:</label>
					<input type="number" name="quantity" value="1" min="1" max="99" class="qty-input">
				</div>
				<button type="submit" class="btn btn-lg">Add to Cart</button>
			</form>
		</div>
	</section>

	<section class="section">
		<h2>Customer Reviews</h2>
		<form method="POST" action="/review" class="review-form">
			<input type="hidden" name="product_id" value="%d">
			<div class="form-row">
				<input type="text" name="username" placeholder="Your name" required>
				<select name="rating"><option value="5">⭐⭐⭐⭐⭐</option><option value="4">⭐⭐⭐⭐</option><option value="3">⭐⭐⭐</option><option value="2">⭐⭐</option><option value="1">⭐</option></select>
			</div>
			<textarea name="comment" placeholder="Write your review..." required></textarea>
			<button type="submit" class="btn">Post Review</button>
		</form>
		<div class="reviews-list">%s</div>
	</section>
	`, img, cat, name, price, desc, stock, id, price, id, reviews))
}

func handleReview(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Redirect(w, r, "/products", 302)
		return
	}

	productID := r.FormValue("product_id")
	username := r.FormValue("username")
	rating := r.FormValue("rating")
	comment := r.FormValue("comment")

	// VULN: Stored XSS — comment stored without sanitization
	db.DB.Exec("INSERT INTO reviews (product_id, user_id, username, rating, comment) VALUES (?, 0, ?, ?, ?)",
		productID, username, rating, comment)

	commentLower := strings.ToLower(comment)
	if strings.Contains(commentLower, "<script") || strings.Contains(commentLower, "onerror") || strings.Contains(commentLower, "onload") || strings.Contains(commentLower, "javascript:") {
		render(w, "Review Posted", fmt.Sprintf(`
		<div class="alert alert-success">Review posted!</div>
		<div class="flag-box">🚩 FLAG{st0r3d_xss_r3v13w}</div>
		<a href="/product/%s" class="btn">Back to Product</a>`, productID))
		return
	}

	http.Redirect(w, r, "/product/"+productID, 302)
}

// ══════════════════════════════════════════
//  AUTH (Brute Force, JWT, Session)
// ══════════════════════════════════════════

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		render(w, "Login", `
		<div class="auth-page">
			<div class="auth-card">
				<h2>Sign In</h2>
				<form method="POST" class="auth-form">
					<input type="text" name="username" placeholder="Username" required>
					<input type="password" name="password" placeholder="Password" required>
					<button type="submit" class="btn btn-full">Sign In</button>
				</form>
				<p class="auth-link">Don't have an account? <a href="/register">Sign up</a></p>
				<p class="auth-link"><a href="/forgot-password">Forgot password?</a></p>
			</div>
		</div>`)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	// VULN: SQL Injection in login
	query := fmt.Sprintf("SELECT id, username, role FROM users WHERE username='%s' AND password='%s'", username, password)
	var id int
	var user, role string
	err := db.DB.QueryRow(query).Scan(&id, &user, &role)

	if err != nil {
		// VULN: No rate limiting (brute force)
		render(w, "Login", `
		<div class="auth-page"><div class="auth-card">
			<h2>Sign In</h2>
			<div class="alert alert-danger">Invalid username or password.</div>
			<form method="POST" class="auth-form">
				<input type="text" name="username" placeholder="Username" required>
				<input type="password" name="password" placeholder="Password" required>
				<button type="submit" class="btn btn-full">Sign In</button>
			</form>
			<div class="info-box"><p>🚩 FLAG{n0_r4t3_l1m1t} — No rate limiting on this form!</p></div>
		</div></div>`)
		return
	}

	// Detect SQLi login bypass
	sqliFlag := ""
	isSQLi := strings.Contains(username, "'") || strings.Contains(username, "OR") || strings.Contains(username, "--") || strings.Contains(username, "=")
	if isSQLi {
		sqliFlag = "FLAG{sql_1nj3ct10n_l0g1n}"
	}
	// Detect default credentials
	defaultCredsFlag := ""
	if username == "admin" && password == "admin123" {
		defaultCredsFlag = "FLAG{d3f4ult_cr3ds}"
	}

	// Set session cookie
	http.SetCookie(w, &http.Cookie{Name: "user_id", Value: strconv.Itoa(id), Path: "/", MaxAge: 86400})
	http.SetCookie(w, &http.Cookie{Name: "username", Value: user, Path: "/", MaxAge: 86400})
	http.SetCookie(w, &http.Cookie{Name: "role", Value: role, Path: "/", MaxAge: 86400}) // VULN: Role in cookie (tamperable)

	if sqliFlag != "" || defaultCredsFlag != "" {
		flags := ""
		if sqliFlag != "" {
			flags += fmt.Sprintf(`<div class="flag-box">🚩 %s</div>`, sqliFlag)
		}
		if defaultCredsFlag != "" {
			flags += fmt.Sprintf(`<div class="flag-box">🚩 %s</div>`, defaultCredsFlag)
		}
		render(w, "Login Success", fmt.Sprintf(`
		<div class="auth-page"><div class="auth-card">
			<h2>Welcome, %s!</h2>
			<div class="alert alert-success">Logged in as %s (role: %s)</div>
			%s
			<a href="/" class="btn">Continue</a>
		</div></div>`, user, user, role, flags))
		return
	}

	http.Redirect(w, r, "/", 302)
}

func handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		render(w, "Register", `
		<div class="auth-page"><div class="auth-card">
			<h2>Create Account</h2>
			<form method="POST" class="auth-form">
				<input type="text" name="username" placeholder="Username" required>
				<input type="email" name="email" placeholder="Email" required>
				<input type="password" name="password" placeholder="Password" required>
				<button type="submit" class="btn btn-full">Create Account</button>
			</form>
			<p class="auth-link">Already have an account? <a href="/login">Sign in</a></p>
		</div></div>`)
		return
	}

	username := r.FormValue("username")
	email := r.FormValue("email")
	password := r.FormValue("password")
	db.DB.Exec("INSERT INTO users (username, email, password) VALUES (?, ?, ?)", username, email, password)
	http.Redirect(w, r, "/login", 302)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: "user_id", Value: "", Path: "/", MaxAge: -1})
	http.SetCookie(w, &http.Cookie{Name: "username", Value: "", Path: "/", MaxAge: -1})
	http.SetCookie(w, &http.Cookie{Name: "role", Value: "", Path: "/", MaxAge: -1})
	http.Redirect(w, r, "/", 302)
}

func handleForgotPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		render(w, "Forgot Password", `
		<div class="auth-page"><div class="auth-card">
			<h2>Reset Password</h2>
			<form method="POST" class="auth-form">
				<input type="email" name="email" placeholder="Email address" required>
				<button type="submit" class="btn btn-full">Send Reset Link</button>
			</form>
		</div></div>`)
		return
	}

	email := r.FormValue("email")
	// VULN: Predictable reset token (MD5 of email + timestamp with low resolution)
	token := fmt.Sprintf("%x", md5.Sum([]byte(email+time.Now().Format("2006-01-02"))))
	db.DB.Exec("UPDATE users SET reset_token = ? WHERE email = ?", token, email)

	render(w, "Forgot Password", fmt.Sprintf(`
	<div class="auth-page"><div class="auth-card">
		<h2>Reset Link Sent</h2>
		<div class="alert alert-success">If the email exists, a reset link has been sent.</div>
		<div class="info-box"><p><strong>Debug (intentionally shown):</strong> Reset link: <a href="/reset-password?token=%s">/reset-password?token=%s</a></p></div>
	</div></div>`, token, token))
}

func handleResetPassword(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		render(w, "Reset Password", `<div class="alert alert-danger">Invalid token.</div>`)
		return
	}

	if r.Method == "GET" {
		render(w, "Reset Password", fmt.Sprintf(`
		<div class="auth-page"><div class="auth-card">
			<h2>Set New Password</h2>
			<form method="POST" class="auth-form">
				<input type="hidden" name="token" value="%s">
				<input type="password" name="password" placeholder="New password" required>
				<button type="submit" class="btn btn-full">Reset Password</button>
			</form>
		</div></div>`, token))
		return
	}

	password := r.FormValue("password")
	token = r.FormValue("token")

	// Check which user this token belongs to (for flag detection)
	var resetEmail string
	db.DB.QueryRow("SELECT email FROM users WHERE reset_token = ?", token).Scan(&resetEmail)

	result, _ := db.DB.Exec("UPDATE users SET password = ?, reset_token = '' WHERE reset_token = ?", password, token)
	affected, _ := result.RowsAffected()
	if affected > 0 {
		flag := ""
		if resetEmail != "" {
			// Token was predictable (MD5 of email + date) — if they got here, they predicted it
			flag = `<div class="flag-box">🚩 FLAG{pr3d1ct4bl3_t0k3n}</div>
			<div class="info-box"><p>You predicted the reset token! Token = MD5(email + YYYY-MM-DD)</p></div>`
		}
		render(w, "Reset Password", fmt.Sprintf(`<div class="alert alert-success">Password reset! <a href="/login">Login</a></div>%s`, flag))
	} else {
		render(w, "Reset Password", `<div class="alert alert-danger">Invalid or expired token.</div>`)
	}
}

// ══════════════════════════════════════════
//  PROFILE (IDOR, XSS, File Upload)
// ══════════════════════════════════════════

func handleProfile(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("id")
	if userID == "" {
		c, _ := r.Cookie("user_id")
		if c != nil {
			userID = c.Value
		}
	}
	if userID == "" {
		http.Redirect(w, r, "/login", 302)
		return
	}

	// VULN: IDOR — can view any user profile by changing id
	var username, email, role, bio, avatar string
	err := db.DB.QueryRow("SELECT username, email, role, bio, avatar FROM users WHERE id = ?", userID).
		Scan(&username, &email, &role, &bio, &avatar)
	if err != nil {
		render(w, "Profile", `<div class="alert alert-danger">User not found.</div>`)
		return
	}

	if avatar == "" {
		avatar = "👤"
	}

	// VULN: DOM XSS — bio rendered without encoding
	render(w, "Profile — "+username, fmt.Sprintf(`
	<div class="profile-page">
		<div class="profile-card">
			<div class="profile-avatar">%s</div>
			<h2>%s</h2>
			<span class="badge">%s</span>
			<p class="profile-email">%s</p>
			<div class="profile-bio">%s</div>
		</div>
	</div>`, avatar, username, role, email, bio))
}

func handleProfileEdit(w http.ResponseWriter, r *http.Request) {
	c, _ := r.Cookie("user_id")
	if c == nil {
		http.Redirect(w, r, "/login", 302)
		return
	}

	if r.Method == "POST" {
		bio := r.FormValue("bio")
		// VULN: Stored XSS via bio field
		db.DB.Exec("UPDATE users SET bio = ? WHERE id = ?", bio, c.Value)

		bioLower := strings.ToLower(bio)
		if strings.Contains(bioLower, "<img") || strings.Contains(bioLower, "<script") || strings.Contains(bioLower, "onerror") || strings.Contains(bioLower, "onload") {
			render(w, "Profile Updated", `
			<div class="alert alert-success">Profile updated!</div>
			<div class="flag-box">🚩 FLAG{d0m_xss_pr0f1l3}</div>
			<a href="/profile" class="btn">View Profile</a>`)
			return
		}

		http.Redirect(w, r, "/profile", 302)
		return
	}

	var bio string
	db.DB.QueryRow("SELECT bio FROM users WHERE id = ?", c.Value).Scan(&bio)

	render(w, "Edit Profile", fmt.Sprintf(`
	<div class="auth-page"><div class="auth-card">
		<h2>Edit Profile</h2>
		<form method="POST" class="auth-form">
			<textarea name="bio" placeholder="Tell us about yourself...">%s</textarea>
			<button type="submit" class="btn btn-full">Save</button>
		</form>
	</div></div>`, bio))
}

func handleAvatarUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		render(w, "Upload Avatar", `
		<div class="auth-page"><div class="auth-card">
			<h2>Upload Avatar</h2>
			<form method="POST" enctype="multipart/form-data" class="auth-form">
				<input type="file" name="avatar" required>
				<button type="submit" class="btn btn-full">Upload</button>
			</form>
			<div class="info-box"><p>Supported: jpg, png, gif</p></div>
		</div></div>`)
		return
	}

	c, _ := r.Cookie("user_id")
	if c == nil {
		http.Redirect(w, r, "/login", 302)
		return
	}

	file, header, err := r.FormFile("avatar")
	if err != nil {
		render(w, "Upload Avatar", `<div class="alert alert-danger">Upload failed.</div>`)
		return
	}
	defer file.Close()

	content, _ := io.ReadAll(io.LimitReader(file, 1<<20))

	// VULN: No file type validation — can upload anything
	ext := header.Filename[strings.LastIndex(header.Filename, "."):]
	filename := fmt.Sprintf("avatar_%s%s", c.Value, ext)
	_ = content
	_ = filename

	db.DB.Exec("UPDATE users SET avatar = ? WHERE id = ?", "📸", c.Value)

	flag := ""
	lowerName := strings.ToLower(header.Filename)
	contentStr := string(content)
	contentLower := strings.ToLower(contentStr)
	if strings.Contains(lowerName, ".php") || strings.Contains(lowerName, ".jsp") ||
		strings.Contains(contentStr, "<?php") || strings.Contains(contentStr, "PHANTOM_SHELL") {
		flag = `<div class="flag-box">🚩 FLAG{sh3ll_upl04d_4v4t4r}</div>`
	}
	// Double extension bypass
	if strings.Contains(lowerName, ".php.") || strings.Contains(lowerName, ".jsp.") || strings.Contains(lowerName, ".aspx.") {
		flag += `<div class="flag-box">🚩 FLAG{d0ubl3_3xt3ns10n}</div>`
	}
	// SVG XSS
	if strings.HasSuffix(lowerName, ".svg") || strings.Contains(contentLower, "<svg") {
		if strings.Contains(contentLower, "onload") || strings.Contains(contentLower, "onerror") || strings.Contains(contentLower, "<script") {
			flag += `<div class="flag-box">🚩 FLAG{svg_xss_upl04d}</div>`
		}
	}
	// Magic bytes bypass (JPEG header + PHP/script content)
	if len(content) > 4 && content[0] == 0xFF && content[1] == 0xD8 && content[2] == 0xFF {
		if strings.Contains(contentStr, "<?php") || strings.Contains(contentStr, "<script") {
			flag += `<div class="flag-box">🚩 FLAG{m4g1c_byt3s}</div>`
		}
	}

	render(w, "Upload Avatar", fmt.Sprintf(`
		<div class="alert alert-success">Avatar uploaded: %s (%d bytes)</div>%s
		<a href="/profile" class="btn">View Profile</a>
	`, header.Filename, len(content), flag))
}

// ══════════════════════════════════════════
//  CART & CHECKOUT (Business Logic)
// ══════════════════════════════════════════

func handleCart(w http.ResponseWriter, r *http.Request) {
	render(w, "Shopping Cart", `
	<section class="section">
		<h2>Shopping Cart</h2>
		<div class="info-box"><p>Cart is stored in cookies (client-side). Add items from product pages.</p></div>
		<a href="/products" class="btn">Continue Shopping</a>
		<a href="/checkout" class="btn">Checkout</a>
	</section>`)
}

func handleCartAdd(w http.ResponseWriter, r *http.Request) {
	productID := r.FormValue("product_id")
	price := r.FormValue("price")   // VULN: Price from client-side (manipulable)
	quantity := r.FormValue("quantity") // VULN: No validation on negative quantities

	qty, _ := strconv.Atoi(quantity)
	p, _ := strconv.ParseFloat(price, 64)
	pid, _ := strconv.Atoi(productID)

	flag := ""
	if p < 1 {
		flag = `<div class="flag-box">🚩 FLAG{pr1c3_m4n1pul4t10n}</div><div class="info-box"><p>You changed the price in the request! The server trusts client-submitted prices.</p></div>`
	}
	if qty < 0 {
		flag += `<div class="flag-box">🚩 FLAG{n3g4t1v3_qu4nt1ty}</div><div class="info-box"><p>Negative quantity! This could give you a refund.</p></div>`
	}
	// VULN: SKU Swap — check if submitted price doesn't match actual product price
	if pid > 0 && p >= 1 {
		var realPrice float64
		err := db.DB.QueryRow("SELECT price FROM products WHERE id = ?", pid).Scan(&realPrice)
		if err == nil && realPrice > 0 && p < realPrice*0.5 {
			flag += `<div class="flag-box">🚩 FLAG{sku_sw4p_ch34p}</div><div class="info-box"><p>SKU swap! Product price doesn't match — you swapped to a cheaper SKU.</p></div>`
		}
	}

	total := p * float64(qty)

	render(w, "Added to Cart", fmt.Sprintf(`
	<div class="alert alert-success">Added %s × %d to cart. Total: $%.2f</div>
	%s
	<a href="/products" class="btn">Continue Shopping</a>
	<a href="/checkout" class="btn">Checkout</a>
	`, productID, qty, total, flag))
}

func handleCheckout(w http.ResponseWriter, r *http.Request) {
	render(w, "Checkout", `
	<div class="auth-page"><div class="auth-card" style="max-width:500px">
		<h2>Checkout</h2>
		<form method="POST" action="/apply-coupon" class="auth-form">
			<input type="text" name="coupon" placeholder="Coupon code (optional)">
			<input type="text" name="total" placeholder="Order total" value="199.99">
			<button type="submit" class="btn btn-full">Apply & Place Order</button>
		</form>
	</div></div>`)
}

func handleApplyCoupon(w http.ResponseWriter, r *http.Request) {
	code := r.FormValue("coupon")
	totalStr := r.FormValue("total")
	total, _ := strconv.ParseFloat(totalStr, 64)

	if code != "" {
		var discount float64
		err := db.DB.QueryRow("SELECT discount FROM coupons WHERE code = ?", code).Scan(&discount)
		if err == nil {
			// VULN: Negative discount coupon adds money
			total = total - (total * discount / 100)

			flag := ""
			if discount < 0 {
				flag = `<div class="flag-box">🚩 FLAG{c0up0n_4bus3}</div><div class="info-box"><p>Negative discount coupon! The total went UP instead of down.</p></div>`
			}
			if discount >= 100 {
				flag += `<div class="info-box"><p>100% discount — free order!</p></div>`
			}

			render(w, "Order Placed", fmt.Sprintf(`
			<div class="alert alert-success">Coupon %s applied! Discount: %.0f%%</div>
			<div class="order-total">Order Total: $%.2f</div>
			%s
			<a href="/" class="btn">Continue Shopping</a>
			`, code, discount, total, flag))
			return
		}
	}

	render(w, "Order Placed", fmt.Sprintf(`
	<div class="alert alert-success">Order placed! Total: $%.2f</div>
	<a href="/" class="btn">Continue Shopping</a>
	`, total))
}

// ══════════════════════════════════════════
//  ORDERS (IDOR)
// ══════════════════════════════════════════

func handleOrders(w http.ResponseWriter, r *http.Request) {
	c, _ := r.Cookie("user_id")
	if c == nil {
		http.Redirect(w, r, "/login", 302)
		return
	}
	render(w, "My Orders", `
	<section class="section">
		<h2>My Orders</h2>
		<div class="info-box"><p>Order #1001: $199.99 — Pending</p><p>Order #1002: $89.99 — Shipped</p></div>
		<p>View order: <a href="/order/1001">#1001</a> | <a href="/order/1002">#1002</a></p>
	</section>`)
}

func handleOrderDetail(w http.ResponseWriter, r *http.Request) {
	orderID := strings.TrimPrefix(r.URL.Path, "/order/")

	// VULN: IDOR — no authorization check
	flag := ""
	if orderID == "1337" {
		flag = `<div class="flag-box">🚩 FLAG{1d0r_0rd3r_4cc3ss}</div>`
	}

	// VULN: Blind SQLi — order ID injected into raw SQL
	query := fmt.Sprintf("SELECT id FROM orders WHERE id=%s", orderID)
	var oid int
	db.DB.QueryRow(query).Scan(&oid)

	if strings.Contains(strings.ToUpper(orderID), "AND") || strings.Contains(strings.ToUpper(orderID), "SUBSTRING") || strings.Contains(strings.ToUpper(orderID), "CASE") {
		flag += `<div class="flag-box">🚩 FLAG{bl1nd_sql1_3xtr4ct}</div>`
	}

	render(w, "Order #"+orderID, fmt.Sprintf(`
	<section class="section">
		<h2>Order #%s</h2>
		<div class="profile-card">
			<p><strong>Status:</strong> Processing</p>
			<p><strong>Total:</strong> $199.99</p>
			<p><strong>Date:</strong> 2026-03-28</p>
		</div>
		%s
	</section>`, orderID, flag))
}

// ══════════════════════════════════════════
//  API (CORS, IDOR, SSRF)
// ══════════════════════════════════════════

func handleAPIUser(w http.ResponseWriter, r *http.Request) {
	// VULN: CORS misconfiguration
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "*")
	w.Header().Set("Access-Control-Allow-Methods", "*")

	idStr := strings.TrimPrefix(r.URL.Path, "/api/user/")
	id, _ := strconv.Atoi(idStr)

	var username, email, role string
	err := db.DB.QueryRow("SELECT username, email, role FROM users WHERE id = ?", id).Scan(&username, &email, &role)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(404)
		json.NewEncoder(w).Encode(map[string]string{"error": "user not found"})
		return
	}

	resp := map[string]interface{}{"id": id, "username": username, "email": email, "role": role}
	if role == "admin" {
		resp["flag"] = "FLAG{1d0r_pr0f1l3_l34k}"
	}

	// CORS flag — detect external origin
	origin := r.Header.Get("Origin")
	if origin != "" && !strings.Contains(origin, "localhost") && !strings.Contains(origin, "127.0.0.1") {
		resp["cors_flag"] = "FLAG{c0rs_m1sc0nf1g}"
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func handleAPIProducts(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	rows, _ := db.DB.Query("SELECT id, name, price, category FROM products")
	defer rows.Close()

	var products []map[string]interface{}
	for rows.Next() {
		var id int
		var name, cat string
		var price float64
		rows.Scan(&id, &name, &price, &cat)
		products = append(products, map[string]interface{}{"id": id, "name": name, "price": price, "category": cat})
	}
	json.NewEncoder(w).Encode(products)
}

func handleAPIOrder(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	orderID := strings.TrimPrefix(r.URL.Path, "/api/order/")

	resp := map[string]interface{}{
		"id": orderID, "status": "processing", "total": 199.99,
	}
	if orderID == "1337" {
		resp["flag"] = "FLAG{1d0r_0rd3r_4cc3ss}"
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func handleNewsletter(w http.ResponseWriter, r *http.Request) {
	url := r.URL.Query().Get("url")
	if url == "" {
		url = r.FormValue("url")
	}

	if url != "" {
		var content string

		// VULN: SSRF — fetches any URL including file:// protocol
		if strings.HasPrefix(strings.ToLower(url), "file://") {
			// VULN: file:// protocol — read local files
			filePath := strings.TrimPrefix(url, "file://")
			data, err := os.ReadFile(filePath)
			if err == nil {
				content = string(data)
				if len(content) > 5000 {
					content = content[:5000] + "\n... (truncated)"
				}
			} else {
				content = "Error reading file: " + err.Error()
			}
			flag := `<div class="flag-box">🚩 FLAG{f1l3_pr0t0c0l}</div>`
			render(w, "Newsletter", fmt.Sprintf(`
			<div class="alert alert-danger">SSRF with file:// protocol!</div>
			<div class="output-box"><pre>%s</pre></div>%s`, content, flag))
			return
		}

		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Get(url)
		if err == nil {
			defer resp.Body.Close()
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 10000))
			content = string(body)

			flag := ""
			if strings.Contains(content, "FLAG{") {
				start := strings.Index(content, "FLAG{")
				end := strings.Index(content[start:], "}") + start + 1
				flag = fmt.Sprintf(`<div class="flag-box">🚩 %s</div>`, content[start:end])
			}

			w.Header().Set("Content-Type", "text/html")
			render(w, "Newsletter", fmt.Sprintf(`
			<div class="alert alert-success">URL fetched!</div>
			<div class="output-box"><pre>%s</pre></div>%s`, content, flag))
			return
		}
	}

	render(w, "Newsletter", `
	<div class="auth-page"><div class="auth-card">
		<h2>Subscribe to Newsletter</h2>
		<form method="POST" class="auth-form">
			<input type="email" name="email" placeholder="Your email" required>
			<input type="text" name="url" placeholder="Your blog/website URL (we'll feature it!)">
			<button type="submit" class="btn btn-full">Subscribe</button>
		</form>
	</div></div>`)
}

// ══════════════════════════════════════════
//  ADMIN (Command Injection, XXE)
// ══════════════════════════════════════════

func handleAdmin(w http.ResponseWriter, r *http.Request) {
	// VULN: Only checks cookie (tamperable)
	c, _ := r.Cookie("role")
	if c == nil || c.Value != "admin" {
		render(w, "Admin", `<div class="alert alert-danger">Access denied. Admin only.</div><div class="info-box"><p>Hint: How is the role determined? Check your cookies...</p></div>`)
		return
	}

	// Detect cookie tampering: if role=admin but user_id cookie doesn't match a real admin
	flag := ""
	uidCookie, _ := r.Cookie("user_id")
	if uidCookie != nil {
		var realRole string
		db.DB.QueryRow("SELECT role FROM users WHERE id = ?", uidCookie.Value).Scan(&realRole)
		if realRole != "admin" {
			flag = `<div class="flag-box">🚩 FLAG{w34k_jwt_s3cr3t}</div>
			<div class="flag-box">🚩 FLAG{2f4_byp4ss_sk1p}</div>
			<div class="info-box"><p>You tampered with the role cookie to bypass access control and 2FA!</p></div>`
		}
	} else {
		// No user_id cookie but role=admin — definitely tampered
		flag = `<div class="flag-box">🚩 FLAG{w34k_jwt_s3cr3t}</div>
		<div class="flag-box">🚩 FLAG{2f4_byp4ss_sk1p}</div>`
	}

	render(w, "Admin Panel", fmt.Sprintf(`
	<section class="section">
		<h2>Admin Panel</h2>
		%s
		<div class="admin-grid">
			<a href="/admin/invoice" class="cat-card"><span>📄</span>Generate Invoice</a>
			<a href="/api/export" class="cat-card"><span>📤</span>Export Products</a>
			<a href="/api/import" class="cat-card"><span>📥</span>Import Products (XML)</a>
		</div>
	</section>`, flag))
}

func handleInvoice(w http.ResponseWriter, r *http.Request) {
	orderID := r.URL.Query().Get("order")
	if orderID == "" {
		render(w, "Generate Invoice", `
		<div class="auth-page"><div class="auth-card">
			<h2>Generate Invoice</h2>
			<form method="GET" class="auth-form">
				<input type="text" name="order" placeholder="Order ID" required>
				<button type="submit" class="btn btn-full">Generate</button>
			</form>
		</div></div>`)
		return
	}

	// VULN: Command injection in invoice generation
	var cmd string
	if runtime.GOOS == "windows" {
		cmd = fmt.Sprintf("echo Invoice for order %s generated", orderID)
	} else {
		cmd = fmt.Sprintf("echo 'Invoice for order %s generated at '$(date)", orderID)
	}
	output, err := exec.Command("sh", "-c", cmd).CombinedOutput()

	flag := ""
	if strings.Contains(orderID, ";") || strings.Contains(orderID, "`") || strings.Contains(orderID, "$(") || strings.Contains(orderID, "|") {
		flag = `<div class="flag-box">🚩 FLAG{cmd_1nj3ct_pdf}</div>`
	}

	result := string(output)
	if err != nil {
		result += "\n" + err.Error()
	}

	render(w, "Invoice", fmt.Sprintf(`
	<div class="output-box"><pre>%s</pre></div>%s
	<a href="/admin" class="btn">Back</a>`, result, flag))
}

func handleExport(w http.ResponseWriter, r *http.Request) {
	rows, _ := db.DB.Query("SELECT id, name, price, category FROM products")
	defer rows.Close()

	type Product struct {
		XMLName xml.Name `xml:"product"`
		ID      int      `xml:"id"`
		Name    string   `xml:"name"`
		Price   float64  `xml:"price"`
		Cat     string   `xml:"category"`
	}
	type Products struct {
		XMLName xml.Name  `xml:"products"`
		Items   []Product `xml:"product"`
	}

	var prods Products
	for rows.Next() {
		var p Product
		rows.Scan(&p.ID, &p.Name, &p.Price, &p.Cat)
		prods.Items = append(prods.Items, p)
	}

	w.Header().Set("Content-Type", "application/xml")
	w.Header().Set("Content-Disposition", "attachment; filename=products.xml")
	xml.NewEncoder(w).Encode(prods)
}

func handleImport(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		render(w, "Import Products", `
		<div class="auth-page"><div class="auth-card">
			<h2>Import Products (XML)</h2>
			<form method="POST" enctype="multipart/form-data" class="auth-form">
				<input type="file" name="xml" accept=".xml" required>
				<button type="submit" class="btn btn-full">Import</button>
			</form>
			<div class="info-box"><p>Upload an XML file with product data.</p></div>
		</div></div>`)
		return
	}

	file, _, err := r.FormFile("xml")
	if err != nil {
		render(w, "Import", `<div class="alert alert-danger">Upload failed.</div>`)
		return
	}
	defer file.Close()

	data, _ := io.ReadAll(io.LimitReader(file, 1<<20))

	// VULN: XXE — parses XML without disabling external entities
	// Note: Go's encoding/xml doesn't process external entities by default,
	// but the flag triggers if the XML contains entity declarations
	flag := ""
	content := string(data)
	if strings.Contains(content, "<!ENTITY") || strings.Contains(content, "SYSTEM") || strings.Contains(content, "file://") {
		flag = `<div class="flag-box">🚩 FLAG{xx3_f1l3_r34d}</div><div class="info-box"><p>XXE attempt detected! In a real Java/.NET app, this would read local files.</p></div>`
	}

	render(w, "Import Results", fmt.Sprintf(`
	<div class="alert alert-success">XML processed (%d bytes)</div>
	<div class="output-box"><pre>%s</pre></div>%s
	<a href="/admin" class="btn">Back</a>`, len(data), content, flag))
}

// ══════════════════════════════════════════
//  CONTACT (CRLF)
// ══════════════════════════════════════════

func handleContact(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		redirect := r.URL.Query().Get("redirect")
		if redirect != "" {
			// VULN: CRLF injection in redirect header
			if strings.Contains(redirect, "\r") || strings.Contains(redirect, "\n") ||
				strings.Contains(redirect, "Set-Cookie") || strings.Contains(redirect, "%0d%0a") {
				render(w, "CRLF Injection", fmt.Sprintf(`
				<div class="alert alert-danger">CRLF injection detected! Target: %s</div>
				<div class="flag-box">🚩 FLAG{crlf_h34d3r_1nj3ct}</div>`, redirect))
				return
			}
			w.Header().Set("Location", redirect)
			w.WriteHeader(302)
			return
		}

		render(w, "Contact Us", `
		<div class="auth-page"><div class="auth-card" style="max-width:500px">
			<h2>Contact Us</h2>
			<form method="POST" class="auth-form">
				<input type="text" name="name" placeholder="Your name" required>
				<input type="email" name="email" placeholder="Your email" required>
				<input type="text" name="subject" placeholder="Subject" required>
				<textarea name="message" placeholder="Your message..." required></textarea>
				<button type="submit" class="btn btn-full">Send Message</button>
			</form>
		</div></div>`)
		return
	}

	name := r.FormValue("name")
	render(w, "Contact Us", fmt.Sprintf(`
	<div class="alert alert-success">Thanks %s! We'll get back to you soon.</div>
	<a href="/" class="btn">Back to Shop</a>`, name))
}

// ══════════════════════════════════════════
//  INTERNAL SERVICE (for SSRF)
// ══════════════════════════════════════════

func startInternalService() {
	mux := http.NewServeMux()
	mux.HandleFunc("/internal/admin", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "Internal Admin Panel\n\nSecret: FLAG{ssrf_1nt3rn4l}\nDB Password: phantom_db_2026\n")
	})
	mux.HandleFunc("/latest/meta-data/iam/security-credentials/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"AccessKeyId":"AKIAIOSFODNN7EXAMPLE","SecretAccessKey":"FLAG{cl0ud_m3t4d4t4}","Token":"FakeToken"}`)
	})
	http.ListenAndServe("127.0.0.1:9999", mux)
}
