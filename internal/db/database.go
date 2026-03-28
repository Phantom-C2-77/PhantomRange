package db

import (
	"database/sql"
	"os"

	_ "modernc.org/sqlite"
)

var DB *sql.DB

func Init() {
	os.MkdirAll("data", 0755)
	var err error
	DB, err = sql.Open("sqlite", "data/shop.db")
	if err != nil {
		panic(err)
	}

	// Users
	DB.Exec(`CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE,
		email TEXT,
		password TEXT,
		role TEXT DEFAULT 'user',
		avatar TEXT DEFAULT '',
		bio TEXT DEFAULT '',
		reset_token TEXT DEFAULT '',
		otp_secret TEXT DEFAULT ''
	)`)

	// Products
	DB.Exec(`CREATE TABLE IF NOT EXISTS products (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT,
		description TEXT,
		price REAL,
		category TEXT,
		image TEXT,
		stock INTEGER DEFAULT 100
	)`)

	// Orders
	DB.Exec(`CREATE TABLE IF NOT EXISTS orders (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER,
		total REAL,
		status TEXT DEFAULT 'pending',
		coupon TEXT DEFAULT '',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`)

	// Order items
	DB.Exec(`CREATE TABLE IF NOT EXISTS order_items (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		order_id INTEGER,
		product_id INTEGER,
		quantity INTEGER,
		price REAL
	)`)

	// Reviews
	DB.Exec(`CREATE TABLE IF NOT EXISTS reviews (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		product_id INTEGER,
		user_id INTEGER,
		username TEXT,
		rating INTEGER,
		comment TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`)

	// Coupons
	DB.Exec(`CREATE TABLE IF NOT EXISTS coupons (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		code TEXT UNIQUE,
		discount REAL,
		max_uses INTEGER DEFAULT 1,
		used INTEGER DEFAULT 0
	)`)

	// Messages (contact form)
	DB.Exec(`CREATE TABLE IF NOT EXISTS messages (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT,
		email TEXT,
		subject TEXT,
		message TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`)

	// Flags
	DB.Exec(`CREATE TABLE IF NOT EXISTS flags (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT UNIQUE,
		value TEXT,
		category TEXT,
		difficulty TEXT,
		points INTEGER,
		description TEXT
	)`)

	// Seed data
	seedData()
}

func seedData() {
	// Check if already seeded
	var count int
	DB.QueryRow("SELECT COUNT(*) FROM products").Scan(&count)
	if count > 0 {
		return
	}

	// Admin user (password: admin123)
	DB.Exec(`INSERT INTO users (username, email, password, role, bio) VALUES ('admin', 'admin@phantomshop.com', 'admin123', 'admin', 'Store administrator')`)
	DB.Exec(`INSERT INTO users (username, email, password, role, bio) VALUES ('john', 'john@example.com', 'password123', 'user', 'Regular customer')`)
	DB.Exec(`INSERT INTO users (username, email, password, role, bio) VALUES ('jane', 'jane@example.com', 'letmein', 'user', 'VIP customer')`)
	DB.Exec(`INSERT INTO users (username, email, password, role, bio) VALUES ('support', 'support@phantomshop.com', 'support2026', 'moderator', 'Customer support')`)

	// Products — Fashion store
	products := []struct{ name, desc, cat, img string; price float64 }{
		{"Classic White Sneakers", "Premium leather sneakers with cushioned sole. Perfect for everyday wear.", "Shoes", "👟", 89.99},
		{"Black Running Shoes", "Lightweight mesh running shoes with responsive foam.", "Shoes", "🏃", 129.99},
		{"Leather Chelsea Boots", "Handcrafted Italian leather boots with elastic side panels.", "Shoes", "🥾", 199.99},
		{"Slim Fit Denim Jeans", "Stretch denim jeans with modern slim fit cut.", "Clothing", "👖", 59.99},
		{"Cotton Crew T-Shirt", "100% organic cotton tee in classic fit.", "Clothing", "👕", 24.99},
		{"Wool Blend Overcoat", "Tailored overcoat in premium wool blend. Water resistant.", "Clothing", "🧥", 249.99},
		{"Leather Crossbody Bag", "Genuine leather bag with adjustable strap and brass hardware.", "Accessories", "👜", 149.99},
		{"Aviator Sunglasses", "Polarized UV400 protection with metal frame.", "Accessories", "🕶️", 79.99},
		{"Automatic Watch", "Swiss movement watch with sapphire crystal and leather band.", "Accessories", "⌚", 399.99},
		{"Cashmere Scarf", "Ultra-soft 100% cashmere scarf. Made in Scotland.", "Accessories", "🧣", 119.99},
		{"High-Top Canvas Shoes", "Retro style canvas shoes with vulcanized rubber sole.", "Shoes", "👞", 69.99},
		{"Performance Hoodie", "Tech fleece hoodie with zippered pockets.", "Clothing", "🧶", 89.99},
	}

	for _, p := range products {
		DB.Exec(`INSERT INTO products (name, description, price, category, image) VALUES (?, ?, ?, ?, ?)`,
			p.name, p.desc, p.price, p.cat, p.img)
	}

	// Coupons
	DB.Exec(`INSERT INTO coupons (code, discount, max_uses) VALUES ('WELCOME10', 10.0, 100)`)
	DB.Exec(`INSERT INTO coupons (code, discount, max_uses) VALUES ('VIP50', 50.0, 1)`)
	DB.Exec(`INSERT INTO coupons (code, discount, max_uses) VALUES ('ADMIN100', 100.0, 1)`)
	DB.Exec(`INSERT INTO coupons (code, discount, max_uses) VALUES ('NEGATIVE', -500.0, 1)`) // Business logic vuln

	// Flags
	flags := []struct{ name, value, cat, diff, desc string; pts int }{
		{"sqli_login", "FLAG{sql_1nj3ct10n_l0g1n}", "SQL Injection", "Easy", "Bypass login with SQLi", 100},
		{"sqli_search", "FLAG{un10n_s3l3ct_pr0ducts}", "SQL Injection", "Easy", "Extract data via product search", 150},
		{"sqli_blind", "FLAG{bl1nd_sql1_3xtr4ct}", "SQL Injection", "Medium", "Blind SQLi on order lookup", 250},
		{"xss_search", "FLAG{r3fl3ct3d_xss_sh0p}", "XSS", "Easy", "XSS in product search", 100},
		{"xss_review", "FLAG{st0r3d_xss_r3v13w}", "XSS", "Easy", "Stored XSS in product reviews", 150},
		{"xss_profile", "FLAG{d0m_xss_pr0f1l3}", "XSS", "Medium", "DOM XSS in user profile bio", 200},
		{"idor_order", "FLAG{1d0r_0rd3r_4cc3ss}", "IDOR", "Easy", "Access other users' orders", 100},
		{"idor_profile", "FLAG{1d0r_pr0f1l3_l34k}", "IDOR", "Easy", "View other users' profiles via API", 100},
		{"auth_bruteforce", "FLAG{n0_r4t3_l1m1t}", "Auth", "Easy", "No rate limiting on login", 100},
		{"auth_jwt", "FLAG{w34k_jwt_s3cr3t}", "Auth", "Medium", "Forge JWT with weak secret", 200},
		{"auth_2fa", "FLAG{2f4_byp4ss_sk1p}", "Auth", "Hard", "Bypass 2FA verification", 300},
		{"ssrf_internal", "FLAG{ssrf_1nt3rn4l}", "SSRF", "Medium", "Access internal admin via newsletter URL", 200},
		{"cmdi_invoice", "FLAG{cmd_1nj3ct_pdf}", "Command Injection", "Medium", "Command injection in invoice generator", 200},
		{"upload_avatar", "FLAG{sh3ll_upl04d_4v4t4r}", "File Upload", "Medium", "Upload web shell as avatar", 200},
		{"business_price", "FLAG{pr1c3_m4n1pul4t10n}", "Business Logic", "Medium", "Modify price in cart request", 200},
		{"business_coupon", "FLAG{c0up0n_4bus3}", "Business Logic", "Medium", "Use negative discount coupon", 200},
		{"business_quantity", "FLAG{n3g4t1v3_qu4nt1ty}", "Business Logic", "Hard", "Negative quantity in cart", 300},
		{"cors_api", "FLAG{c0rs_m1sc0nf1g}", "CORS", "Medium", "Exploit wildcard CORS on API", 200},
		{"crlf_header", "FLAG{crlf_h34d3r_1nj3ct}", "CRLF", "Medium", "Inject headers via CRLF in redirect", 200},
		{"xxe_import", "FLAG{xx3_f1l3_r34d}", "XXE", "Hard", "XXE in product import XML", 300},
		{"crypto_reset", "FLAG{pr3d1ct4bl3_t0k3n}", "Crypto", "Medium", "Predictable password reset token", 200},
		{"lfi_template", "FLAG{l0c4l_f1l3_1nclud3}", "File Inclusion", "Hard", "LFI in template rendering", 300},

		// ── 28 NEW VULNERABILITIES ──

		// SQL Injection (3 more)
		{"sqli_error", "FLAG{3rr0r_b4s3d_sql1}", "SQL Injection", "Medium", "Error-based SQLi in product filter", 200},
		{"sqli_time", "FLAG{t1m3_b4s3d_sql1}", "SQL Injection", "Hard", "Time-based blind SQLi on user lookup", 300},
		{"sqli_stacked", "FLAG{st4ck3d_qu3r13s}", "SQL Injection", "Hard", "Stacked queries to insert admin user", 350},

		// XSS (3 more)
		{"xss_svg", "FLAG{svg_xss_upl04d}", "XSS", "Medium", "XSS via SVG file upload", 200},
		{"xss_href", "FLAG{j4v4scr1pt_hr3f}", "XSS", "Medium", "JavaScript in href attribute on user website", 200},
		{"xss_csp_bypass", "FLAG{csp_byp4ss_xss}", "XSS", "Hard", "Bypass weak CSP to execute XSS", 300},

		// Authentication (2 more)
		{"auth_default_creds", "FLAG{d3f4ult_cr3ds}", "Auth", "Easy", "Default credentials on admin panel", 100},
		{"auth_pass_in_response", "FLAG{p4ss_1n_r3sp0ns3}", "Auth", "Easy", "Password leaked in API response", 100},

		// IDOR (2 more)
		{"idor_delete", "FLAG{d3l3t3_0th3r_r3v13w}", "IDOR", "Medium", "Delete another user's review", 200},
		{"idor_mass_assign", "FLAG{m4ss_4ss1gnm3nt}", "IDOR", "Hard", "Mass assignment to set role=admin", 300},

		// SSRF (2 more)
		{"ssrf_cloud_meta", "FLAG{cl0ud_m3t4d4t4}", "SSRF", "Hard", "Access cloud metadata via SSRF", 300},
		{"ssrf_file_proto", "FLAG{f1l3_pr0t0c0l}", "SSRF", "Hard", "Read files via file:// protocol", 300},

		// File Upload (2 more)
		{"upload_ext_bypass", "FLAG{d0ubl3_3xt3ns10n}", "File Upload", "Medium", "Bypass extension filter with .php.jpg", 200},
		{"upload_magic_bytes", "FLAG{m4g1c_byt3s}", "File Upload", "Hard", "Bypass magic bytes check with polyglot", 300},

		// Business Logic (3 more)
		{"business_race", "FLAG{r4c3_c0nd1t10n}", "Business Logic", "Hard", "Race condition on coupon apply", 300},
		{"business_sku_swap", "FLAG{sku_sw4p_ch34p}", "Business Logic", "Medium", "Swap expensive product SKU with cheap one", 200},
		{"business_gift_card", "FLAG{g1ft_c4rd_fr4ud}", "Business Logic", "Hard", "Generate unlimited gift card balance", 350},

		// Open Redirect (2)
		{"open_redir_login", "FLAG{0p3n_r3d1r3ct_l0g1n}", "Open Redirect", "Easy", "Open redirect after login via next= param", 100},
		{"open_redir_checkout", "FLAG{0p3n_r3d1r3ct_ch3ck0ut}", "Open Redirect", "Medium", "Open redirect in checkout callback", 150},

		// Path Traversal (2)
		{"path_traversal_img", "FLAG{p4th_tr4v3rs4l_1mg}", "Path Traversal", "Medium", "Read files via image path traversal", 200},
		{"path_traversal_export", "FLAG{p4th_tr4v3rs4l_3xp0rt}", "Path Traversal", "Hard", "Download arbitrary files via export endpoint", 300},

		// Information Disclosure (3)
		{"info_debug_endpoint", "FLAG{d3bug_3ndp01nt}", "Info Disclosure", "Easy", "Debug endpoint leaks server info", 100},
		{"info_error_stack", "FLAG{st4ck_tr4c3_l34k}", "Info Disclosure", "Easy", "Stack trace in error response", 100},
		{"info_git_exposed", "FLAG{g1t_3xp0s3d}", "Info Disclosure", "Medium", "Git directory accessible", 200},

		// Insecure Deserialization (2)
		{"deser_cookie", "FLAG{c00k13_d3s3r14l}", "Deserialization", "Hard", "Insecure deserialization in session cookie", 300},
		{"deser_json_inject", "FLAG{js0n_1nj3ct10n}", "Deserialization", "Medium", "JSON injection in order notes", 200},

		// HTTP Security (2)
		{"clickjack_no_xframe", "FLAG{cl1ckj4ck_fr4m3}", "HTTP Security", "Easy", "Missing X-Frame-Options allows clickjacking", 100},
		{"http_method_tamper", "FLAG{m3th0d_t4mp3r}", "HTTP Security", "Medium", "PUT/DELETE methods accepted on sensitive endpoints", 200},
	}

	for _, f := range flags {
		DB.Exec(`INSERT INTO flags (name, value, category, difficulty, points, description) VALUES (?, ?, ?, ?, ?, ?)`,
			f.name, f.value, f.cat, f.diff, f.pts, f.desc)
	}
}
