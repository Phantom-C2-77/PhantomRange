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
		description TEXT,
		hint TEXT DEFAULT '',
		captured INTEGER DEFAULT 0,
		captured_at DATETIME DEFAULT NULL
	)`)

	// Migration: add columns if table already exists without them
	DB.Exec(`ALTER TABLE flags ADD COLUMN captured INTEGER DEFAULT 0`)
	DB.Exec(`ALTER TABLE flags ADD COLUMN captured_at DATETIME DEFAULT NULL`)
	DB.Exec(`ALTER TABLE flags ADD COLUMN hint TEXT DEFAULT ''`)

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

	// Flags — description is the full detail, hint is a vague nudge
	flags := []struct{ name, value, cat, diff, desc, hint string; pts int }{
		{"sqli_login", "FLAG{sql_1nj3ct10n_l0g1n}", "SQL Injection", "Easy", "Bypass login with SQLi", "What happens if you put special characters in the login form?", 100},
		{"sqli_search", "FLAG{un10n_s3l3ct_pr0ducts}", "SQL Injection", "Easy", "Extract data via product search", "The search feature talks directly to the database.", 150},
		{"sqli_blind", "FLAG{bl1nd_sql1_3xtr4ct}", "SQL Injection", "Medium", "Blind SQLi on order lookup", "Order IDs go straight into a query. Can you ask yes/no questions?", 250},
		{"xss_search", "FLAG{r3fl3ct3d_xss_sh0p}", "XSS", "Easy", "XSS in product search", "Your search term shows up in the page. Is it escaped?", 100},
		{"xss_review", "FLAG{st0r3d_xss_r3v13w}", "XSS", "Easy", "Stored XSS in product reviews", "Reviews are saved and shown to everyone. What if one contains code?", 150},
		{"xss_profile", "FLAG{d0m_xss_pr0f1l3}", "XSS", "Medium", "DOM XSS in user profile bio", "Your bio is rendered on the profile page without filtering.", 200},
		{"idor_order", "FLAG{1d0r_0rd3r_4cc3ss}", "IDOR", "Easy", "Access other users' orders", "Try changing the number in the URL when viewing an order.", 100},
		{"idor_profile", "FLAG{1d0r_pr0f1l3_l34k}", "IDOR", "Easy", "View other users' profiles via API", "The API serves user data by ID. What IDs exist?", 100},
		{"auth_bruteforce", "FLAG{n0_r4t3_l1m1t}", "Auth", "Easy", "No rate limiting on login", "Try logging in wrong. Again. And again. Does anything stop you?", 100},
		{"auth_jwt", "FLAG{w34k_jwt_s3cr3t}", "Auth", "Medium", "Forge JWT with weak secret", "How does the server know your role? Check your cookies.", 200},
		{"auth_2fa", "FLAG{2f4_byp4ss_sk1p}", "Auth", "Hard", "Bypass 2FA verification", "Is the second factor enforced server-side or just assumed?", 300},
		{"ssrf_internal", "FLAG{ssrf_1nt3rn4l}", "SSRF", "Medium", "Access internal admin via newsletter URL", "The newsletter feature fetches a URL. What URLs can it reach?", 200},
		{"cmdi_invoice", "FLAG{cmd_1nj3ct_pdf}", "Command Injection", "Medium", "Command injection in invoice generator", "The invoice generator passes your input to the system. What if you add shell characters?", 200},
		{"upload_avatar", "FLAG{sh3ll_upl04d_4v4t4r}", "File Upload", "Medium", "Upload web shell as avatar", "The avatar uploader accepts files. Does it check what you upload?", 200},
		{"business_price", "FLAG{pr1c3_m4n1pul4t10n}", "Business Logic", "Medium", "Modify price in cart request", "When you add to cart, who decides the price — the server or the browser?", 200},
		{"business_coupon", "FLAG{c0up0n_4bus3}", "Business Logic", "Medium", "Use negative discount coupon", "Not all coupons reduce the price. Some do the opposite.", 200},
		{"business_quantity", "FLAG{n3g4t1v3_qu4nt1ty}", "Business Logic", "Hard", "Negative quantity in cart", "What happens if you order less than zero items?", 300},
		{"cors_api", "FLAG{c0rs_m1sc0nf1g}", "CORS", "Medium", "Exploit wildcard CORS on API", "Check the response headers when you call the API from a different origin.", 200},
		{"crlf_header", "FLAG{crlf_h34d3r_1nj3ct}", "CRLF", "Medium", "Inject headers via CRLF in redirect", "A redirect parameter sets an HTTP header. Can you inject a new line?", 200},
		{"xxe_import", "FLAG{xx3_f1l3_r34d}", "XXE", "Hard", "XXE in product import XML", "The import feature parses XML. What if your XML defines external entities?", 300},
		{"crypto_reset", "FLAG{pr3d1ct4bl3_t0k3n}", "Crypto", "Medium", "Predictable password reset token", "The reset token looks random but isn't. What inputs could generate it?", 200},
		{"lfi_template", "FLAG{l0c4l_f1l3_1nclud3}", "File Inclusion", "Hard", "LFI in template rendering", "A page is loaded by name from a parameter. What other files exist on the system?", 300},

		// SQL Injection (3 more)
		{"sqli_error", "FLAG{3rr0r_b4s3d_sql1}", "SQL Injection", "Medium", "Error-based SQLi in product filter", "The product filter has a sort parameter. What if it's not a column name?", 200},
		{"sqli_time", "FLAG{t1m3_b4s3d_sql1}", "SQL Injection", "Hard", "Time-based blind SQLi on user lookup", "The user lookup API takes a username. Can you make it think for a while?", 300},
		{"sqli_stacked", "FLAG{st4ck3d_qu3r13s}", "SQL Injection", "Hard", "Stacked queries to insert admin user", "What if you could run a second SQL statement after the first?", 350},

		// XSS (3 more)
		{"xss_svg", "FLAG{svg_xss_upl04d}", "XSS", "Medium", "XSS via SVG file upload", "SVG files can contain more than just graphics.", 200},
		{"xss_href", "FLAG{j4v4scr1pt_hr3f}", "XSS", "Medium", "JavaScript in href attribute on user website", "Not all URLs start with http. What other protocols can a link use?", 200},
		{"xss_csp_bypass", "FLAG{csp_byp4ss_xss}", "XSS", "Hard", "Bypass weak CSP to execute XSS", "Check the Content-Security-Policy header. Is it actually restrictive?", 300},

		// Authentication (2 more)
		{"auth_default_creds", "FLAG{d3f4ult_cr3ds}", "Auth", "Easy", "Default credentials on admin panel", "Did anyone change the admin password after setup?", 100},
		{"auth_pass_in_response", "FLAG{p4ss_1n_r3sp0ns3}", "Auth", "Easy", "Password leaked in API response", "The user API returns a lot of fields. Maybe too many.", 100},

		// IDOR (2 more)
		{"idor_delete", "FLAG{d3l3t3_0th3r_r3v13w}", "IDOR", "Medium", "Delete another user's review", "The delete endpoint takes a review ID. Does it check who's asking?", 200},
		{"idor_mass_assign", "FLAG{m4ss_4ss1gnm3nt}", "IDOR", "Hard", "Mass assignment to set role=admin", "The profile update API accepts JSON. What fields does it blindly trust?", 300},

		// SSRF (2 more)
		{"ssrf_cloud_meta", "FLAG{cl0ud_m3t4d4t4}", "SSRF", "Hard", "Access cloud metadata via SSRF", "Cloud instances have a special IP for metadata. Can you reach it?", 300},
		{"ssrf_file_proto", "FLAG{f1l3_pr0t0c0l}", "SSRF", "Hard", "Read files via file:// protocol", "URLs don't have to use http. What other schemes exist?", 300},

		// File Upload (2 more)
		{"upload_ext_bypass", "FLAG{d0ubl3_3xt3ns10n}", "File Upload", "Medium", "Bypass extension filter with .php.jpg", "If the server only checks the last extension, what about two extensions?", 200},
		{"upload_magic_bytes", "FLAG{m4g1c_byt3s}", "File Upload", "Hard", "Bypass magic bytes check with polyglot", "Files are identified by their first few bytes. Can you fake them?", 300},

		// Business Logic (3 more)
		{"business_race", "FLAG{r4c3_c0nd1t10n}", "Business Logic", "Hard", "Race condition on coupon apply", "If you use a coupon really fast, does the counter keep up?", 300},
		{"business_sku_swap", "FLAG{sku_sw4p_ch34p}", "Business Logic", "Medium", "Swap expensive product SKU with cheap one", "The cart trusts the price you send. Does it match the product?", 200},
		{"business_gift_card", "FLAG{g1ft_c4rd_fr4ud}", "Business Logic", "Hard", "Generate unlimited gift card balance", "Gift card codes follow a pattern. Can you predict the next one?", 350},

		// Open Redirect (2)
		{"open_redir_login", "FLAG{0p3n_r3d1r3ct_l0g1n}", "Open Redirect", "Easy", "Open redirect after login via next= param", "After login, you're sent somewhere. Who decides where?", 100},
		{"open_redir_checkout", "FLAG{0p3n_r3d1r3ct_ch3ck0ut}", "Open Redirect", "Medium", "Open redirect in checkout callback", "The checkout callback has a return URL. Is it validated?", 150},

		// Path Traversal (2)
		{"path_traversal_img", "FLAG{p4th_tr4v3rs4l_1mg}", "Path Traversal", "Medium", "Read files via image path traversal", "Images are served from a directory. Can you navigate out of it?", 200},
		{"path_traversal_export", "FLAG{p4th_tr4v3rs4l_3xp0rt}", "Path Traversal", "Hard", "Download arbitrary files via export endpoint", "The export downloads a file by name. What other files can you request?", 300},

		// Information Disclosure (3)
		{"info_debug_endpoint", "FLAG{d3bug_3ndp01nt}", "Info Disclosure", "Easy", "Debug endpoint leaks server info", "Developers sometimes leave diagnostic pages exposed.", 100},
		{"info_error_stack", "FLAG{st4ck_tr4c3_l34k}", "Info Disclosure", "Easy", "Stack trace in error response", "Errors can reveal more than they should.", 100},
		{"info_git_exposed", "FLAG{g1t_3xp0s3d}", "Info Disclosure", "Medium", "Git directory accessible", "Version control metadata shouldn't be publicly accessible.", 200},

		// Insecure Deserialization (2)
		{"deser_cookie", "FLAG{c00k13_d3s3r14l}", "Deserialization", "Hard", "Insecure deserialization in session cookie", "The session cookie is encoded, not encrypted. What's inside?", 300},
		{"deser_json_inject", "FLAG{js0n_1nj3ct10n}", "Deserialization", "Medium", "JSON injection in order notes", "Your notes get embedded in a JSON string. Can you break out?", 200},

		// HTTP Security (2)
		{"clickjack_no_xframe", "FLAG{cl1ckj4ck_fr4m3}", "HTTP Security", "Easy", "Missing X-Frame-Options allows clickjacking", "Can this page be embedded in someone else's site?", 100},
		{"http_method_tamper", "FLAG{m3th0d_t4mp3r}", "HTTP Security", "Medium", "PUT/DELETE methods accepted on sensitive endpoints", "Not every endpoint checks the HTTP method. Try something besides GET.", 200},
	}

	for _, f := range flags {
		DB.Exec(`INSERT INTO flags (name, value, category, difficulty, points, description, hint) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			f.name, f.value, f.cat, f.diff, f.pts, f.desc, f.hint)
	}
}
