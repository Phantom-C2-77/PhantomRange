package sqli

import (
	"database/sql"
	"fmt"
	"net/http"
	"strings"

	"github.com/Phantom-C2-77/PhantomRange/internal/challenges"

	_ "modernc.org/sqlite"
)

var db *sql.DB

func init() {
	// Register challenges
	challenges.Register(&challenges.Challenge{
		ID:          "sqli-01",
		Name:        "Login Bypass",
		Category:    challenges.CatSQLi,
		Difficulty:  challenges.Easy,
		Description: "A classic login form vulnerable to SQL injection. Bypass authentication without knowing the password.",
		Hint:        "Try entering a payload in the username field that makes the SQL query always return true. Think about how OR works.",
		Flag:        "FLAG{sql_injection_login_bypass_101}",
		Points:      100,
		Path:        "/challenges/sqli/login",
	})

	challenges.Register(&challenges.Challenge{
		ID:          "sqli-02",
		Name:        "Data Exfiltration",
		Category:    challenges.CatSQLi,
		Difficulty:  challenges.Easy,
		Description: "A product search page with a SQL injection vulnerability. Extract the admin password from the users table.",
		Hint:        "Use UNION SELECT to combine your query with the users table. You need to match the number of columns.",
		Flag:        "FLAG{union_select_data_exfil}",
		Points:      150,
		Path:        "/challenges/sqli/search",
	})

	challenges.Register(&challenges.Challenge{
		ID:          "sqli-03",
		Name:        "Blind SQL Injection",
		Category:    challenges.CatSQLi,
		Difficulty:  challenges.Medium,
		Description: "The application doesn't show SQL errors or query results. Extract the secret flag character by character using boolean-based blind injection.",
		Hint:        "Use SUBSTRING() and compare character by character. If the page shows 'Welcome' the condition is true, otherwise it's different.",
		Flag:        "FLAG{bl1nd_sqli_master}",
		Points:      250,
		Path:        "/challenges/sqli/blind",
	})

	challenges.Register(&challenges.Challenge{
		ID:          "sqli-04",
		Name:        "Second-Order SQLi",
		Category:    challenges.CatSQLi,
		Difficulty:  challenges.Hard,
		Description: "Register a user account. The username is stored safely, but it's used unsafely in a profile query later. Exploit the second-order injection to extract the flag.",
		Hint:        "Register with a malicious username. When the profile page queries using your stored username, the injection triggers.",
		Flag:        "FLAG{s3cond_0rder_injection}",
		Points:      350,
		Path:        "/challenges/sqli/second-order",
	})
}

// InitDB creates the vulnerable database.
func InitDB() {
	var err error
	db, err = sql.Open("sqlite", ":memory:")
	if err != nil {
		panic(err)
	}

	// Users table
	db.Exec(`CREATE TABLE users (
		id INTEGER PRIMARY KEY,
		username TEXT,
		password TEXT,
		role TEXT,
		email TEXT
	)`)
	db.Exec(`INSERT INTO users VALUES (1, 'admin', 'sup3rs3cur3p@ss', 'admin', 'admin@phantom.lab')`)
	db.Exec(`INSERT INTO users VALUES (2, 'user', 'password123', 'user', 'user@phantom.lab')`)
	db.Exec(`INSERT INTO users VALUES (3, 'guest', 'guest', 'guest', 'guest@phantom.lab')`)

	// Products table
	db.Exec(`CREATE TABLE products (
		id INTEGER PRIMARY KEY,
		name TEXT,
		description TEXT,
		price REAL
	)`)
	db.Exec(`INSERT INTO products VALUES (1, 'Laptop', 'Gaming laptop', 999.99)`)
	db.Exec(`INSERT INTO products VALUES (2, 'Phone', 'Smartphone', 699.99)`)
	db.Exec(`INSERT INTO products VALUES (3, 'Tablet', 'Android tablet', 399.99)`)

	// Secrets table (for blind sqli)
	db.Exec(`CREATE TABLE secrets (id INTEGER PRIMARY KEY, flag TEXT)`)
	db.Exec(`INSERT INTO secrets VALUES (1, 'FLAG{bl1nd_sqli_master}')`)

	// Second-order table
	db.Exec(`CREATE TABLE profiles (id INTEGER PRIMARY KEY, username TEXT, bio TEXT)`)
	db.Exec(`CREATE TABLE flags (id INTEGER PRIMARY KEY, name TEXT, value TEXT)`)
	db.Exec(`INSERT INTO flags VALUES (1, 'second_order', 'FLAG{s3cond_0rder_injection}')`)
}

// RegisterRoutes adds SQLi challenge routes.
func RegisterRoutes(mux *http.ServeMux) {
	InitDB()
	mux.HandleFunc("/challenges/sqli/login", handleLogin)
	mux.HandleFunc("/challenges/sqli/search", handleSearch)
	mux.HandleFunc("/challenges/sqli/blind", handleBlind)
	mux.HandleFunc("/challenges/sqli/second-order", handleSecondOrder)
	mux.HandleFunc("/challenges/sqli/second-order/register", handleSecondOrderRegister)
	mux.HandleFunc("/challenges/sqli/second-order/profile", handleSecondOrderProfile)
}

// ── Challenge 1: Login Bypass ──
func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, challengeHTML("sqli-01", "Login Bypass", `
			<form method="POST" class="challenge-form">
				<div class="form-group">
					<label>Username</label>
					<input type="text" name="username" placeholder="Enter username" required>
				</div>
				<div class="form-group">
					<label>Password</label>
					<input type="password" name="password" placeholder="Enter password" required>
				</div>
				<button type="submit" class="btn">Login</button>
			</form>
			<div class="info-box">
				<p><strong>Objective:</strong> Login as admin without knowing the password.</p>
				<p><strong>Backend Query:</strong> <code>SELECT * FROM users WHERE username='[INPUT]' AND password='[INPUT]'</code></p>
			</div>
		`))
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	// VULNERABLE: Direct string concatenation
	query := fmt.Sprintf("SELECT * FROM users WHERE username='%s' AND password='%s'", username, password)

	rows, err := db.Query(query)
	if err != nil {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, challengeHTML("sqli-01", "Login Bypass", `
			<div class="alert alert-danger">SQL Error: %s</div>
			<a href="/challenges/sqli/login" class="btn">Try Again</a>
		`), err.Error())
		return
	}
	defer rows.Close()

	if rows.Next() {
		var id int
		var user, pass, role, email string
		rows.Scan(&id, &user, &pass, &role, &email)

		flag := ""
		if role == "admin" || user == "admin" {
			flag = `<div class="flag-box">🚩 FLAG{sql_injection_login_bypass_101}</div>`
		}

		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, challengeHTML("sqli-01", "Login Bypass", `
			<div class="alert alert-success">Welcome, %s! (Role: %s)</div>
			%s
			<a href="/challenges/sqli/login" class="btn">Try Again</a>
		`), user, role, flag)
	} else {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, challengeHTML("sqli-01", "Login Bypass", `
			<div class="alert alert-danger">Invalid username or password.</div>
			<a href="/challenges/sqli/login" class="btn">Try Again</a>
		`))
	}
}

// ── Challenge 2: UNION-based Data Exfiltration ──
func handleSearch(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")

	if query == "" {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, challengeHTML("sqli-02", "Data Exfiltration", `
			<form method="GET" class="challenge-form">
				<div class="form-group">
					<label>Search Products</label>
					<input type="text" name="q" placeholder="Search..." required>
				</div>
				<button type="submit" class="btn">Search</button>
			</form>
			<div class="info-box">
				<p><strong>Objective:</strong> Extract the admin password from the users table.</p>
				<p><strong>Backend Query:</strong> <code>SELECT name, description, price FROM products WHERE name LIKE '%[INPUT]%'</code></p>
				<p><strong>Hint:</strong> The products table has 3 columns. The users table has: id, username, password, role, email</p>
			</div>
		`))
		return
	}

	// VULNERABLE: Direct string concatenation
	sqlQuery := fmt.Sprintf("SELECT name, description, price FROM products WHERE name LIKE '%%%s%%'", query)

	rows, err := db.Query(sqlQuery)
	var results string
	if err != nil {
		results = fmt.Sprintf(`<div class="alert alert-danger">SQL Error: %s</div>`, err.Error())
	} else {
		defer rows.Close()
		results = `<table class="result-table"><tr><th>Name</th><th>Description</th><th>Price</th></tr>`
		count := 0
		for rows.Next() {
			var col1, col2, col3 string
			rows.Scan(&col1, &col2, &col3)
			results += fmt.Sprintf("<tr><td>%s</td><td>%s</td><td>%s</td></tr>", col1, col2, col3)
			count++

			// Check if they extracted the admin password
			if col1 == "admin" && strings.Contains(col2, "sup3r") {
				results += `<tr><td colspan="3"><div class="flag-box">🚩 FLAG{union_select_data_exfil}</div></td></tr>`
			}
		}
		results += "</table>"
		if count == 0 {
			results = `<div class="alert">No products found.</div>`
		}
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, challengeHTML("sqli-02", "Data Exfiltration", `
		<form method="GET" class="challenge-form">
			<div class="form-group">
				<label>Search Products</label>
				<input type="text" name="q" value="%s" required>
			</div>
			<button type="submit" class="btn">Search</button>
		</form>
		%s
	`), query, results)
}

// ── Challenge 3: Blind SQL Injection ──
func handleBlind(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")

	if id == "" {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, challengeHTML("sqli-03", "Blind SQL Injection", `
			<form method="GET" class="challenge-form">
				<div class="form-group">
					<label>User ID</label>
					<input type="text" name="id" placeholder="Enter user ID (1, 2, 3)" required>
				</div>
				<button type="submit" class="btn">Lookup</button>
			</form>
			<div class="info-box">
				<p><strong>Objective:</strong> Extract the flag from the 'secrets' table using blind injection.</p>
				<p><strong>Backend Query:</strong> <code>SELECT username FROM users WHERE id=[INPUT]</code></p>
				<p><strong>Behavior:</strong> Shows "Welcome, [user]" if found, "User not found" if not.</p>
				<p><strong>Target:</strong> <code>SELECT flag FROM secrets WHERE id=1</code></p>
			</div>
		`))
		return
	}

	// VULNERABLE: Direct concatenation (no quotes — numeric injection)
	query := fmt.Sprintf("SELECT username FROM users WHERE id=%s", id)

	var username string
	err := db.QueryRow(query).Scan(&username)

	var result string
	if err == nil {
		result = fmt.Sprintf(`<div class="alert alert-success">Welcome, %s!</div>`, username)
	} else {
		result = `<div class="alert alert-danger">User not found.</div>`
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, challengeHTML("sqli-03", "Blind SQL Injection", `
		<form method="GET" class="challenge-form">
			<div class="form-group">
				<label>User ID</label>
				<input type="text" name="id" value="%s" required>
			</div>
			<button type="submit" class="btn">Lookup</button>
		</form>
		%s
		<div class="info-box">
			<p><strong>Hint:</strong> Try: <code>1 AND SUBSTRING((SELECT flag FROM secrets WHERE id=1),1,1)='F'</code></p>
			<p>If it shows "Welcome", the character is correct. Extract the full flag character by character.</p>
		</div>
	`), id, result)
}

// ── Challenge 4: Second-Order SQLi ──
func handleSecondOrder(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, challengeHTML("sqli-04", "Second-Order SQL Injection", `
		<div class="info-box">
			<p><strong>Objective:</strong> The registration form safely stores your username. But the profile page uses your stored username in an unsafe query. Exploit this to extract the flag from the 'flags' table.</p>
		</div>
		<h3>Step 1: Register</h3>
		<form method="POST" action="/challenges/sqli/second-order/register" class="challenge-form">
			<div class="form-group">
				<label>Username</label>
				<input type="text" name="username" placeholder="Choose a username" required>
			</div>
			<div class="form-group">
				<label>Bio</label>
				<input type="text" name="bio" placeholder="Short bio" value="Hello!">
			</div>
			<button type="submit" class="btn">Register</button>
		</form>
		<h3>Step 2: View Profile</h3>
		<form method="GET" action="/challenges/sqli/second-order/profile" class="challenge-form">
			<div class="form-group">
				<label>Username</label>
				<input type="text" name="username" placeholder="Enter your username" required>
			</div>
			<button type="submit" class="btn">View Profile</button>
		</form>
	`))
}

func handleSecondOrderRegister(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	bio := r.FormValue("bio")

	// SAFE insert — parameterized query (the username is stored as-is)
	db.Exec("INSERT INTO profiles (username, bio) VALUES (?, ?)", username, bio)

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, challengeHTML("sqli-04", "Second-Order SQL Injection", `
		<div class="alert alert-success">User '%s' registered! Now view your profile.</div>
		<a href="/challenges/sqli/second-order" class="btn">Back</a>
	`), username)
}

func handleSecondOrderProfile(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")

	// Get stored username from DB
	var storedUsername, bio string
	err := db.QueryRow("SELECT username, bio FROM profiles WHERE username = ?", username).Scan(&storedUsername, &bio)
	if err != nil {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, challengeHTML("sqli-04", "Second-Order SQL Injection", `
			<div class="alert alert-danger">User not found. Register first.</div>
			<a href="/challenges/sqli/second-order" class="btn">Back</a>
		`))
		return
	}

	// VULNERABLE: Uses the stored username directly in a new query
	query := fmt.Sprintf("SELECT bio FROM profiles WHERE username='%s'", storedUsername)
	rows, err := db.Query(query)

	var results string
	if err != nil {
		results = fmt.Sprintf(`<div class="alert alert-danger">Error: %s</div>`, err.Error())
	} else {
		defer rows.Close()
		for rows.Next() {
			var b string
			rows.Scan(&b)
			results += fmt.Sprintf("<p>%s</p>", b)

			if strings.Contains(b, "FLAG{") {
				results += fmt.Sprintf(`<div class="flag-box">🚩 %s</div>`, b)
			}
		}
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, challengeHTML("sqli-04", "Second-Order SQL Injection", `
		<h3>Profile: %s</h3>
		<div class="profile-box">%s</div>
		<a href="/challenges/sqli/second-order" class="btn">Back</a>
	`), storedUsername, results)
}

// ── HTML Template ──
func challengeHTML(id, title, content string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>%s — PhantomRange</title>
<link rel="stylesheet" href="/static/css/style.css">
</head><body>
<nav class="navbar">
	<a href="/" class="brand">👻 PhantomRange</a>
	<div class="nav-links">
		<a href="/challenges">Challenges</a>
		<a href="/scoreboard">Scoreboard</a>
	</div>
</nav>
<div class="container">
	<div class="challenge-header">
		<h1>%s</h1>
		<span class="badge" id="challenge-id">%s</span>
	</div>
	%s
</div>
</body></html>`, title, title, id, content)
}
