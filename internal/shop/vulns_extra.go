package shop

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Phantom-C2-77/PhantomRange/internal/db"
)

func init() {
	// Extra routes are registered via RegisterExtraRoutes
}

// RegisterExtraRoutes adds all new vulnerability endpoints.
func RegisterExtraRoutes(mux *http.ServeMux) {
	// SQL Injection extras
	mux.HandleFunc("/products/filter", handleSQLiFilter)
	mux.HandleFunc("/api/user/lookup", handleSQLiTimeBased)

	// XSS extras
	mux.HandleFunc("/profile/website", handleXSSHref)

	// Auth extras
	mux.HandleFunc("/api/user/details/", handlePassInResponse)

	// IDOR extras
	mux.HandleFunc("/api/review/delete", handleIDORDeleteReview)
	mux.HandleFunc("/api/user/update", handleMassAssignment)

	// Open Redirect
	mux.HandleFunc("/auth/callback", handleOpenRedirectLogin)
	mux.HandleFunc("/checkout/callback", handleOpenRedirectCheckout)

	// Path Traversal
	mux.HandleFunc("/static/img/", handlePathTraversalImg)
	mux.HandleFunc("/api/export/file", handlePathTraversalExport)

	// Info Disclosure
	mux.HandleFunc("/debug", handleDebugEndpoint)
	mux.HandleFunc("/api/error", handleErrorStack)
	mux.HandleFunc("/.git/config", handleGitExposed)

	// Deserialization
	mux.HandleFunc("/api/order/notes", handleJSONInjection)

	// HTTP Security
	mux.HandleFunc("/api/admin/user", handleMethodTamper)

	// Gift card
	mux.HandleFunc("/giftcard", handleGiftCard)
	mux.HandleFunc("/giftcard/redeem", handleGiftCardRedeem)
}

// ══════ SQL INJECTION EXTRAS ══════

func handleSQLiFilter(w http.ResponseWriter, r *http.Request) {
	cat := r.URL.Query().Get("category")
	sort := r.URL.Query().Get("sort")
	if sort == "" {
		sort = "price"
	}

	// VULN: SQLi in ORDER BY clause
	query := fmt.Sprintf("SELECT id, name, price, category FROM products WHERE category='%s' ORDER BY %s", cat, sort)
	rows, err := db.DB.Query(query)

	var results string
	if err != nil {
		// VULN: Error-based SQLi — shows SQL error
		results = fmt.Sprintf(`<div class="alert alert-danger">Database error: %s</div>
		<div class="flag-box">🚩 FLAG{3rr0r_b4s3d_sql1}</div>`, err.Error())
	} else {
		defer rows.Close()
		results = `<table class="result-table"><tr><th>Name</th><th>Price</th><th>Category</th></tr>`
		for rows.Next() {
			var id int
			var name, categ string
			var price float64
			rows.Scan(&id, &name, &price, &categ)
			results += fmt.Sprintf("<tr><td>%s</td><td>$%.2f</td><td>%s</td></tr>", name, price, categ)
		}
		results += "</table>"
	}

	render(w, "Filter Products", fmt.Sprintf(`
	<section class="section">
		<h2>Filter Products</h2>
		<form method="GET" class="search-bar">
			<input type="text" name="category" value="%s" placeholder="Category" class="search-input">
			<input type="text" name="sort" value="%s" placeholder="Sort by (price, name)" class="search-input">
			<button type="submit" class="btn">Filter</button>
		</form>
		%s
		<div class="info-box"><p><strong>Backend:</strong> <code>SELECT ... ORDER BY %s</code></p></div>
	</section>`, cat, sort, results, sort))
}

func handleSQLiTimeBased(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	if username == "" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"error": "username required"})
		return
	}

	// VULN: Time-based blind SQLi
	start := time.Now()
	query := fmt.Sprintf("SELECT id FROM users WHERE username='%s'", username)
	var id int
	db.DB.QueryRow(query).Scan(&id)
	elapsed := time.Since(start)

	w.Header().Set("Content-Type", "application/json")
	resp := map[string]interface{}{"exists": id > 0, "time_ms": elapsed.Milliseconds()}

	if strings.Contains(username, "CASE") || strings.Contains(username, "sleep") || strings.Contains(username, "LIKE") {
		resp["flag"] = "FLAG{t1m3_b4s3d_sql1}"
	}

	json.NewEncoder(w).Encode(resp)
}

// ══════ XSS EXTRAS ══════

func handleXSSHref(w http.ResponseWriter, r *http.Request) {
	website := r.URL.Query().Get("url")
	if website == "" {
		website = "https://example.com"
	}

	flag := ""
	if strings.HasPrefix(strings.ToLower(website), "javascript:") {
		flag = `<div class="flag-box">🚩 FLAG{j4v4scr1pt_hr3f}</div>`
	}

	// VULN: javascript: in href
	render(w, "User Website", fmt.Sprintf(`
	<section class="section">
		<h2>User Website</h2>
		<form method="GET" class="search-bar">
			<input type="text" name="url" value="%s" class="search-input" placeholder="Your website URL">
			<button type="submit" class="btn">Set</button>
		</form>
		<p>Your website: <a href="%s">Visit Profile Website</a></p>
		%s
		<div class="info-box"><p><strong>Hint:</strong> What happens if the URL starts with <code>javascript:</code>?</p></div>
	</section>`, website, website, flag))
}

// ══════ AUTH EXTRAS ══════

func handlePassInResponse(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	idStr := strings.TrimPrefix(r.URL.Path, "/api/user/details/")

	var username, email, password, role string
	err := db.DB.QueryRow("SELECT username, email, password, role FROM users WHERE id = ?", idStr).
		Scan(&username, &email, &password, &role)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
		return
	}

	// VULN: Password leaked in API response
	json.NewEncoder(w).Encode(map[string]interface{}{
		"username": username,
		"email":    email,
		"password": password, // VULN!
		"role":     role,
		"flag":     "FLAG{p4ss_1n_r3sp0ns3}",
	})
}

// ══════ IDOR EXTRAS ══════

func handleIDORDeleteReview(w http.ResponseWriter, r *http.Request) {
	reviewID := r.URL.Query().Get("id")
	w.Header().Set("Content-Type", "application/json")

	// VULN: No auth check — anyone can delete any review
	if reviewID != "" {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "deleted",
			"review":  reviewID,
			"message": "Review deleted (no auth check!)",
			"flag":    "FLAG{d3l3t3_0th3r_r3v13w}",
		})
	} else {
		json.NewEncoder(w).Encode(map[string]string{"error": "id parameter required", "hint": "DELETE /api/review/delete?id=1"})
	}
}

func handleMassAssignment(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"hint": "POST with JSON: {\"username\":\"john\",\"role\":\"admin\"}",
		})
		return
	}

	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	var data map[string]interface{}
	json.Unmarshal(body, &data)

	w.Header().Set("Content-Type", "application/json")

	// VULN: Mass assignment — role field accepted from user input
	if role, ok := data["role"]; ok && role == "admin" {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "updated",
			"message": "Profile updated with role=admin (mass assignment!)",
			"flag":    "FLAG{m4ss_4ss1gnm3nt}",
		})
	} else {
		json.NewEncoder(w).Encode(map[string]string{"status": "updated", "message": "Profile updated"})
	}
}

// ══════ OPEN REDIRECT ══════

func handleOpenRedirectLogin(w http.ResponseWriter, r *http.Request) {
	next := r.URL.Query().Get("next")

	if next == "" {
		render(w, "Login Callback", `
		<div class="info-box">
			<p><strong>Endpoint:</strong> <code>/auth/callback?next=URL</code></p>
			<p>After login, redirects to the 'next' parameter without validation.</p>
			<p>Try: <code>/auth/callback?next=https://evil.com</code></p>
		</div>`)
		return
	}

	flag := ""
	if strings.HasPrefix(next, "http") && !strings.Contains(next, "localhost") {
		flag = "FLAG{0p3n_r3d1r3ct_l0g1n}"
		render(w, "Open Redirect", fmt.Sprintf(`
		<div class="alert alert-danger">Open redirect detected! Would redirect to: %s</div>
		<div class="flag-box">🚩 %s</div>`, next, flag))
		return
	}

	http.Redirect(w, r, next, 302)
}

func handleOpenRedirectCheckout(w http.ResponseWriter, r *http.Request) {
	returnURL := r.URL.Query().Get("return_url")

	if returnURL != "" && strings.HasPrefix(returnURL, "http") && !strings.Contains(returnURL, "localhost") {
		render(w, "Open Redirect", fmt.Sprintf(`
		<div class="alert alert-danger">Open redirect in checkout! Target: %s</div>
		<div class="flag-box">🚩 FLAG{0p3n_r3d1r3ct_ch3ck0ut}</div>`, returnURL))
		return
	}

	render(w, "Checkout Callback", `
	<div class="info-box">
		<p><strong>Endpoint:</strong> <code>/checkout/callback?return_url=URL</code></p>
		<p>Try: <code>/checkout/callback?return_url=https://evil.com</code></p>
	</div>`)
}

// ══════ PATH TRAVERSAL ══════

func handlePathTraversalImg(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/static/img/")

	// VULN: Path traversal — no sanitization
	if strings.Contains(path, "..") {
		render(w, "Path Traversal", fmt.Sprintf(`
		<div class="alert alert-danger">Path traversal detected: %s</div>
		<div class="flag-box">🚩 FLAG{p4th_tr4v3rs4l_1mg}</div>
		<div class="info-box"><p>In a real app, this would read: <code>%s</code></p></div>`, path, path))
		return
	}

	http.ServeFile(w, r, "internal/shop/static/img/"+path)
}

func handlePathTraversalExport(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("file")
	if filename == "" {
		render(w, "Export", `
		<div class="info-box">
			<p><strong>Endpoint:</strong> <code>/api/export/file?file=products.csv</code></p>
			<p>Try: <code>/api/export/file?file=../../../etc/passwd</code></p>
		</div>`)
		return
	}

	// VULN: Path traversal in file download
	if strings.Contains(filename, "..") {
		content := ""
		data, err := os.ReadFile(filename)
		if err == nil {
			content = string(data)
			if len(content) > 2000 {
				content = content[:2000] + "\n... (truncated)"
			}
		} else {
			content = "File not found: " + filename
		}

		render(w, "Path Traversal", fmt.Sprintf(`
		<div class="alert alert-danger">Path traversal! Reading: %s</div>
		<div class="output-box"><pre>%s</pre></div>
		<div class="flag-box">🚩 FLAG{p4th_tr4v3rs4l_3xp0rt}</div>`, filename, content))
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprint(w, "id,name,price\n1,Sneakers,89.99\n2,Boots,199.99\n")
}

// ══════ INFO DISCLOSURE ══════

func handleDebugEndpoint(w http.ResponseWriter, r *http.Request) {
	// VULN: Debug endpoint exposed in production
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"server":    "PhantomShop v2.0",
		"go_version": "go1.24",
		"db_path":   "data/shop.db",
		"admin_key": "phantom-admin-2026",
		"debug":     true,
		"env":       "production",
		"flag":      "FLAG{d3bug_3ndp01nt}",
	})
}

func handleErrorStack(w http.ResponseWriter, r *http.Request) {
	// VULN: Stack trace in error response
	render(w, "Error", `
	<div class="alert alert-danger">Internal Server Error</div>
	<div class="output-box"><pre>
goroutine 1 [running]:
main.handleCheckout(0xc000112000, 0xc0001a6000)
	/app/internal/shop/pages.go:342 +0x1a4
net/http.HandlerFunc.ServeHTTP(0xc000112000, 0xc0001a6000)
	/usr/local/go/src/net/http/server.go:2136 +0x29

Database: data/shop.db
Config: configs/server.yaml
Admin password: admin123
SECRET_KEY=phantom-secret-key-2026
DB_PASSWORD=phantom_db_2026
</pre></div>
	<div class="flag-box">🚩 FLAG{st4ck_tr4c3_l34k}</div>
	<div class="info-box"><p>Stack traces leak: file paths, database info, config values, and sometimes credentials.</p></div>`)
}

func handleGitExposed(w http.ResponseWriter, r *http.Request) {
	// VULN: .git directory accessible
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprint(w, `[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
[remote "origin"]
	url = https://admin:admin123@github.com/phantomshop/app.git
	fetch = +refs/heads/*:refs/remotes/origin/*

FLAG{g1t_3xp0s3d}
`)
}

// ══════ DESERIALIZATION ══════

func handleJSONInjection(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		render(w, "Order Notes", `
		<div class="auth-page"><div class="auth-card">
			<h2>Add Order Notes</h2>
			<form method="POST" class="auth-form">
				<input type="text" name="order_id" placeholder="Order ID" value="1001">
				<textarea name="notes" placeholder="Order notes..."></textarea>
				<button type="submit" class="btn btn-full">Save Notes</button>
			</form>
			<div class="info-box"><p>Try injecting JSON: <code>","role":"admin","flag":"</code></p></div>
		</div></div>`)
		return
	}

	notes := r.FormValue("notes")
	orderID := r.FormValue("order_id")

	// VULN: JSON injection — notes concatenated into JSON string
	jsonStr := fmt.Sprintf(`{"order":"%s","notes":"%s","status":"pending"}`, orderID, notes)

	flag := ""
	if strings.Contains(notes, "\"") || strings.Contains(notes, "role") {
		flag = `<div class="flag-box">🚩 FLAG{js0n_1nj3ct10n}</div>`
	}

	render(w, "Order Notes", fmt.Sprintf(`
	<div class="alert alert-success">Notes saved!</div>
	<div class="output-box"><pre>%s</pre></div>
	%s
	<a href="/api/order/notes" class="btn">Back</a>`, jsonStr, flag))
}

// ══════ HTTP SECURITY ══════

func handleMethodTamper(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// VULN: Accepts PUT/DELETE without auth
	switch r.Method {
	case "PUT":
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "user updated via PUT (no auth!)",
			"flag":    "FLAG{m3th0d_t4mp3r}",
			"message": "PUT/DELETE methods should be restricted",
		})
	case "DELETE":
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "user deleted via DELETE (no auth!)",
			"flag":    "FLAG{m3th0d_t4mp3r}",
			"message": "Destructive operations without authentication",
		})
	default:
		json.NewEncoder(w).Encode(map[string]string{
			"hint":   "Try PUT or DELETE method",
			"example": "curl -X PUT http://localhost:9000/api/admin/user",
		})
	}
}

// ══════ GIFT CARD (Business Logic) ══════

func handleGiftCard(w http.ResponseWriter, r *http.Request) {
	render(w, "Gift Cards", `
	<div class="auth-page"><div class="auth-card">
		<h2>Buy Gift Card</h2>
		<form method="POST" action="/giftcard/redeem" class="auth-form">
			<select name="amount">
				<option value="25">$25 Gift Card</option>
				<option value="50">$50 Gift Card</option>
				<option value="100">$100 Gift Card</option>
			</select>
			<input type="text" name="code" placeholder="Gift card code (leave empty to generate)">
			<button type="submit" class="btn btn-full">Redeem / Generate</button>
		</form>
		<div class="info-box"><p>Gift card codes are predictable: GC-[amount]-[sequential_number]</p></div>
	</div></div>`)
}

func handleGiftCardRedeem(w http.ResponseWriter, r *http.Request) {
	amount := r.FormValue("amount")
	code := r.FormValue("code")

	if code == "" {
		// Generate predictable code
		code = fmt.Sprintf("GC-%s-%d", amount, time.Now().Unix()%10000)
	}

	flag := ""
	if strings.Contains(code, "GC-") && code != fmt.Sprintf("GC-%s-%d", amount, time.Now().Unix()%10000) {
		flag = `<div class="flag-box">🚩 FLAG{g1ft_c4rd_fr4ud}</div>
		<div class="info-box"><p>You redeemed a predicted/forged gift card code!</p></div>`
	}

	render(w, "Gift Card Redeemed", fmt.Sprintf(`
	<div class="alert alert-success">Gift card %s redeemed! Amount: $%s</div>
	<div class="info-box"><p>Code format: GC-[amount]-[number]. Predictable = forgeable.</p></div>
	%s
	<a href="/giftcard" class="btn">Back</a>`, code, amount, flag))
}
