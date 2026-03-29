package shop

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/Phantom-C2-77/PhantomRange/internal/db"
)

func render(w http.ResponseWriter, title, content string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// VULN: Weak CSP — allows unsafe-inline and unsafe-eval (bypassable)
	w.Header().Set("Content-Security-Policy", "default-src * 'unsafe-inline' 'unsafe-eval'; script-src * 'unsafe-inline' 'unsafe-eval'")
	// VULN: No X-Frame-Options — clickjacking possible
	// Intentionally NOT setting X-Frame-Options or frame-ancestors
	fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>%s — PhantomShop</title>
<link rel="stylesheet" href="/static/css/style.css">
</head>
<body>
<nav class="navbar">
	<a href="/" class="brand">👻 PhantomShop</a>
	<div class="nav-links">
		<a href="/products">Shop</a>
		<a href="/search">Search</a>
		<a href="/vulns">Vulnerabilities</a>
		<a href="/scoreboard">Scoreboard</a>
		<a href="/profile">Profile</a>
		<a href="/login">Login</a>
	</div>
</nav>
<main>%s</main>
<footer class="footer">
	<p>👻 PhantomShop — Intentionally Vulnerable E-Commerce | <a href="/vulns">50 Vulnerabilities</a> | <a href="https://github.com/Phantom-C2-77/PhantomRange">GitHub</a></p>
</footer>
</body>
</html>`, title, content)
}

// ══════════════════════════════════════════
//  VULNERABILITY LISTING
// ══════════════════════════════════════════

func handleVulnList(w http.ResponseWriter, r *http.Request) {
	rows, _ := db.DB.Query("SELECT name, value, category, difficulty, points, description FROM flags ORDER BY category, difficulty")
	defer rows.Close()

	var cards string
	lastCat := ""
	for rows.Next() {
		var name, value, cat, diff, desc string
		var pts int
		rows.Scan(&name, &value, &cat, &diff, &pts, &desc)

		if cat != lastCat {
			if lastCat != "" {
				cards += `</div>`
			}
			cards += fmt.Sprintf(`<div class="category-title">%s</div><div class="vuln-grid">`, cat)
			lastCat = cat
		}

		diffClass := "difficulty-" + diff
		cards += fmt.Sprintf(`
		<div class="vuln-card">
			<div class="vuln-header">
				<span class="vuln-name">%s</span>
				<span class="%s">%s</span>
			</div>
			<p class="vuln-desc">%s</p>
			<div class="vuln-footer">
				<span class="points">%d pts</span>
				<code class="flag-hint">FLAG{...}</code>
			</div>
		</div>`, desc, diffClass, diff, desc, pts)
	}
	if lastCat != "" {
		cards += `</div>`
	}

	render(w, "Vulnerabilities", fmt.Sprintf(`
	<section class="section">
		<div class="section-header">
			<h2>All Vulnerabilities (50)</h2>
			<p class="muted">Find and exploit each vulnerability to capture the flag.</p>
		</div>
		%s
	</section>`, cards))
}

// ══════════════════════════════════════════
//  SCOREBOARD
// ══════════════════════════════════════════

func handleScoreboard(w http.ResponseWriter, r *http.Request) {
	var totalFlags, totalPoints int
	db.DB.QueryRow("SELECT COUNT(*), COALESCE(SUM(points),0) FROM flags").Scan(&totalFlags, &totalPoints)

	render(w, "Scoreboard", fmt.Sprintf(`
	<section class="section">
		<div class="section-header"><h2>Scoreboard</h2></div>
		<div class="stats-row">
			<div class="stat-card"><div class="stat-value" style="color:#a78bfa">%d</div><div class="stat-label">Total Flags</div></div>
			<div class="stat-card"><div class="stat-value" style="color:#3b82f6">%d</div><div class="stat-label">Total Points</div></div>
			<div class="stat-card"><div class="stat-value" style="color:#10b981">50</div><div class="stat-label">Vulnerabilities</div></div>
		</div>
		<div class="info-box">
			<h3>How to Submit Flags</h3>
			<p>When you exploit a vulnerability, you'll see a flag like <code>FLAG{example}</code>.</p>
			<p>Submit it via the API:</p>
			<pre>curl -X POST http://localhost:8080/flag -H "Content-Type: application/json" -d '{"flag":"FLAG{example}"}'</pre>
		</div>
	</section>`, totalFlags, totalPoints))
}

func handleFlagSubmit(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"error": "POST required"})
		return
	}

	var req struct {
		Flag string `json:"flag"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	var name, category string
	var points int
	err := db.DB.QueryRow("SELECT name, category, points FROM flags WHERE value = ?", req.Flag).Scan(&name, &category, &points)

	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"correct": false, "message": "Invalid flag"})
	} else {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"correct":  true,
			"message":  fmt.Sprintf("Correct! %s (%s) — %d points", name, category, points),
			"name":     name,
			"category": category,
			"points":   points,
		})
	}
}
