package shop

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/phantom-offensive/PhantomRange/internal/db"
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
	<a href="/" class="brand"><svg viewBox="0 0 100 50" width="28" style="vertical-align:middle;margin-right:6px;filter:drop-shadow(0 0 4px rgba(167,139,250,0.5))"><defs><linearGradient id="b2g" x1="0%%" y1="0%%" x2="100%%" y2="100%%"><stop offset="0%%" style="stop-color:#a78bfa"/><stop offset="100%%" style="stop-color:#6d28d9"/></linearGradient></defs><path d="M50 8 L15 30 L2 28 L8 32 L15 35 L28 38 L42 42 L50 44 L58 42 L72 38 L85 35 L92 32 L98 28 L85 30 Z" fill="url(#b2g)"/><path d="M50 12 L35 28 L50 36 L65 28 Z" fill="rgba(10,14,26,0.4)"/><circle cx="50" cy="26" r="2" fill="#a78bfa" opacity="0.8"/></svg>PhantomShop</a>
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
	<p>✦ PhantomShop — Intentionally Vulnerable E-Commerce | <a href="/vulns">50 Vulnerabilities</a> | <a href="https://github.com/phantom-offensive/PhantomRange">GitHub</a></p>
</footer>
</body>
</html>`, title, content)
}

// ══════════════════════════════════════════
//  VULNERABILITY LISTING
// ══════════════════════════════════════════

func handleVulnList(w http.ResponseWriter, r *http.Request) {
	rows, _ := db.DB.Query("SELECT name, value, category, difficulty, points, description, COALESCE(hint,'') FROM flags ORDER BY category, difficulty")
	defer rows.Close()

	var cards string
	lastCat := ""
	catCount := 0
	for rows.Next() {
		var name, value, cat, diff, desc, hint string
		var pts int
		rows.Scan(&name, &value, &cat, &diff, &pts, &desc, &hint)

		if cat != lastCat {
			if lastCat != "" {
				cards += `</div>`
			}
			catCount++
			cards += fmt.Sprintf(`<div class="category-title">%s</div><div class="vuln-grid">`, cat)
			lastCat = cat
		}

		diffClass := "difficulty-" + diff
		hintID := "hint-" + name
		cards += fmt.Sprintf(`
		<div class="vuln-card">
			<div class="vuln-header">
				<span class="vuln-name">%s</span>
				<span class="%s">%s</span>
			</div>
			<div class="vuln-footer">
				<span class="points">%d pts</span>
				<button class="hint-btn" onclick="toggleHint('%s')">Show Hint</button>
			</div>
			<div class="hint-text" id="%s" style="display:none;">%s</div>
		</div>`, name, diffClass, diff, pts, hintID, hintID, hint)
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
	</section>
	<script>
	function toggleHint(id) {
		var el = document.getElementById(id);
		var btn = el.previousElementSibling.querySelector('.hint-btn');
		if (el.style.display === 'none') {
			el.style.display = 'block';
			btn.textContent = 'Hide Hint';
			btn.classList.add('hint-btn-active');
		} else {
			el.style.display = 'none';
			btn.textContent = 'Show Hint';
			btn.classList.remove('hint-btn-active');
		}
	}
	</script>`, cards))
}

// ══════════════════════════════════════════
//  SCOREBOARD
// ══════════════════════════════════════════

func handleScoreboard(w http.ResponseWriter, r *http.Request) {
	var totalFlags, totalPoints, capturedFlags, capturedPoints int
	db.DB.QueryRow("SELECT COUNT(*), COALESCE(SUM(points),0) FROM flags").Scan(&totalFlags, &totalPoints)
	db.DB.QueryRow("SELECT COUNT(*), COALESCE(SUM(points),0) FROM flags WHERE captured = 1").Scan(&capturedFlags, &capturedPoints)

	// Get per-category breakdown
	rows, _ := db.DB.Query(`
		SELECT category,
			COUNT(*) as total,
			SUM(CASE WHEN captured = 1 THEN 1 ELSE 0 END) as found,
			SUM(points) as total_pts,
			SUM(CASE WHEN captured = 1 THEN points ELSE 0 END) as found_pts
		FROM flags GROUP BY category ORDER BY category`)

	catRows := ""
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var cat string
			var total, found, totalPts, foundPts int
			rows.Scan(&cat, &total, &found, &totalPts, &foundPts)
			pct := 0
			if total > 0 {
				pct = found * 100 / total
			}
			color := "#ef4444"
			if pct == 100 {
				color = "#10b981"
			} else if pct > 0 {
				color = "#f59e0b"
			}
			catRows += fmt.Sprintf(`<tr>
				<td style="font-weight:600">%s</td>
				<td>%d / %d</td>
				<td>%d / %d</td>
				<td><div style="background:#1f2937;border-radius:4px;height:8px;width:100px;display:inline-block;vertical-align:middle;">
					<div style="background:%s;height:100%%;border-radius:4px;width:%d%%"></div>
				</div> <span style="font-size:12px;color:#9ca3af">%d%%</span></td>
			</tr>`, cat, found, total, foundPts, totalPts, color, pct, pct)
		}
	}

	// Get recently captured flags
	recentRows, _ := db.DB.Query(`SELECT name, category, points, captured_at FROM flags WHERE captured = 1 ORDER BY captured_at DESC LIMIT 10`)
	recentHTML := ""
	if recentRows != nil {
		defer recentRows.Close()
		for recentRows.Next() {
			var name, cat, capturedAt string
			var pts int
			recentRows.Scan(&name, &cat, &pts, &capturedAt)
			recentHTML += fmt.Sprintf(`<tr><td style="color:#10b981">%s</td><td>%s</td><td>%d</td><td style="color:#6b7280;font-size:12px">%s</td></tr>`, name, cat, pts, capturedAt)
		}
	}
	if recentHTML == "" {
		recentHTML = `<tr><td colspan="4" style="color:#6b7280;text-align:center;padding:20px">No flags captured yet. Start exploiting!</td></tr>`
	}

	pctTotal := 0
	if totalFlags > 0 {
		pctTotal = capturedFlags * 100 / totalFlags
	}

	render(w, "Scoreboard", fmt.Sprintf(`
	<section class="section">
		<div class="section-header"><h2>Scoreboard</h2></div>
		<div class="stats-row">
			<div class="stat-card"><div class="stat-value" style="color:#10b981">%d / %d</div><div class="stat-label">Flags Captured</div></div>
			<div class="stat-card"><div class="stat-value" style="color:#3b82f6">%d / %d</div><div class="stat-label">Points Earned</div></div>
			<div class="stat-card"><div class="stat-value" style="color:#a78bfa">%d%%</div><div class="stat-label">Completion</div></div>
		</div>

		<div style="background:#111827;border:1px solid #1f2937;border-radius:12px;padding:20px;margin-bottom:16px;">
			<h3 style="margin-bottom:12px;color:#e5e7eb;">Progress by Category</h3>
			<table style="width:100%%;border-collapse:collapse;">
				<thead><tr style="border-bottom:1px solid #374151;">
					<th style="text-align:left;padding:8px;color:#9ca3af;font-size:12px">CATEGORY</th>
					<th style="text-align:left;padding:8px;color:#9ca3af;font-size:12px">FLAGS</th>
					<th style="text-align:left;padding:8px;color:#9ca3af;font-size:12px">POINTS</th>
					<th style="text-align:left;padding:8px;color:#9ca3af;font-size:12px">PROGRESS</th>
				</tr></thead>
				<tbody>%s</tbody>
			</table>
		</div>

		<div style="background:#111827;border:1px solid #1f2937;border-radius:12px;padding:20px;margin-bottom:16px;">
			<h3 style="margin-bottom:12px;color:#e5e7eb;">Recently Captured</h3>
			<table style="width:100%%;border-collapse:collapse;">
				<thead><tr style="border-bottom:1px solid #374151;">
					<th style="text-align:left;padding:8px;color:#9ca3af;font-size:12px">FLAG</th>
					<th style="text-align:left;padding:8px;color:#9ca3af;font-size:12px">CATEGORY</th>
					<th style="text-align:left;padding:8px;color:#9ca3af;font-size:12px">POINTS</th>
					<th style="text-align:left;padding:8px;color:#9ca3af;font-size:12px">CAPTURED AT</th>
				</tr></thead>
				<tbody>%s</tbody>
			</table>
		</div>

		<div class="info-box">
			<h3>How to Submit Flags</h3>
			<p>When you exploit a vulnerability, you'll see a flag like <code>FLAG{example}</code>. Submit via API or the form below:</p>
			<pre>curl -X POST http://localhost:9000/flag -H "Content-Type: application/json" -d '{"flag":"FLAG{example}"}'</pre>
			<div style="margin-top:16px;display:flex;gap:8px;">
				<input type="text" id="flag-input" placeholder="FLAG{...}" style="flex:1;padding:10px 14px;background:#0a0e1a;border:1px solid #2a3050;border-radius:8px;color:#e8ecf4;font-size:14px;font-family:monospace;">
				<button onclick="submitFlag()" style="padding:10px 20px;background:#7c3aed;color:white;border:none;border-radius:8px;font-weight:600;cursor:pointer;">Submit Flag</button>
			</div>
			<div id="flag-result" style="margin-top:10px;font-size:14px;"></div>
		</div>
	</section>
	<script>
	async function submitFlag() {
		const input = document.getElementById('flag-input');
		const result = document.getElementById('flag-result');
		const flag = input.value.trim();
		if (!flag) return;
		try {
			const resp = await fetch('/flag', {
				method: 'POST',
				headers: {'Content-Type': 'application/json'},
				body: JSON.stringify({flag: flag})
			});
			const data = await resp.json();
			if (data.correct) {
				if (data.already) {
					result.innerHTML = '<span style="color:#f59e0b;">&#9888; ' + data.message + '</span>';
				} else {
					result.innerHTML = '<span style="color:#10b981;">&#10004; ' + data.message + '</span>';
					setTimeout(() => location.reload(), 1500);
				}
			} else {
				result.innerHTML = '<span style="color:#ef4444;">&#10008; ' + data.message + '</span>';
			}
			input.value = '';
		} catch(e) {
			result.innerHTML = '<span style="color:#ef4444;">Error: ' + e.message + '</span>';
		}
	}
	document.getElementById('flag-input').addEventListener('keydown', function(e) { if (e.key === 'Enter') submitFlag(); });
	</script>`,
		capturedFlags, totalFlags, capturedPoints, totalPoints, pctTotal,
		catRows, recentHTML))
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
	var points, captured int
	err := db.DB.QueryRow("SELECT name, category, points, captured FROM flags WHERE value = ?", req.Flag).Scan(&name, &category, &points, &captured)

	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"correct": false, "message": "Invalid flag"})
	} else if captured == 1 {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"correct":  true,
			"message":  fmt.Sprintf("Already captured! %s (%s) — %d points", name, category, points),
			"name":     name,
			"category": category,
			"points":   points,
			"already":  true,
		})
	} else {
		db.DB.Exec("UPDATE flags SET captured = 1, captured_at = CURRENT_TIMESTAMP WHERE value = ?", req.Flag)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"correct":  true,
			"message":  fmt.Sprintf("Correct! %s (%s) — %d points", name, category, points),
			"name":     name,
			"category": category,
			"points":   points,
		})
	}
}
