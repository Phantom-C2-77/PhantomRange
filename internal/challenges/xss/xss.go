package xss

import (
	"fmt"
	"html"
	"net/http"
	"strings"
	"sync"

	"github.com/Phantom-C2-77/PhantomRange/internal/challenges"
)

var (
	guestbook   []GuestbookEntry
	guestbookMu sync.Mutex
)

type GuestbookEntry struct {
	Name    string
	Message string
}

func init() {
	challenges.Register(&challenges.Challenge{
		ID:          "xss-01",
		Name:        "Reflected XSS",
		Category:    challenges.CatXSS,
		Difficulty:  challenges.Easy,
		Description: "A search page that reflects your input without sanitization. Make an alert box pop up with 'XSS'.",
		Hint:        "The search term is reflected directly in the page. Try <script>alert('XSS')</script>",
		Flag:        "FLAG{reflected_xss_easy_win}",
		Points:      100,
		Path:        "/challenges/xss/reflected",
	})

	challenges.Register(&challenges.Challenge{
		ID:          "xss-02",
		Name:        "Stored XSS",
		Category:    challenges.CatXSS,
		Difficulty:  challenges.Easy,
		Description: "A guestbook that stores messages without sanitization. Store a persistent XSS payload.",
		Hint:        "Submit a message containing a script tag. It will execute every time someone views the guestbook.",
		Flag:        "FLAG{stored_xss_persistent}",
		Points:      150,
		Path:        "/challenges/xss/stored",
	})

	challenges.Register(&challenges.Challenge{
		ID:          "xss-03",
		Name:        "DOM-Based XSS",
		Category:    challenges.CatXSS,
		Difficulty:  challenges.Medium,
		Description: "The page reads from the URL hash (#) and writes it to the DOM using innerHTML. No server-side reflection.",
		Hint:        "The JavaScript reads location.hash and puts it in the page via innerHTML. Craft a hash payload: #<img src=x onerror=alert('XSS')>",
		Flag:        "FLAG{dom_xss_client_side}",
		Points:      200,
		Path:        "/challenges/xss/dom",
	})

	challenges.Register(&challenges.Challenge{
		ID:          "xss-04",
		Name:        "XSS Filter Bypass",
		Category:    challenges.CatXSS,
		Difficulty:  challenges.Hard,
		Description: "The application filters <script> tags and common XSS patterns. Bypass the filter to execute JavaScript.",
		Hint:        "The filter blocks 'script', 'alert', 'onerror'. Try event handlers on other tags, or encoding tricks like <img src=x oNeRrOr=confirm(1)>",
		Flag:        "FLAG{xss_f1lter_byp4ss}",
		Points:      300,
		Path:        "/challenges/xss/filter",
	})
}

// RegisterRoutes adds XSS challenge routes.
func RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/challenges/xss/reflected", handleReflected)
	mux.HandleFunc("/challenges/xss/stored", handleStored)
	mux.HandleFunc("/challenges/xss/dom", handleDOM)
	mux.HandleFunc("/challenges/xss/filter", handleFilter)
}

func handleReflected(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")

	result := ""
	if query != "" {
		// VULNERABLE: No sanitization
		result = fmt.Sprintf(`<div class="alert">Search results for: %s</div>
		<div class="info-box"><p>No results found for your query.</p></div>`, query)

		if strings.Contains(strings.ToLower(query), "<script") || strings.Contains(strings.ToLower(query), "onerror") {
			result += `<div class="flag-box">🚩 FLAG{reflected_xss_easy_win}</div>`
		}
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, page("xss-01", "Reflected XSS", fmt.Sprintf(`
		<form method="GET" class="challenge-form">
			<div class="form-group">
				<label>Search</label>
				<input type="text" name="q" value="%s" placeholder="Search something...">
			</div>
			<button type="submit" class="btn">Search</button>
		</form>
		%s
		<div class="info-box">
			<p><strong>Objective:</strong> Execute JavaScript in the page using XSS.</p>
			<p><strong>Note:</strong> Your input is reflected without encoding.</p>
		</div>
	`, html.EscapeString(query), result)))
}

func handleStored(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		name := r.FormValue("name")
		message := r.FormValue("message")

		guestbookMu.Lock()
		guestbook = append(guestbook, GuestbookEntry{Name: name, Message: message})
		guestbookMu.Unlock()
	}

	var entries string
	guestbookMu.Lock()
	for _, e := range guestbook {
		// VULNERABLE: No sanitization on stored content
		entries += fmt.Sprintf(`<div class="guestbook-entry"><strong>%s</strong><p>%s</p></div>`, e.Name, e.Message)

		if strings.Contains(strings.ToLower(e.Message), "<script") || strings.Contains(strings.ToLower(e.Message), "onerror") {
			entries += `<div class="flag-box">🚩 FLAG{stored_xss_persistent}</div>`
		}
	}
	guestbookMu.Unlock()

	if entries == "" {
		entries = `<div class="info-box"><p>No messages yet. Be the first!</p></div>`
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, page("xss-02", "Stored XSS — Guestbook", fmt.Sprintf(`
		<form method="POST" class="challenge-form">
			<div class="form-group">
				<label>Name</label>
				<input type="text" name="name" placeholder="Your name" required>
			</div>
			<div class="form-group">
				<label>Message</label>
				<textarea name="message" placeholder="Leave a message..." required></textarea>
			</div>
			<button type="submit" class="btn">Post</button>
		</form>
		<h3>Messages</h3>
		%s
	`, entries)))
}

func handleDOM(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, page("xss-03", "DOM-Based XSS", `
		<div class="info-box">
			<p><strong>Objective:</strong> The page reads from the URL hash and writes it to the page. Exploit it.</p>
			<p><strong>Try:</strong> Add <code>#&lt;img src=x onerror=alert('XSS')&gt;</code> to the URL</p>
		</div>
		<h3>Welcome Message</h3>
		<div id="welcome-output" class="output-box">Loading...</div>
		<script>
			// VULNERABLE: innerHTML with unsanitized hash
			var msg = decodeURIComponent(location.hash.substring(1));
			if (msg) {
				document.getElementById('welcome-output').innerHTML = 'Hello, ' + msg + '!';
			} else {
				document.getElementById('welcome-output').innerHTML = 'Hello, Guest! Add your name to the URL hash.';
			}

			// Check for XSS execution
			window.addEventListener('error', function(e) {
				if (e.target && e.target.tagName === 'IMG') {
					document.getElementById('welcome-output').innerHTML += '<div class="flag-box">🚩 FLAG{dom_xss_client_side}</div>';
				}
			}, true);
		</script>
	`))
}

func handleFilter(w http.ResponseWriter, r *http.Request) {
	input := r.URL.Query().Get("input")
	filtered := input

	if input != "" {
		// "Security" filter — easily bypassable
		filtered = strings.ReplaceAll(filtered, "<script", "")
		filtered = strings.ReplaceAll(filtered, "</script>", "")
		filtered = strings.ReplaceAll(filtered, "alert", "")
		filtered = strings.ReplaceAll(filtered, "onerror", "")
		filtered = strings.ReplaceAll(filtered, "onload", "")
		filtered = strings.ReplaceAll(filtered, "javascript:", "")
	}

	result := ""
	if input != "" {
		// Check for bypass (case variations, encoding tricks)
		lower := strings.ToLower(input)
		if (strings.Contains(lower, "confirm") || strings.Contains(lower, "prompt") ||
			strings.Contains(lower, "eval") || strings.Contains(lower, "onerror") ||
			strings.Contains(lower, "onmouseover")) && input != filtered {
			result = `<div class="flag-box">🚩 FLAG{xss_f1lter_byp4ss}</div>`
		}
		result += fmt.Sprintf(`<div class="output-box"><p>Filtered output: %s</p></div>`, filtered)
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, page("xss-04", "XSS Filter Bypass", fmt.Sprintf(`
		<form method="GET" class="challenge-form">
			<div class="form-group">
				<label>Message</label>
				<input type="text" name="input" value="%s" placeholder="Enter a message...">
			</div>
			<button type="submit" class="btn">Submit</button>
		</form>
		%s
		<div class="info-box">
			<p><strong>Blocked:</strong> &lt;script&gt;, alert, onerror, onload, javascript:</p>
			<p><strong>Objective:</strong> Bypass the filter and execute JavaScript.</p>
		</div>
	`, html.EscapeString(input), result)))
}

func page(id, title, content string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>%s — PhantomRange</title>
<link rel="stylesheet" href="/static/css/style.css">
</head><body>
<nav class="navbar"><a href="/" class="brand">👻 PhantomRange</a>
<div class="nav-links"><a href="/challenges">Challenges</a><a href="/scoreboard">Scoreboard</a></div></nav>
<div class="container">
<div class="challenge-header"><h1>%s</h1><span class="badge">%s</span></div>
%s
</div></body></html>`, title, title, id, content)
}
