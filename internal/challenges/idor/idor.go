package idor

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/Phantom-C2-77/PhantomRange/internal/challenges"
)

type UserProfile struct {
	ID      int    `json:"id"`
	Name    string `json:"name"`
	Email   string `json:"email"`
	Role    string `json:"role"`
	Secret  string `json:"secret,omitempty"`
}

var users = map[int]UserProfile{
	1:    {ID: 1, Name: "John Doe", Email: "john@phantom.lab", Role: "user", Secret: "I like cats"},
	2:    {ID: 2, Name: "Jane Smith", Email: "jane@phantom.lab", Role: "user", Secret: "My password is jane123"},
	1337: {ID: 1337, Name: "Admin", Email: "admin@phantom.lab", Role: "admin", Secret: "FLAG{id0r_acc3ss_c0ntrol}"},
}

type Document struct {
	ID      int    `json:"id"`
	Title   string `json:"title"`
	Content string `json:"content"`
	Owner   string `json:"owner"`
}

var documents = map[int]Document{
	100: {ID: 100, Title: "Public Report", Content: "This is a public document.", Owner: "user"},
	101: {ID: 101, Title: "Meeting Notes", Content: "Quarterly meeting notes.", Owner: "user"},
	999: {ID: 999, Title: "Confidential", Content: "FLAG{h0riz0ntal_privesc_d0c}", Owner: "admin"},
}

func init() {
	challenges.Register(&challenges.Challenge{
		ID:          "idor-01",
		Name:        "User Profile IDOR",
		Category:    challenges.CatIDOR,
		Difficulty:  challenges.Easy,
		Description: "You're logged in as user ID 1. Access another user's profile by changing the ID parameter.",
		Hint:        "Change ?id=1 to other numbers. Try common admin IDs like 0, 1337, or 9999.",
		Flag:        "FLAG{id0r_acc3ss_c0ntrol}",
		Points:      100,
		Path:        "/challenges/idor/profile",
	})

	challenges.Register(&challenges.Challenge{
		ID:          "idor-02",
		Name:        "Document Access Control",
		Category:    challenges.CatIDOR,
		Difficulty:  challenges.Medium,
		Description: "You can view your documents (IDs 100, 101). Find and access the admin's confidential document.",
		Hint:        "Enumerate document IDs. Try IDs outside your range — 200, 500, 999, etc.",
		Flag:        "FLAG{h0riz0ntal_privesc_d0c}",
		Points:      150,
		Path:        "/challenges/idor/documents",
	})

	challenges.Register(&challenges.Challenge{
		ID:          "idor-03",
		Name:        "API IDOR",
		Category:    challenges.CatIDOR,
		Difficulty:  challenges.Medium,
		Description: "The API endpoint /api/user/{id} returns user data. The frontend only shows your profile, but the API doesn't check authorization.",
		Hint:        "Use curl or Burp to directly call: GET /challenges/idor/api/user/1337",
		Flag:        "FLAG{4pi_id0r_n0_4uth_ch3ck}",
		Points:      200,
		Path:        "/challenges/idor/api",
	})
}

func RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/challenges/idor/profile", handleProfile)
	mux.HandleFunc("/challenges/idor/documents", handleDocuments)
	mux.HandleFunc("/challenges/idor/api", handleAPIPage)
	mux.HandleFunc("/challenges/idor/api/user/", handleAPIUser)
}

func handleProfile(w http.ResponseWriter, r *http.Request) {
	idStr := r.URL.Query().Get("id")
	if idStr == "" {
		idStr = "1"
	}

	id, _ := strconv.Atoi(idStr)
	user, ok := users[id]

	result := ""
	if ok {
		result = fmt.Sprintf(`
			<div class="profile-box">
				<p><strong>Name:</strong> %s</p>
				<p><strong>Email:</strong> %s</p>
				<p><strong>Role:</strong> %s</p>
				<p><strong>Secret:</strong> %s</p>
			</div>`, user.Name, user.Email, user.Role, user.Secret)

		if id == 1337 {
			result += fmt.Sprintf(`<div class="flag-box">🚩 %s</div>`, user.Secret)
		}
	} else {
		result = `<div class="alert alert-danger">User not found.</div>`
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, page("idor-01", "User Profile IDOR", fmt.Sprintf(`
		<div class="info-box">
			<p><strong>You are logged in as:</strong> John Doe (ID: 1)</p>
			<p><strong>Objective:</strong> Access the admin's profile.</p>
		</div>
		<form method="GET" class="challenge-form">
			<div class="form-group"><label>User ID</label><input type="text" name="id" value="%s"></div>
			<button type="submit" class="btn">View Profile</button>
		</form>
		%s
	`, idStr, result)))
}

func handleDocuments(w http.ResponseWriter, r *http.Request) {
	idStr := r.URL.Query().Get("id")

	if idStr == "" {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, page("idor-02", "Document Access Control", `
			<div class="info-box">
				<p><strong>Your documents:</strong></p>
				<ul>
					<li><a href="?id=100">Document #100 — Public Report</a></li>
					<li><a href="?id=101">Document #101 — Meeting Notes</a></li>
				</ul>
				<p><strong>Objective:</strong> Find the admin's confidential document.</p>
			</div>
		`))
		return
	}

	id, _ := strconv.Atoi(idStr)
	doc, ok := documents[id]

	result := ""
	if ok {
		// VULNERABLE: No authorization check
		result = fmt.Sprintf(`
			<div class="profile-box">
				<p><strong>Title:</strong> %s</p>
				<p><strong>Owner:</strong> %s</p>
				<p><strong>Content:</strong> %s</p>
			</div>`, doc.Title, doc.Owner, doc.Content)

		if id == 999 {
			result += fmt.Sprintf(`<div class="flag-box">🚩 %s</div>`, doc.Content)
		}
	} else {
		result = `<div class="alert alert-danger">Document not found.</div>`
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, page("idor-02", "Document Access Control", fmt.Sprintf(`
		<form method="GET" class="challenge-form">
			<div class="form-group"><label>Document ID</label><input type="text" name="id" value="%s"></div>
			<button type="submit" class="btn">View Document</button>
		</form>
		%s
	`, idStr, result)))
}

func handleAPIPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, page("idor-03", "API IDOR", `
		<div class="info-box">
			<p><strong>API Endpoint:</strong> <code>GET /challenges/idor/api/user/{id}</code></p>
			<p><strong>Your profile:</strong> <a href="/challenges/idor/api/user/1">/api/user/1</a></p>
			<p><strong>Objective:</strong> Access the admin's profile via the API. The frontend restricts you, but the API doesn't.</p>
		</div>
		<div class="output-box">
			<pre>$ curl http://localhost:8080/challenges/idor/api/user/1

{
  "id": 1,
  "name": "John Doe",
  "email": "john@phantom.lab",
  "role": "user"
}

Try other IDs...</pre>
		</div>
	`))
}

func handleAPIUser(w http.ResponseWriter, r *http.Request) {
	// Extract ID from URL: /challenges/idor/api/user/123
	parts := strings.Split(r.URL.Path, "/")
	idStr := parts[len(parts)-1]
	id, _ := strconv.Atoi(idStr)

	user, ok := users[id]
	if !ok {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(404)
		json.NewEncoder(w).Encode(map[string]string{"error": "user not found"})
		return
	}

	// VULNERABLE: No authorization check — returns any user's data
	resp := map[string]interface{}{
		"id":    user.ID,
		"name":  user.Name,
		"email": user.Email,
		"role":  user.Role,
	}

	if user.Role == "admin" {
		resp["flag"] = "FLAG{4pi_id0r_n0_4uth_ch3ck}"
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// Need strings for URL parsing
var strings = struct {
	Split func(string, string) []string
}{Split: func(s, sep string) []string {
	result := []string{}
	for len(s) > 0 {
		idx := -1
		for i := 0; i <= len(s)-len(sep); i++ {
			if s[i:i+len(sep)] == sep {
				idx = i
				break
			}
		}
		if idx == -1 {
			result = append(result, s)
			break
		}
		result = append(result, s[:idx])
		s = s[idx+len(sep):]
	}
	return result
}}

func page(id, title, content string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>%s — PhantomRange</title><link rel="stylesheet" href="/static/css/style.css">
</head><body>
<nav class="navbar"><a href="/" class="brand">👻 PhantomRange</a>
<div class="nav-links"><a href="/challenges">Challenges</a><a href="/scoreboard">Scoreboard</a></div></nav>
<div class="container"><div class="challenge-header"><h1>%s</h1><span class="badge">%s</span></div>%s</div>
</body></html>`, title, title, id, content)
}
