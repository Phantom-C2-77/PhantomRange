package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Phantom-C2-77/PhantomRange/internal/challenges"
)

var (
	loginAttempts   = make(map[string]int)
	loginMu         sync.Mutex
	sessions        = make(map[string]string) // token -> username
	otpCodes        = map[string]string{"admin": "123456", "user": "654321"}
)

const jwtSecret = "phantom-secret-key-2026" // Intentionally weak

func init() {
	challenges.Register(&challenges.Challenge{
		ID:          "auth-01",
		Name:        "Brute Force Login",
		Category:    challenges.CatAuth,
		Difficulty:  challenges.Easy,
		Description: "The login has no rate limiting or account lockout. Brute force the admin password. Username is 'admin', password is a common 4-digit PIN.",
		Hint:        "Try PINs from 0000 to 9999. The password is a common PIN. Tools: hydra, Burp Intruder, or a simple Python script.",
		Flag:        "FLAG{brut3_f0rc3_n0_l0ckout}",
		Points:      100,
		Path:        "/challenges/auth/bruteforce",
	})

	challenges.Register(&challenges.Challenge{
		ID:          "auth-02",
		Name:        "JWT Token Manipulation",
		Category:    challenges.CatAuth,
		Difficulty:  challenges.Medium,
		Description: "The application uses JWT tokens for authentication. The secret key is weak. Forge a token to become admin.",
		Hint:        "Decode the JWT (base64). Change the 'role' to 'admin'. The secret key is guessable — try common words. Use jwt.io or hashcat.",
		Flag:        "FLAG{jwt_t0ken_f0rg3ry}",
		Points:      200,
		Path:        "/challenges/auth/jwt",
	})

	challenges.Register(&challenges.Challenge{
		ID:          "auth-03",
		Name:        "Session Fixation",
		Category:    challenges.CatAuth,
		Difficulty:  challenges.Medium,
		Description: "The application accepts session tokens from URL parameters and doesn't regenerate them after login. Fix a session and hijack it.",
		Hint:        "Set a session token via ?session=KNOWN_VALUE, then 'login'. The token isn't changed. If you set the session first, you know the token.",
		Flag:        "FLAG{s3ssion_fix4tion_attack}",
		Points:      200,
		Path:        "/challenges/auth/session-fixation",
	})

	challenges.Register(&challenges.Challenge{
		ID:          "auth-04",
		Name:        "2FA Bypass",
		Category:    challenges.CatAuth,
		Difficulty:  challenges.Hard,
		Description: "The login requires a 2FA code after password. But the 2FA check can be bypassed by manipulating the request flow.",
		Hint:        "After entering the correct password, you're redirected to /2fa. But what if you go directly to /dashboard with the session cookie from step 1? The 2FA check is only client-side.",
		Flag:        "FLAG{2fa_byp4ss_sk1p_step}",
		Points:      300,
		Path:        "/challenges/auth/2fa",
	})
}

func RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/challenges/auth/bruteforce", handleBruteforce)
	mux.HandleFunc("/challenges/auth/jwt", handleJWT)
	mux.HandleFunc("/challenges/auth/jwt/verify", handleJWTVerify)
	mux.HandleFunc("/challenges/auth/session-fixation", handleSessionFixation)
	mux.HandleFunc("/challenges/auth/session-fixation/login", handleSessionFixationLogin)
	mux.HandleFunc("/challenges/auth/session-fixation/dashboard", handleSessionFixationDashboard)
	mux.HandleFunc("/challenges/auth/2fa", handle2FA)
	mux.HandleFunc("/challenges/auth/2fa/step1", handle2FAStep1)
	mux.HandleFunc("/challenges/auth/2fa/step2", handle2FAStep2)
	mux.HandleFunc("/challenges/auth/2fa/dashboard", handle2FADashboard)
}

// ── Challenge 1: Brute Force ──
func handleBruteforce(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, page("auth-01", "Brute Force Login", `
			<form method="POST" class="challenge-form">
				<div class="form-group"><label>Username</label><input type="text" name="username" value="admin" required></div>
				<div class="form-group"><label>PIN (4 digits)</label><input type="text" name="pin" placeholder="0000" required maxlength="4"></div>
				<button type="submit" class="btn">Login</button>
			</form>
			<div class="info-box">
				<p><strong>Objective:</strong> Brute force the admin PIN. No rate limiting.</p>
				<p><strong>Username:</strong> admin</p>
				<p><strong>PIN:</strong> 4-digit number (common PIN)</p>
			</div>
		`))
		return
	}

	pin := r.FormValue("pin")
	// The admin PIN is 1337
	if pin == "1337" {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, page("auth-01", "Brute Force Login", `
			<div class="alert alert-success">Welcome, admin!</div>
			<div class="flag-box">🚩 FLAG{brut3_f0rc3_n0_l0ckout}</div>
			<a href="/challenges/auth/bruteforce" class="btn">Try Again</a>
		`))
	} else {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, page("auth-01", "Brute Force Login", fmt.Sprintf(`
			<div class="alert alert-danger">Invalid PIN: %s</div>
			<a href="/challenges/auth/bruteforce" class="btn">Try Again</a>
		`, pin)))
	}
}

// ── Challenge 2: JWT Manipulation ──
func handleJWT(w http.ResponseWriter, r *http.Request) {
	// Generate a "user" JWT
	token := createJWT("guest", "user")

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, page("auth-02", "JWT Token Manipulation", fmt.Sprintf(`
		<div class="info-box">
			<p><strong>Objective:</strong> You have a guest JWT. Forge one with role=admin.</p>
			<p><strong>Your token:</strong></p>
			<div class="output-box"><pre>%s</pre></div>
			<p><strong>Decoded header:</strong> <code>{"alg":"HS256","typ":"JWT"}</code></p>
			<p><strong>Decoded payload:</strong> <code>{"username":"guest","role":"user","exp":...}</code></p>
		</div>
		<form method="POST" action="/challenges/auth/jwt/verify" class="challenge-form">
			<div class="form-group"><label>Submit forged JWT</label><input type="text" name="token" placeholder="eyJ..." required></div>
			<button type="submit" class="btn">Verify Token</button>
		</form>
		<div class="info-box">
			<p><strong>Hint:</strong> The secret key is weak. Try cracking it with <code>hashcat -m 16500 token.txt wordlist.txt</code></p>
			<p>Or guess it — it's a common phrase.</p>
		</div>
	`, token)))
}

func handleJWTVerify(w http.ResponseWriter, r *http.Request) {
	token := r.FormValue("token")

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, page("auth-02", "JWT Token Manipulation", `
			<div class="alert alert-danger">Invalid JWT format</div>
			<a href="/challenges/auth/jwt" class="btn">Back</a>
		`))
		return
	}

	// Verify signature
	sigInput := parts[0] + "." + parts[1]
	mac := hmac.New(sha256.New, []byte(jwtSecret))
	mac.Write([]byte(sigInput))
	expectedSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	if parts[2] != expectedSig {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, page("auth-02", "JWT Token Manipulation", `
			<div class="alert alert-danger">Invalid signature! The secret key doesn't match.</div>
			<a href="/challenges/auth/jwt" class="btn">Back</a>
		`))
		return
	}

	// Decode payload
	payloadJSON, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var payload map[string]interface{}
	json.Unmarshal(payloadJSON, &payload)

	role, _ := payload["role"].(string)
	if role == "admin" {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, page("auth-02", "JWT Token Manipulation", `
			<div class="alert alert-success">Token verified! Role: admin</div>
			<div class="flag-box">🚩 FLAG{jwt_t0ken_f0rg3ry}</div>
			<a href="/challenges/auth/jwt" class="btn">Back</a>
		`))
	} else {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, page("auth-02", "JWT Token Manipulation", fmt.Sprintf(`
			<div class="alert alert-danger">Token valid but role is "%s" — need "admin"</div>
			<a href="/challenges/auth/jwt" class="btn">Back</a>
		`, role)))
	}
}

func createJWT(username, role string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload := fmt.Sprintf(`{"username":"%s","role":"%s","exp":%d}`, username, role, time.Now().Add(24*time.Hour).Unix())
	payloadEnc := base64.RawURLEncoding.EncodeToString([]byte(payload))

	sigInput := header + "." + payloadEnc
	mac := hmac.New(sha256.New, []byte(jwtSecret))
	mac.Write([]byte(sigInput))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return header + "." + payloadEnc + "." + sig
}

// ── Challenge 3: Session Fixation ──
func handleSessionFixation(w http.ResponseWriter, r *http.Request) {
	// Accept session from URL or cookie
	session := r.URL.Query().Get("session")
	if session == "" {
		c, err := r.Cookie("session")
		if err == nil {
			session = c.Value
		}
	}

	if session != "" {
		// VULNERABLE: Sets cookie from URL parameter without regeneration
		http.SetCookie(w, &http.Cookie{Name: "session", Value: session, Path: "/"})
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, page("auth-03", "Session Fixation", fmt.Sprintf(`
		<div class="info-box">
			<p><strong>Objective:</strong> The app accepts session IDs from URL parameters.</p>
			<p><strong>Current session:</strong> <code>%s</code></p>
			<p><strong>Attack:</strong> Set a known session via URL, then login — the session won't change.</p>
		</div>
		<p>Step 1: <a href="/challenges/auth/session-fixation?session=ATTACKER_SESSION">Set a known session</a></p>
		<p>Step 2: <a href="/challenges/auth/session-fixation/login?session=ATTACKER_SESSION">Login with that session</a></p>
		<p>Step 3: <a href="/challenges/auth/session-fixation/dashboard">Check dashboard</a></p>
	`, session)))
}

func handleSessionFixationLogin(w http.ResponseWriter, r *http.Request) {
	session := r.URL.Query().Get("session")
	if session == "" {
		c, _ := r.Cookie("session")
		if c != nil {
			session = c.Value
		}
	}

	// VULNERABLE: Doesn't regenerate session after login
	if session != "" {
		sessions[session] = "admin"
		http.SetCookie(w, &http.Cookie{Name: "session", Value: session, Path: "/"})
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, page("auth-03", "Session Fixation", `
		<div class="alert alert-success">Logged in as admin (session not regenerated!)</div>
		<a href="/challenges/auth/session-fixation/dashboard" class="btn">Go to Dashboard</a>
	`))
}

func handleSessionFixationDashboard(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("session")
	if err != nil || c.Value == "" {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, page("auth-03", "Session Fixation", `
			<div class="alert alert-danger">No session. Login first.</div>
			<a href="/challenges/auth/session-fixation" class="btn">Back</a>
		`))
		return
	}

	username, ok := sessions[c.Value]
	if !ok {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, page("auth-03", "Session Fixation", `
			<div class="alert alert-danger">Invalid session.</div>
			<a href="/challenges/auth/session-fixation" class="btn">Back</a>
		`))
		return
	}

	flag := ""
	if username == "admin" && c.Value == "ATTACKER_SESSION" {
		flag = `<div class="flag-box">🚩 FLAG{s3ssion_fix4tion_attack}</div>`
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, page("auth-03", "Session Fixation", fmt.Sprintf(`
		<div class="alert alert-success">Welcome, %s! Session: %s</div>
		%s
		<a href="/challenges/auth/session-fixation" class="btn">Back</a>
	`, username, c.Value, flag)))
}

// ── Challenge 4: 2FA Bypass ──
func handle2FA(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, page("auth-04", "2FA Bypass", `
		<div class="info-box">
			<p><strong>Objective:</strong> Login requires password + 2FA code. But the 2FA check is only enforced client-side.</p>
		</div>
		<h3>Step 1: Password Login</h3>
		<form method="POST" action="/challenges/auth/2fa/step1" class="challenge-form">
			<div class="form-group"><label>Username</label><input type="text" name="username" value="admin" required></div>
			<div class="form-group"><label>Password</label><input type="text" name="password" placeholder="password" required></div>
			<button type="submit" class="btn">Login</button>
		</form>
		<div class="info-box"><p><strong>Credentials:</strong> admin / admin123</p></div>
	`))
}

func handle2FAStep1(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	if username == "admin" && password == "admin123" {
		// Set auth cookie but mark as "needs 2FA"
		http.SetCookie(w, &http.Cookie{Name: "auth_step1", Value: "admin", Path: "/"})

		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, page("auth-04", "2FA Bypass", `
			<div class="alert alert-success">Password correct! Now enter your 2FA code.</div>
			<h3>Step 2: Enter 2FA Code</h3>
			<form method="POST" action="/challenges/auth/2fa/step2" class="challenge-form">
				<div class="form-group"><label>2FA Code</label><input type="text" name="code" placeholder="6-digit code" required></div>
				<button type="submit" class="btn">Verify</button>
			</form>
			<div class="info-box"><p><strong>Hint:</strong> Do you really need to complete step 2? What if you go directly to the dashboard?</p></div>
		`))
		return
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, page("auth-04", "2FA Bypass", `
		<div class="alert alert-danger">Invalid credentials.</div>
		<a href="/challenges/auth/2fa" class="btn">Back</a>
	`))
}

func handle2FAStep2(w http.ResponseWriter, r *http.Request) {
	code := r.FormValue("code")
	if code == otpCodes["admin"] {
		http.SetCookie(w, &http.Cookie{Name: "auth_2fa", Value: "verified", Path: "/"})
		http.Redirect(w, r, "/challenges/auth/2fa/dashboard", http.StatusFound)
	} else {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, page("auth-04", "2FA Bypass", `
			<div class="alert alert-danger">Invalid 2FA code.</div>
			<a href="/challenges/auth/2fa" class="btn">Back</a>
		`))
	}
}

func handle2FADashboard(w http.ResponseWriter, r *http.Request) {
	// VULNERABLE: Only checks step1 cookie, not 2FA cookie
	c, err := r.Cookie("auth_step1")
	if err != nil || c.Value != "admin" {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, page("auth-04", "2FA Bypass", `
			<div class="alert alert-danger">Not authenticated. Complete step 1 first.</div>
			<a href="/challenges/auth/2fa" class="btn">Back</a>
		`))
		return
	}

	// Check if 2FA was actually bypassed
	c2fa, _ := r.Cookie("auth_2fa")
	flag := ""
	if c2fa == nil || c2fa.Value != "verified" {
		flag = `<div class="flag-box">🚩 FLAG{2fa_byp4ss_sk1p_step}</div>
			<div class="info-box"><p>You accessed the dashboard WITHOUT completing 2FA! The server only checks the step1 cookie.</p></div>`
	} else {
		flag = `<div class="alert">You completed 2FA normally. Try bypassing it — go directly to /dashboard after step 1.</div>`
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, page("auth-04", "2FA Bypass", `
		<div class="alert alert-success">Welcome to the admin dashboard!</div>
		%s
		<a href="/challenges/auth/2fa" class="btn">Back</a>
	`), flag)
}

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
