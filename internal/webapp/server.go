package webapp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/Phantom-C2-77/PhantomRange/internal/challenges"
	"github.com/Phantom-C2-77/PhantomRange/internal/challenges/cmdi"
	"github.com/Phantom-C2-77/PhantomRange/internal/challenges/sqli"
	"github.com/Phantom-C2-77/PhantomRange/internal/challenges/xss"
	"github.com/Phantom-C2-77/PhantomRange/internal/scoreboard"
)

// Server is the main PhantomRange web application.
type Server struct {
	board *scoreboard.Board
	mux   *http.ServeMux
}

// New creates a new PhantomRange server.
func New() *Server {
	s := &Server{
		board: scoreboard.New(),
		mux:   http.NewServeMux(),
	}

	// Static files
	s.mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("internal/webapp/static"))))

	// Pages
	s.mux.HandleFunc("/", s.handleHome)
	s.mux.HandleFunc("/challenges", s.handleChallengeList)
	s.mux.HandleFunc("/scoreboard", s.handleScoreboard)
	s.mux.HandleFunc("/api/flag", s.handleFlagSubmit)
	s.mux.HandleFunc("/api/hint", s.handleHint)
	s.mux.HandleFunc("/api/reset", s.handleReset)

	// Register challenge routes
	sqli.RegisterRoutes(s.mux)
	xss.RegisterRoutes(s.mux)
	cmdi.RegisterRoutes(s.mux)

	return s
}

// Start launches the web server.
func (s *Server) Start(addr string) error {
	return http.ListenAndServe(addr, s.mux)
}

func (s *Server) handleHome(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	allChallenges := challenges.All()
	solved, _, points := s.board.Stats()
	total := len(allChallenges)

	totalPoints := 0
	for _, c := range allChallenges {
		totalPoints += c.Points
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>PhantomRange — Vulnerable Training Environment</title>
<link rel="stylesheet" href="/static/css/style.css">
</head><body>
<nav class="navbar"><a href="/" class="brand">👻 PhantomRange</a>
<div class="nav-links"><a href="/challenges">Challenges</a><a href="/scoreboard">Scoreboard</a></div></nav>

<div class="hero">
	<h1>👻 PhantomRange</h1>
	<p>A vulnerable training environment for penetration testers. Practice real-world web vulnerabilities with guided challenges and flags.</p>
	<a href="/challenges" class="btn">Start Hacking →</a>
</div>

<div class="container">
	<div class="stats-row">
		<div class="stat-card"><div class="stat-value" style="color:#a78bfa">%d</div><div class="stat-label">Challenges</div></div>
		<div class="stat-card"><div class="stat-value" style="color:#10b981">%d/%d</div><div class="stat-label">Solved</div></div>
		<div class="stat-card"><div class="stat-value" style="color:#3b82f6">%d/%d</div><div class="stat-label">Points</div></div>
	</div>

	<h2 style="margin-bottom:14px">Categories</h2>
	<div class="challenge-grid">
`, total, solved, total, points, totalPoints)

	for _, cat := range challenges.AllCategories() {
		catChallenges := challenges.GetByCategory(cat)
		if len(catChallenges) == 0 {
			continue
		}
		catSolved := 0
		for _, c := range catChallenges {
			if s.board.IsSolved(c.ID) {
				catSolved++
			}
		}
		fmt.Fprintf(w, `
		<a href="/challenges#%s" class="challenge-card">
			<div class="cat">%s</div>
			<h3>%d Challenges</h3>
			<div class="meta">
				<span>%d/%d solved</span>
				<span class="points">%s</span>
			</div>
		</a>`, strings.ReplaceAll(cat, " ", "-"), cat, len(catChallenges), catSolved, len(catChallenges),
			difficultyRange(catChallenges))
	}

	fmt.Fprint(w, `</div></div></body></html>`)
}

func (s *Server) handleChallengeList(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, `<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Challenges — PhantomRange</title>
<link rel="stylesheet" href="/static/css/style.css">
</head><body>
<nav class="navbar"><a href="/" class="brand">👻 PhantomRange</a>
<div class="nav-links"><a href="/challenges">Challenges</a><a href="/scoreboard">Scoreboard</a></div></nav>
<div class="container"><h1 style="margin-bottom:20px">All Challenges</h1>`)

	for _, cat := range challenges.AllCategories() {
		catChallenges := challenges.GetByCategory(cat)
		if len(catChallenges) == 0 {
			continue
		}

		// Sort by difficulty
		sort.Slice(catChallenges, func(i, j int) bool {
			order := map[string]int{"Easy": 0, "Medium": 1, "Hard": 2}
			return order[catChallenges[i].Difficulty] < order[catChallenges[j].Difficulty]
		})

		fmt.Fprintf(w, `<div class="category-title" id="%s">%s</div><div class="challenge-grid">`,
			strings.ReplaceAll(cat, " ", "-"), cat)

		for _, c := range catChallenges {
			solved := ""
			if s.board.IsSolved(c.ID) {
				solved = `<span class="solved-badge">✓ Solved</span>`
			}
			diffClass := "difficulty-" + strings.ToLower(c.Difficulty)

			fmt.Fprintf(w, `
			<a href="%s" class="challenge-card">
				<div class="cat">%s %s</div>
				<h3>%s</h3>
				<div class="desc">%s</div>
				<div class="meta">
					<span class="%s">%s</span>
					<span class="points">%d pts</span>
				</div>
			</a>`, c.Path, c.Category, solved, c.Name, truncate(c.Description, 80), diffClass, c.Difficulty, c.Points)
		}

		fmt.Fprint(w, `</div>`)
	}

	fmt.Fprint(w, `</div></body></html>`)
}

func (s *Server) handleScoreboard(w http.ResponseWriter, r *http.Request) {
	allChallenges := challenges.All()
	solved, _, points := s.board.Stats()
	total := len(allChallenges)
	totalPoints := 0
	for _, c := range allChallenges {
		totalPoints += c.Points
	}

	pct := 0
	if total > 0 {
		pct = (solved * 100) / total
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Scoreboard — PhantomRange</title>
<link rel="stylesheet" href="/static/css/style.css">
</head><body>
<nav class="navbar"><a href="/" class="brand">👻 PhantomRange</a>
<div class="nav-links"><a href="/challenges">Challenges</a><a href="/scoreboard">Scoreboard</a></div></nav>
<div class="container">
<h1 style="margin-bottom:20px">Scoreboard</h1>

<div class="stats-row">
	<div class="stat-card"><div class="stat-value" style="color:#10b981">%d/%d</div><div class="stat-label">Solved</div></div>
	<div class="stat-card"><div class="stat-value" style="color:#3b82f6">%d</div><div class="stat-label">Points</div></div>
	<div class="stat-card"><div class="stat-value" style="color:#a78bfa">%d%%</div><div class="stat-label">Complete</div></div>
</div>

<div style="background:#111827;border:1px solid #1f2937;border-radius:10px;padding:16px;margin-bottom:16px;">
	<div style="display:flex;justify-content:space-between;font-size:13px;margin-bottom:6px;">
		<span>Progress</span><span>%d/%d (%d%%)</span>
	</div>
	<div style="height:8px;background:#1f2937;border-radius:4px;overflow:hidden;">
		<div style="height:100%%;width:%d%%;background:linear-gradient(90deg,#7c3aed,#3b82f6);border-radius:4px;transition:width .5s;"></div>
	</div>
</div>

<h2 style="margin:20px 0 12px">Challenge Status</h2>
<table class="result-table">
<tr><th>Challenge</th><th>Category</th><th>Difficulty</th><th>Points</th><th>Status</th></tr>
`, solved, total, points, pct, solved, total, pct, pct)

	for _, c := range allChallenges {
		status := `<span style="color:#6b7280">Not attempted</span>`
		if s.board.IsSolved(c.ID) {
			status = `<span class="solved-badge">✓ Solved</span>`
		}
		diffClass := "difficulty-" + strings.ToLower(c.Difficulty)
		fmt.Fprintf(w, `<tr><td><a href="%s" style="color:#a78bfa;text-decoration:none">%s</a></td><td>%s</td><td class="%s">%s</td><td class="points">%d</td><td>%s</td></tr>`,
			c.Path, c.Name, c.Category, diffClass, c.Difficulty, c.Points, status)
	}

	fmt.Fprintf(w, `</table>
<div style="margin-top:20px;text-align:center;">
	<button onclick="if(confirm('Reset all progress?'))fetch('/api/reset',{method:'POST'}).then(()=>location.reload())" class="btn" style="background:#991b1b">Reset Progress</button>
</div>
</div></body></html>`)
}

func (s *Server) handleFlagSubmit(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "POST required", 405)
		return
	}

	var req struct {
		ChallengeID string `json:"challenge_id"`
		Flag        string `json:"flag"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	c := challenges.GetByID(req.ChallengeID)
	if c == nil {
		json.NewEncoder(w).Encode(map[string]string{"error": "challenge not found"})
		return
	}

	ok, msg := s.board.Submit(req.ChallengeID, req.Flag, c.Flag, c.Points)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"correct": ok,
		"message": msg,
	})
}

func (s *Server) handleHint(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	c := challenges.GetByID(id)
	if c == nil {
		json.NewEncoder(w).Encode(map[string]string{"hint": "Challenge not found"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"hint": c.Hint})
}

func (s *Server) handleReset(w http.ResponseWriter, r *http.Request) {
	s.board.Reset()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "reset"})
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

func difficultyRange(cs []*challenges.Challenge) string {
	has := map[string]bool{}
	for _, c := range cs {
		has[c.Difficulty] = true
	}
	var parts []string
	for _, d := range []string{"Easy", "Medium", "Hard"} {
		if has[d] {
			parts = append(parts, d)
		}
	}
	return strings.Join(parts, " → ")
}
