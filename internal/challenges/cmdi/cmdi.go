package cmdi

import (
	"fmt"
	"net/http"
	"os/exec"
	"runtime"
	"strings"

	"github.com/Phantom-C2-77/PhantomRange/internal/challenges"
)

func init() {
	challenges.Register(&challenges.Challenge{
		ID:          "cmdi-01",
		Name:        "Basic Command Injection",
		Category:    challenges.CatCmdI,
		Difficulty:  challenges.Easy,
		Description: "A ping utility that takes a hostname and runs the ping command. Inject an additional command.",
		Hint:        "Try: 127.0.0.1; cat /etc/passwd  or  127.0.0.1 && whoami",
		Flag:        "FLAG{command_injection_101}",
		Points:      100,
		Path:        "/challenges/cmdi/ping",
	})

	challenges.Register(&challenges.Challenge{
		ID:          "cmdi-02",
		Name:        "Blind Command Injection",
		Category:    challenges.CatCmdI,
		Difficulty:  challenges.Medium,
		Description: "The server runs your command but doesn't show the output. Use out-of-band techniques to extract data.",
		Hint:        "Try time-based: 127.0.0.1; sleep 5  — if the response is delayed, injection works. Then use: ; echo FLAG > /tmp/cmdi_flag && cat /tmp/cmdi_flag",
		Flag:        "FLAG{bl1nd_cmd_inject}",
		Points:      200,
		Path:        "/challenges/cmdi/blind",
	})

	challenges.Register(&challenges.Challenge{
		ID:          "cmdi-03",
		Name:        "Filtered Command Injection",
		Category:    challenges.CatCmdI,
		Difficulty:  challenges.Hard,
		Description: "The application filters semicolons, pipes, and common shell metacharacters. Bypass the filter.",
		Hint:        "Try newlines (%0a), backticks (`id`), or $() substitution: $(whoami). Also try: 127.0.0.1%0aid",
		Flag:        "FLAG{f1lter_byp4ss_cmdi}",
		Points:      300,
		Path:        "/challenges/cmdi/filtered",
	})
}

func RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/challenges/cmdi/ping", handlePing)
	mux.HandleFunc("/challenges/cmdi/blind", handleBlind)
	mux.HandleFunc("/challenges/cmdi/filtered", handleFiltered)
}

func handlePing(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")

	result := ""
	if host != "" {
		// VULNERABLE: Direct command execution
		var cmd *exec.Cmd
		if runtime.GOOS == "windows" {
			cmd = exec.Command("cmd", "/C", "ping -n 1 "+host)
		} else {
			cmd = exec.Command("sh", "-c", "ping -c 1 "+host)
		}
		output, err := cmd.CombinedOutput()
		if err != nil {
			result = fmt.Sprintf(`<div class="output-box"><pre>%s\n%s</pre></div>`, string(output), err.Error())
		} else {
			result = fmt.Sprintf(`<div class="output-box"><pre>%s</pre></div>`, string(output))
		}

		// Check for injection
		if strings.Contains(host, ";") || strings.Contains(host, "&&") || strings.Contains(host, "|") || strings.Contains(host, "`") {
			result += `<div class="flag-box">🚩 FLAG{command_injection_101}</div>`
		}
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, page("cmdi-01", "Command Injection — Ping", fmt.Sprintf(`
		<form method="GET" class="challenge-form">
			<div class="form-group">
				<label>Hostname / IP</label>
				<input type="text" name="host" value="%s" placeholder="e.g., 127.0.0.1">
			</div>
			<button type="submit" class="btn">Ping</button>
		</form>
		%s
		<div class="info-box">
			<p><strong>Backend:</strong> <code>ping -c 1 [INPUT]</code></p>
		</div>
	`, host, result)))
}

func handleBlind(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")

	if host != "" {
		// VULNERABLE: Runs command but discards output
		var cmd *exec.Cmd
		if runtime.GOOS == "windows" {
			cmd = exec.Command("cmd", "/C", "ping -n 1 "+host)
		} else {
			cmd = exec.Command("sh", "-c", "ping -c 1 "+host+" > /dev/null 2>&1")
		}
		cmd.Run() // Output discarded
	}

	result := ""
	if host != "" {
		result = `<div class="alert alert-success">Ping sent successfully.</div>`
		if strings.Contains(host, ";") || strings.Contains(host, "&&") || strings.Contains(host, "`") || strings.Contains(host, "$(") {
			result += `<div class="flag-box">🚩 FLAG{bl1nd_cmd_inject}</div>`
		}
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, page("cmdi-02", "Blind Command Injection", fmt.Sprintf(`
		<form method="GET" class="challenge-form">
			<div class="form-group">
				<label>Hostname / IP</label>
				<input type="text" name="host" value="%s" placeholder="e.g., 127.0.0.1">
			</div>
			<button type="submit" class="btn">Ping</button>
		</form>
		%s
		<div class="info-box">
			<p><strong>Note:</strong> Output is NOT shown. This is a blind injection.</p>
			<p><strong>Try:</strong> Time-based detection with <code>sleep</code></p>
		</div>
	`, host, result)))
}

func handleFiltered(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")

	result := ""
	if host != "" {
		filtered := host
		// "Security" filter
		filtered = strings.ReplaceAll(filtered, ";", "")
		filtered = strings.ReplaceAll(filtered, "|", "")
		filtered = strings.ReplaceAll(filtered, "&", "")
		filtered = strings.ReplaceAll(filtered, ">", "")
		filtered = strings.ReplaceAll(filtered, "<", "")

		var cmd *exec.Cmd
		if runtime.GOOS == "windows" {
			cmd = exec.Command("cmd", "/C", "ping -n 1 "+filtered)
		} else {
			cmd = exec.Command("sh", "-c", "ping -c 1 "+filtered)
		}
		output, _ := cmd.CombinedOutput()
		result = fmt.Sprintf(`<div class="output-box"><pre>%s</pre></div>`, string(output))

		// Check for bypass via newline, backtick, $()
		if strings.Contains(host, "\n") || strings.Contains(host, "`") || strings.Contains(host, "$(") || strings.Contains(host, "%0a") {
			result += `<div class="flag-box">🚩 FLAG{f1lter_byp4ss_cmdi}</div>`
		}
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, page("cmdi-03", "Filtered Command Injection", fmt.Sprintf(`
		<form method="GET" class="challenge-form">
			<div class="form-group">
				<label>Hostname / IP</label>
				<input type="text" name="host" value="%s" placeholder="e.g., 127.0.0.1">
			</div>
			<button type="submit" class="btn">Ping</button>
		</form>
		%s
		<div class="info-box">
			<p><strong>Filtered:</strong> ; | & > < are removed</p>
			<p><strong>Objective:</strong> Bypass the filter and execute a command.</p>
		</div>
	`, host, result)))
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
