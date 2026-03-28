package ssrf

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Phantom-C2-77/PhantomRange/internal/challenges"
)

// Internal service (simulated)
var internalFlag = "FLAG{ssrf_internal_s3rvice}"

func init() {
	challenges.Register(&challenges.Challenge{
		ID:          "ssrf-01",
		Name:        "Basic SSRF",
		Category:    challenges.CatSSRF,
		Difficulty:  challenges.Easy,
		Description: "A URL preview feature fetches and displays remote pages. Use it to access an internal service on localhost.",
		Hint:        "Try: http://127.0.0.1:9999/internal/flag — there's a hidden internal service.",
		Flag:        "FLAG{ssrf_internal_s3rvice}",
		Points:      150,
		Path:        "/challenges/ssrf/basic",
	})

	challenges.Register(&challenges.Challenge{
		ID:          "ssrf-02",
		Name:        "SSRF with Filter Bypass",
		Category:    challenges.CatSSRF,
		Difficulty:  challenges.Medium,
		Description: "The application blocks requests to 127.0.0.1 and localhost. Bypass the filter.",
		Hint:        "Try: http://0.0.0.0:9999, http://[::1]:9999, http://0x7f000001:9999, http://2130706433:9999 (decimal IP)",
		Flag:        "FLAG{ssrf_f1lter_byp4ss}",
		Points:      250,
		Path:        "/challenges/ssrf/filtered",
	})

	challenges.Register(&challenges.Challenge{
		ID:          "ssrf-03",
		Name:        "SSRF to Cloud Metadata",
		Category:    challenges.CatSSRF,
		Difficulty:  challenges.Hard,
		Description: "Access the simulated cloud metadata service at http://169.254.169.254 to retrieve credentials.",
		Hint:        "AWS metadata endpoint: http://169.254.169.254/latest/meta-data/iam/security-credentials/. The app simulates this internally.",
		Flag:        "FLAG{cl0ud_m3tadata_l3ak}",
		Points:      300,
		Path:        "/challenges/ssrf/cloud",
	})
}

func RegisterRoutes(mux *http.ServeMux) {
	// Start the internal service
	go startInternalService()

	mux.HandleFunc("/challenges/ssrf/basic", handleBasic)
	mux.HandleFunc("/challenges/ssrf/filtered", handleFiltered)
	mux.HandleFunc("/challenges/ssrf/cloud", handleCloud)
}

func startInternalService() {
	internalMux := http.NewServeMux()
	internalMux.HandleFunc("/internal/flag", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "Internal Service\n\nSecret: %s\n", internalFlag)
	})
	internalMux.HandleFunc("/latest/meta-data/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "ami-id\nami-launch-index\nhostname\niam/\ninstance-id\nlocal-ipv4\npublic-ipv4\n")
	})
	internalMux.HandleFunc("/latest/meta-data/iam/security-credentials/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"AccessKeyId":"AKIA_FAKE_KEY","SecretAccessKey":"FLAG{cl0ud_m3tadata_l3ak}","Token":"FakeSessionToken","Expiration":"2026-12-31T23:59:59Z"}`)
	})

	http.ListenAndServe("127.0.0.1:9999", internalMux)
}

func handleBasic(w http.ResponseWriter, r *http.Request) {
	url := r.URL.Query().Get("url")

	result := ""
	if url != "" {
		// VULNERABLE: Fetches any URL including internal services
		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Get(url)
		if err != nil {
			result = fmt.Sprintf(`<div class="alert alert-danger">Error: %s</div>`, err.Error())
		} else {
			defer resp.Body.Close()
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 10000))
			content := string(body)
			result = fmt.Sprintf(`<div class="output-box"><pre>Status: %d\n\n%s</pre></div>`, resp.StatusCode, content)

			if strings.Contains(content, "FLAG{") {
				// Extract and display flag
				start := strings.Index(content, "FLAG{")
				end := strings.Index(content[start:], "}") + start + 1
				result += fmt.Sprintf(`<div class="flag-box">🚩 %s</div>`, content[start:end])
			}
		}
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, page("ssrf-01", "Basic SSRF", fmt.Sprintf(`
		<form method="GET" class="challenge-form">
			<div class="form-group"><label>URL to Preview</label><input type="text" name="url" value="%s" placeholder="https://example.com"></div>
			<button type="submit" class="btn">Fetch Page</button>
		</form>
		%s
		<div class="info-box">
			<p><strong>Objective:</strong> There's an internal service running. Access it.</p>
			<p><strong>Hint:</strong> What services might be running on localhost?</p>
		</div>
	`, url, result)))
}

func handleFiltered(w http.ResponseWriter, r *http.Request) {
	url := r.URL.Query().Get("url")

	result := ""
	if url != "" {
		// "Security" filter
		blocked := false
		lower := strings.ToLower(url)
		if strings.Contains(lower, "127.0.0.1") || strings.Contains(lower, "localhost") {
			blocked = true
			result = `<div class="alert alert-danger">Blocked: localhost and 127.0.0.1 are not allowed!</div>`
		}

		if !blocked {
			client := &http.Client{Timeout: 5 * time.Second}
			resp, err := client.Get(url)
			if err != nil {
				result = fmt.Sprintf(`<div class="alert alert-danger">Error: %s</div>`, err.Error())
			} else {
				defer resp.Body.Close()
				body, _ := io.ReadAll(io.LimitReader(resp.Body, 10000))
				content := string(body)
				result = fmt.Sprintf(`<div class="output-box"><pre>%s</pre></div>`, content)

				if strings.Contains(content, internalFlag) {
					result += `<div class="flag-box">🚩 FLAG{ssrf_f1lter_byp4ss}</div>`
				}
			}
		}
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, page("ssrf-02", "SSRF Filter Bypass", fmt.Sprintf(`
		<form method="GET" class="challenge-form">
			<div class="form-group"><label>URL to Preview</label><input type="text" name="url" value="%s" placeholder="https://example.com"></div>
			<button type="submit" class="btn">Fetch Page</button>
		</form>
		%s
		<div class="info-box">
			<p><strong>Blocked:</strong> 127.0.0.1, localhost</p>
			<p><strong>Objective:</strong> Bypass the filter and access the internal service on port 9999.</p>
			<p><strong>Hint:</strong> There are many ways to represent localhost...</p>
		</div>
	`, url, result)))
}

func handleCloud(w http.ResponseWriter, r *http.Request) {
	url := r.URL.Query().Get("url")

	result := ""
	if url != "" {
		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Get(url)
		if err != nil {
			result = fmt.Sprintf(`<div class="alert alert-danger">Error: %s</div>`, err.Error())
		} else {
			defer resp.Body.Close()
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 10000))
			content := string(body)
			result = fmt.Sprintf(`<div class="output-box"><pre>%s</pre></div>`, content)

			if strings.Contains(content, "FLAG{") {
				start := strings.Index(content, "FLAG{")
				end := strings.Index(content[start:], "}") + start + 1
				result += fmt.Sprintf(`<div class="flag-box">🚩 %s</div>`, content[start:end])
			}
		}
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, page("ssrf-03", "SSRF to Cloud Metadata", fmt.Sprintf(`
		<form method="GET" class="challenge-form">
			<div class="form-group"><label>URL to Preview</label><input type="text" name="url" value="%s" placeholder="https://example.com"></div>
			<button type="submit" class="btn">Fetch Page</button>
		</form>
		%s
		<div class="info-box">
			<p><strong>Scenario:</strong> This application runs on AWS (simulated).</p>
			<p><strong>Objective:</strong> Access the cloud metadata service to steal IAM credentials.</p>
			<p><strong>AWS metadata:</strong> <code>http://169.254.169.254/latest/meta-data/</code></p>
			<p><strong>Note:</strong> The metadata service is simulated on localhost:9999</p>
			<p>Try: <code>http://127.0.0.1:9999/latest/meta-data/iam/security-credentials/</code></p>
		</div>
	`, url, result)))
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
