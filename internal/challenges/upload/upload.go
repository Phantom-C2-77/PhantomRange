package upload

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/Phantom-C2-77/PhantomRange/internal/challenges"
)

func init() {
	challenges.Register(&challenges.Challenge{
		ID:          "upload-01",
		Name:        "Unrestricted File Upload",
		Category:    challenges.CatUpload,
		Difficulty:  challenges.Easy,
		Description: "The application allows uploading any file type. Upload a 'web shell' (any .php or .html file with a specific content).",
		Hint:        "Upload a file with .php or .html extension containing the text 'PHANTOM_SHELL'. The server doesn't validate file types.",
		Flag:        "FLAG{unr3stricted_upl0ad}",
		Points:      100,
		Path:        "/challenges/upload/basic",
	})

	challenges.Register(&challenges.Challenge{
		ID:          "upload-02",
		Name:        "Extension Filter Bypass",
		Category:    challenges.CatUpload,
		Difficulty:  challenges.Medium,
		Description: "The application blocks .php and .html uploads. Bypass the filter to upload a 'shell'.",
		Hint:        "Try double extensions (.php.jpg), null bytes (.php%00.jpg), or alternative extensions (.phtml, .php5, .phar). The filter only checks the last extension.",
		Flag:        "FLAG{ext3nsion_f1lter_byp4ss}",
		Points:      200,
		Path:        "/challenges/upload/filtered",
	})

	challenges.Register(&challenges.Challenge{
		ID:          "upload-03",
		Name:        "Content-Type Bypass",
		Category:    challenges.CatUpload,
		Difficulty:  challenges.Hard,
		Description: "The server checks both extension AND Content-Type header. Bypass both checks.",
		Hint:        "The server checks: extension must be .jpg/.png AND Content-Type must be image/*. But you control the Content-Type header. Upload a .php.jpg with Content-Type: image/jpeg but PHP content.",
		Flag:        "FLAG{c0ntent_typ3_byp4ss}",
		Points:      300,
		Path:        "/challenges/upload/content-type",
	})
}

func RegisterRoutes(mux *http.ServeMux) {
	os.MkdirAll("data/uploads", 0755)
	mux.HandleFunc("/challenges/upload/basic", handleBasic)
	mux.HandleFunc("/challenges/upload/filtered", handleFiltered)
	mux.HandleFunc("/challenges/upload/content-type", handleContentType)
}

func handleBasic(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, page("upload-01", "Unrestricted File Upload", `
			<form method="POST" enctype="multipart/form-data" class="challenge-form">
				<div class="form-group"><label>Choose File</label><input type="file" name="file" required></div>
				<button type="submit" class="btn">Upload</button>
			</form>
			<div class="info-box">
				<p><strong>Objective:</strong> Upload a file containing "PHANTOM_SHELL" with a .php or .html extension.</p>
				<p><strong>No restrictions</strong> on file type or content.</p>
			</div>
		`))
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, page("upload-01", "Unrestricted File Upload", `<div class="alert alert-danger">Upload failed.</div><a href="/challenges/upload/basic" class="btn">Back</a>`))
		return
	}
	defer file.Close()

	content, _ := io.ReadAll(io.LimitReader(file, 1<<20))
	ext := filepath.Ext(header.Filename)

	flag := ""
	if (ext == ".php" || ext == ".html" || ext == ".phtml") && strings.Contains(string(content), "PHANTOM_SHELL") {
		flag = `<div class="flag-box">🚩 FLAG{unr3stricted_upl0ad}</div>`
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, page("upload-01", "Unrestricted File Upload", fmt.Sprintf(`
		<div class="alert alert-success">File uploaded: %s (%d bytes, ext: %s)</div>
		%s
		<a href="/challenges/upload/basic" class="btn">Upload Another</a>
	`, header.Filename, len(content), ext, flag)))
}

func handleFiltered(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, page("upload-02", "Extension Filter Bypass", `
			<form method="POST" enctype="multipart/form-data" class="challenge-form">
				<div class="form-group"><label>Choose File</label><input type="file" name="file" required></div>
				<button type="submit" class="btn">Upload</button>
			</form>
			<div class="info-box">
				<p><strong>Blocked extensions:</strong> .php, .html, .phtml, .jsp, .asp</p>
				<p><strong>Objective:</strong> Upload a file containing "PHANTOM_SHELL" despite the filter.</p>
			</div>
		`))
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, page("upload-02", "Extension Filter Bypass", `<div class="alert alert-danger">Upload failed.</div><a href="/challenges/upload/filtered" class="btn">Back</a>`))
		return
	}
	defer file.Close()

	content, _ := io.ReadAll(io.LimitReader(file, 1<<20))
	ext := strings.ToLower(filepath.Ext(header.Filename))

	// "Security" filter — only checks last extension
	blocked := []string{".php", ".html", ".phtml", ".jsp", ".asp"}
	for _, b := range blocked {
		if ext == b {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, page("upload-02", "Extension Filter Bypass", `
				<div class="alert alert-danger">Blocked: %s files are not allowed!</div>
				<a href="/challenges/upload/filtered" class="btn">Try Again</a>
			`), ext)
			return
		}
	}

	// Check for bypass
	flag := ""
	fullName := strings.ToLower(header.Filename)
	hasShellContent := strings.Contains(string(content), "PHANTOM_SHELL")

	if hasShellContent && (strings.Contains(fullName, ".php") || strings.Contains(fullName, ".phtml") || strings.Contains(fullName, ".html")) {
		flag = `<div class="flag-box">🚩 FLAG{ext3nsion_f1lter_byp4ss}</div>`
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, page("upload-02", "Extension Filter Bypass", fmt.Sprintf(`
		<div class="alert alert-success">File uploaded: %s (%d bytes)</div>
		%s
		<a href="/challenges/upload/filtered" class="btn">Upload Another</a>
	`, header.Filename, len(content), flag)))
}

func handleContentType(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, page("upload-03", "Content-Type Bypass", `
			<form method="POST" enctype="multipart/form-data" class="challenge-form">
				<div class="form-group"><label>Choose File</label><input type="file" name="file" required></div>
				<button type="submit" class="btn">Upload</button>
			</form>
			<div class="info-box">
				<p><strong>Checks:</strong> Extension must be .jpg or .png AND Content-Type must be image/*</p>
				<p><strong>Objective:</strong> Upload PHP/shell content that passes both checks.</p>
				<p><strong>Hint:</strong> Use Burp Suite or curl to modify the Content-Type header.</p>
				<p><code>curl -F "file=@shell.php.jpg;type=image/jpeg" http://localhost:8080/challenges/upload/content-type</code></p>
			</div>
		`))
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, page("upload-03", "Content-Type Bypass", `<div class="alert alert-danger">Upload failed.</div>`))
		return
	}
	defer file.Close()

	content, _ := io.ReadAll(io.LimitReader(file, 1<<20))
	ext := strings.ToLower(filepath.Ext(header.Filename))
	contentType := header.Header.Get("Content-Type")

	// Check extension
	if ext != ".jpg" && ext != ".png" && ext != ".jpeg" && ext != ".gif" {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, page("upload-03", "Content-Type Bypass", `
			<div class="alert alert-danger">Only image files (.jpg, .png) allowed! Got: %s</div>
			<a href="/challenges/upload/content-type" class="btn">Try Again</a>
		`), ext)
		return
	}

	// Check Content-Type
	if !strings.HasPrefix(contentType, "image/") {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, page("upload-03", "Content-Type Bypass", `
			<div class="alert alert-danger">Content-Type must be image/*! Got: %s</div>
			<a href="/challenges/upload/content-type" class="btn">Try Again</a>
		`), contentType)
		return
	}

	// Both checks passed — check if content is actually a shell
	flag := ""
	if strings.Contains(string(content), "PHANTOM_SHELL") || strings.Contains(string(content), "<?php") || strings.Contains(string(content), "<script") {
		flag = `<div class="flag-box">🚩 FLAG{c0ntent_typ3_byp4ss}</div>
			<div class="info-box"><p>You passed the extension AND Content-Type checks with malicious content!</p></div>`
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, page("upload-03", "Content-Type Bypass", fmt.Sprintf(`
		<div class="alert alert-success">File uploaded: %s (Content-Type: %s, %d bytes)</div>
		%s
		<a href="/challenges/upload/content-type" class="btn">Upload Another</a>
	`, header.Filename, contentType, len(content), flag)))
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
