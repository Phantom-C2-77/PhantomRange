package scoreboard

import (
	"encoding/json"
	"os"
	"sort"
	"sync"
	"time"
)

const dataFile = "data/scoreboard.json"

// Entry represents a solved challenge.
type Entry struct {
	ChallengeID string    `json:"challenge_id"`
	Flag        string    `json:"flag"`
	SolvedAt    time.Time `json:"solved_at"`
	Points      int       `json:"points"`
	HintsUsed   int       `json:"hints_used"`
}

// Board tracks challenge progress.
type Board struct {
	mu      sync.RWMutex
	Entries map[string]*Entry `json:"entries"` // challengeID -> entry
	Total   int               `json:"total_points"`
	Solved  int               `json:"solved"`
}

// New creates a new scoreboard, loading existing progress.
func New() *Board {
	b := &Board{
		Entries: make(map[string]*Entry),
	}
	b.load()
	return b
}

// Submit checks a flag and records it if correct.
func (b *Board) Submit(challengeID, flag, correctFlag string, points int) (bool, string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Already solved?
	if _, ok := b.Entries[challengeID]; ok {
		return true, "Already solved!"
	}

	if flag != correctFlag {
		return false, "Incorrect flag. Try again."
	}

	// Correct!
	b.Entries[challengeID] = &Entry{
		ChallengeID: challengeID,
		Flag:        flag,
		SolvedAt:    time.Now(),
		Points:      points,
	}
	b.Solved++
	b.Total += points

	b.save()
	return true, "Correct! +" + itoa(points) + " points"
}

// UseHint records a hint usage (deducts points).
func (b *Board) UseHint(challengeID string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	entry, ok := b.Entries[challengeID]
	if ok {
		entry.HintsUsed++
	}
}

// IsSolved checks if a challenge has been completed.
func (b *Board) IsSolved(challengeID string) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	_, ok := b.Entries[challengeID]
	return ok
}

// Stats returns current progress.
func (b *Board) Stats() (solved, total int, points int) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.Solved, len(b.Entries), b.Total
}

// RecentSolves returns the last N solved challenges.
func (b *Board) RecentSolves(n int) []*Entry {
	b.mu.RLock()
	defer b.mu.RUnlock()

	entries := make([]*Entry, 0, len(b.Entries))
	for _, e := range b.Entries {
		entries = append(entries, e)
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].SolvedAt.After(entries[j].SolvedAt)
	})

	if len(entries) > n {
		entries = entries[:n]
	}
	return entries
}

// Reset clears all progress.
func (b *Board) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.Entries = make(map[string]*Entry)
	b.Total = 0
	b.Solved = 0
	b.save()
}

func (b *Board) load() {
	data, err := os.ReadFile(dataFile)
	if err != nil {
		return
	}
	json.Unmarshal(data, b)
}

func (b *Board) save() {
	os.MkdirAll("data", 0755)
	data, _ := json.MarshalIndent(b, "", "  ")
	os.WriteFile(dataFile, data, 0644)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	s := ""
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	return s
}
