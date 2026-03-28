package challenges

// Difficulty levels
const (
	Easy   = "Easy"
	Medium = "Medium"
	Hard   = "Hard"
)

// Category names
const (
	CatSQLi   = "SQL Injection"
	CatXSS    = "Cross-Site Scripting"
	CatAuth   = "Authentication"
	CatIDOR   = "Access Control / IDOR"
	CatSSRF   = "Server-Side Request Forgery"
	CatUpload = "File Upload"
	CatCmdI   = "Command Injection"
	CatCrypto = "Cryptography"
)

// Challenge defines a single vulnerable challenge.
type Challenge struct {
	ID          string
	Name        string
	Category    string
	Difficulty  string
	Description string
	Hint        string
	Flag        string
	Points      int
	Path        string // URL path for this challenge
}

// Registry holds all challenges.
var Registry = make(map[string]*Challenge)

// Register adds a challenge to the registry.
func Register(c *Challenge) {
	Registry[c.ID] = c
}

// GetByID retrieves a challenge by ID.
func GetByID(id string) *Challenge {
	return Registry[id]
}

// GetByCategory returns challenges in a category.
func GetByCategory(category string) []*Challenge {
	var result []*Challenge
	for _, c := range Registry {
		if c.Category == category {
			result = append(result, c)
		}
	}
	return result
}

// AllCategories returns all unique categories.
func AllCategories() []string {
	return []string{CatSQLi, CatXSS, CatAuth, CatIDOR, CatSSRF, CatUpload, CatCmdI, CatCrypto}
}

// All returns all challenges.
func All() []*Challenge {
	result := make([]*Challenge, 0, len(Registry))
	for _, c := range Registry {
		result = append(result, c)
	}
	return result
}
