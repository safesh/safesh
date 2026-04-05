// Package finding defines the Finding type and Category constants used across safesh.
package finding

// Category identifies the type of finding.
type Category string

// Category constants for finding classification.
const (
	CategoryExecutionIntegrity Category = "execution-integrity"
	CategoryDestructive        Category = "destructive"
	CategoryPrivilege          Category = "privilege"
	CategoryPersistence        Category = "persistence"
	CategoryNetwork            Category = "network"
	CategoryObfuscation        Category = "obfuscation"
	CategoryExecutionChain     Category = "execution-chain"
)

// AllCategories lists every known category in display order.
var AllCategories = []Category{
	CategoryExecutionIntegrity,
	CategoryDestructive,
	CategoryPrivilege,
	CategoryPersistence,
	CategoryNetwork,
	CategoryObfuscation,
	CategoryExecutionChain,
}

// Finding represents a single analysis result.
type Finding struct {
	Category    Category `json:"category"`
	Line        int      `json:"line"`
	Col         int      `json:"col"`
	Description string   `json:"description"`
	Snippet     string   `json:"snippet,omitempty"`
}

// Module is implemented by each analysis module.
type Module interface {
	Analyze(src []byte) []Finding
}
