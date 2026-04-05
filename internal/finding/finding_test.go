package finding

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAllCategoriesComplete(t *testing.T) {
	seen := map[Category]bool{}
	for _, c := range AllCategories {
		seen[c] = true
	}
	for _, c := range []Category{
		CategoryExecutionIntegrity,
		CategoryDestructive,
		CategoryPrivilege,
		CategoryPersistence,
		CategoryNetwork,
		CategoryObfuscation,
		CategoryExecutionChain,
	} {
		assert.True(t, seen[c], "AllCategories missing %s", c)
	}
	assert.Len(t, AllCategories, 7)
}
