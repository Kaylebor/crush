package permission

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestCommandPatternExtraction verifies command pattern extraction works via extractCommandPattern
func TestCommandPatternExtraction(t *testing.T) {
	tests := []struct {
		name     string
		command  string
		expected string
	}{
		{"git commit", "git commit", "git commit"},
		{"git push", "git push", "git push"},
		{"ls", "ls", "ls"},
		{"ls -la", "ls -la", "ls"},
		{"git -C /path log", "git -C /path log", "git log"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := map[string]any{"command": tt.command}
			
			// Test the helper function directly
			pattern, _ := extractCommandPattern("bash", params)
			require.Equal(t, tt.expected, pattern, "pattern should match expected")
		})
	}
}
