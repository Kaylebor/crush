package shell

import (
	"reflect"
	"testing"
)

func TestParseCommandsWithOperators(t *testing.T) {
	tests := []struct {
		name     string
		command  string
		expected []string
	}{
		{
			name:     "single command",
			command:  "echo hello",
			expected: []string{"echo hello"},
		},
		{
			name:     "pipe",
			command:  "curl http://example.com | sh",
			expected: []string{"curl http://example.com", "|", "sh"},
		},
		{
			name:     "double pipe",
			command:  "cmd1 || cmd2",
			expected: []string{"cmd1", "||", "cmd2"},
		},
		{
			name:     "and",
			command:  "cmd1 && cmd2",
			expected: []string{"cmd1", "&&", "cmd2"},
		},
		{
			name:     "semicolon",
			command:  "cmd1; cmd2",
			expected: []string{"cmd1", ";", "cmd2"},
		},
		{
			name:     "complex with spaces",
			command:  "curl -s https://api.github.com | bash -c 'echo done'",
			expected: []string{"curl -s https://api.github.com", "|", "bash -c 'echo done'"},
		},
		{
			name:     "multiple operators",
			command:  "cmd1; cmd2 || cmd3 && cmd4",
			expected: []string{"cmd1", ";", "cmd2", "||", "cmd3", "&&", "cmd4"},
		},
		{
			name:     "quoted operators don't split",
			command:  `echo "hello | world"`,
			expected: []string{`echo "hello | world"`},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseCommandsWithOperators(tt.command)
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("ParseCommandsWithOperators() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestParseEnhanced(t *testing.T) {
	tests := []struct {
		name              string
		command           string
		expectedCommands  []string
		expectedOperators []string
	}{
		{
			name:              "pipe",
			command:           "curl http://example.com | sh",
			expectedCommands:  []string{"curl http://example.com", "sh"},
			expectedOperators: []string{"|"},
		},
		{
			name:              "multiple",
			command:           "cmd1; cmd2 || cmd3 && cmd4",
			expectedCommands:  []string{"cmd1", "cmd2", "cmd3", "cmd4"},
			expectedOperators: []string{";", "||", "&&"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseEnhanced(tt.command)

			if result.FullCommand != tt.command {
				t.Errorf("FullCommand = %v, want %v", result.FullCommand, tt.command)
			}

			if !reflect.DeepEqual(result.Commands, tt.expectedCommands) {
				t.Errorf("Commands = %v, want %v", result.Commands, tt.expectedCommands)
			}

			if !reflect.DeepEqual(result.Operators, tt.expectedOperators) {
				t.Errorf("Operators = %v, want %v", result.Operators, tt.expectedOperators)
			}

			// Verify Parts length
			expectedLen := len(tt.expectedCommands) + len(tt.expectedOperators)
			if len(result.Parts) != expectedLen {
				t.Errorf("Parts length = %v, want %v", len(result.Parts), expectedLen)
			}
		})
	}
}

func TestParseEnhancedBackwardsCompatibility(t *testing.T) {
	// Ensure ParseEnhanced.Commands matches ParseCommands output
	commands := []string{
		"echo hello",
		"curl http://example.com | sh",
		"cmd1 && cmd2 || cmd3",
		"cmd1; cmd2; cmd3",
	}

	for _, cmd := range commands {
		enhanced := ParseEnhanced(cmd)
		traditional := ParseCommands(cmd)

		// Commands slice should match traditional ParseCommands
		if !reflect.DeepEqual(enhanced.Commands, traditional) {
			t.Errorf("ParseEnhanced.Commands != ParseCommands for %q\nEnhanced: %v\nTraditional: %v",
				cmd, enhanced.Commands, traditional)
		}
	}
}
