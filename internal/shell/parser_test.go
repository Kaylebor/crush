package shell

import (
	"testing"
)

func TestParseCommands(t *testing.T) {
	tests := []struct {
		name     string
		command  string
		expected []string
	}{
		{
			name:     "Simple command",
			command:  "git status",
			expected: []string{"git status"},
		},
		{
			name:     "AND operator",
			command:  "git status && rm -rf /",
			expected: []string{"git status", "rm -rf /"},
		},
		{
			name:     "OR operator",
			command:  "cmd1 || cmd2",
			expected: []string{"cmd1", "cmd2"},
		},
		{
			name:     "Semicolon separator",
			command:  "cmd1; cmd2",
			expected: []string{"cmd1", "cmd2"},
		},
		{
			name:     "Mixed AND and OR operators",
			command:  "cmd1 && cmd2 || cmd3",
			expected: []string{"cmd1", "cmd2", "cmd3"},
		},
		{
			name:     "Multiple AND operators",
			command:  "cmd1 && cmd2 && cmd3",
			expected: []string{"cmd1", "cmd2", "cmd3"},
		},
		{
			name:     "Multiple OR operators",
			command:  "cmd1 || cmd2 || cmd3",
			expected: []string{"cmd1", "cmd2", "cmd3"},
		},
		{
			name:     "Mixed operators with semicolons",
			command:  "cmd1; cmd2 && cmd3",
			expected: []string{"cmd1", "cmd2", "cmd3"},
		},
		{
			name:     "OR and AND combination",
			command:  "cmd1 || cmd2 && cmd3",
			expected: []string{"cmd1", "cmd2", "cmd3"},
		},
		{
			name:     "Quoted string with operator",
			command:  `echo "hello && world"`,
			expected: []string{`echo "hello && world"`},
		},
		{
			name:     "Single quoted string with operator",
			command:  `echo 'hello && world'`,
			expected: []string{`echo 'hello && world'`},
		},
		{
			name:     "Escaped quotes in double quotes",
			command:  `echo "hello \"world\""`,
			expected: []string{`echo "hello \"world\""`},
		},
		{
			name:     "Mixed quotes",
			command:  `echo "hello '&&' world"`,
			expected: []string{`echo "hello '&&' world"`},
		},
		{
			name:     "Backslash escape in normal context",
			command:  `echo hello\;\ world`,
			expected: []string{`echo hello\;\ world`},
		},
		{
			name:     "Multiple escaped characters",
			command:  `echo "test\;test" && echo "another\|test"`,
			expected: []string{`echo "test\;test"`, `echo "another\|test"`},
		},
		{
			name:     "Empty command",
			command:  "",
			expected: []string{},
		},
		{
			name:     "Only whitespace",
			command:  "   ",
			expected: []string{},
		},
		{
			name:     "Trailing operator",
			command:  "cmd1 && ",
			expected: []string{"cmd1"},
		},
		{
			name:     "Leading operator",
			command:  " && cmd1",
			expected: []string{"cmd1"},
		},
		{
			name:     "Multiple spaces around operators",
			command:  "cmd1  &&  cmd2  ||  cmd3",
			expected: []string{"cmd1", "cmd2", "cmd3"},
		},
		{
			name:     "Complex nested quotes",
			command:  `echo "test \"cmd1 && cmd2\" end" && echo 'test'`,
			expected: []string{`echo "test \"cmd1 && cmd2\" end"`, "echo 'test'"},
		},
		{
			name:     "Real world git example",
			command:  `git status && rm -rf /`,
			expected: []string{"git status", "rm -rf /"},
		},
		{
			name:     "Pipe operator (now a command separator)",
			command:  "cmd1 | cmd2 && cmd3",
			expected: []string{"cmd1", "cmd2", "cmd3"},
		},
		{
			name:     "Multiple pipes",
			command:  "cat file.txt | grep test | sort && echo done",
			expected: []string{"cat file.txt", "grep test", "sort", "echo done"},
		},
		{
			name:     "Complex nested quotes",
			command:  `echo "test \"cmd1 && cmd2\" end" && echo 'test'`,
			expected: []string{`echo "test \"cmd1 && cmd2\" end"`, "echo 'test'"},
		},
		{
			name:     "Real world git example",
			command:  `git status && rm -rf /`,
			expected: []string{"git status", "rm -rf /"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseCommands(tt.command)
			if len(result) != len(tt.expected) {
				t.Errorf("ParseCommands(%q) = %v (len %d), want %v (len %d)", tt.command, result, len(result), tt.expected, len(tt.expected))
				return
			}
			for i := range result {
				if result[i] != tt.expected[i] {
					t.Errorf("ParseCommands(%q)[%d] = %q, want %q", tt.command, i, result[i], tt.expected[i])
				}
			}
		})
	}
}

func TestContainsCompoundOperator(t *testing.T) {
	tests := []struct {
		name     string
		command  string
		expected bool
	}{
		{
			name:     "Simple command without operator",
			command:  "git status",
			expected: false,
		},
		{
			name:     "Command with AND operator",
			command:  "git status && rm -rf /",
			expected: true,
		},
		{
			name:     "Command with OR operator",
			command:  "cmd1 || cmd2",
			expected: true,
		},
		{
			name:     "Command with semicolon",
			command:  "cmd1; cmd2",
			expected: true,
		},
		{
			name:     "Command without operator but with semicolon in quotes",
			command:  `echo "test;"`,
			expected: false,
		},
		{
			name:     "Empty command",
			command:  "",
			expected: false,
		},
		{
			name:     "Operator in single quotes",
			command:  `echo '&&'`,
			expected: false,
		},
		{
			name:     "Operator in double quotes",
			command:  `echo "&&"`,
			expected: false,
		},
		{
			name:     "Escaped operator",
			command:  `echo test\;`,
			expected: false,
		},
		{
			name:     "Multiple operators",
			command:  "cmd1 && cmd2 || cmd3",
			expected: true,
		},
		{
			name:     "Operator with surrounding whitespace",
			command:  "cmd1  &&  cmd2",
			expected: true,
		},
		{
			name:     "Multiple pipes (now | is treated as compound operator)",
			command:  "cat foo | grep bar",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ContainsCompoundOperator(tt.command)
			if result != tt.expected {
				t.Errorf("ContainsCompoundOperator(%q) = %v, want %v", tt.command, result, tt.expected)
			}
		})
	}
}

func TestParseCommands_RealWorldExamples(t *testing.T) {
	tests := []struct {
		name     string
		command  string
		expected []string
	}{
		{
			name:     "Git pull and build",
			command:  "git pull origin main && go build ./... && go test ./...",
			expected: []string{"git pull origin main", "go build ./...", "go test ./..."},
		},
		{
			name:     "Fallback commands",
			command:  "npm install || yarn install || pnpm install",
			expected: []string{"npm install", "yarn install", "pnpm install"},
		},
		{
			name:     "Setup script with semicolons",
			command:  "cd /tmp; rm -rf project; git clone https://github.com/user/project.git",
			expected: []string{"cd /tmp", "rm -rf project", "git clone https://github.com/user/project.git"},
		},
		{
			name:     "Complex build with mixed operators",
			command:  "make clean; make build && make test || echo 'Build failed'",
			expected: []string{"make clean", "make build", "make test", "echo 'Build failed'"},
		},
		{
			name:     "Command with environment variable",
			command:  `export PATH="/usr/local/bin:$PATH" && go version`,
			expected: []string{`export PATH="/usr/local/bin:$PATH"`, "go version"},
		},
		{
			name:     "Docker command with quotes",
			command:  `docker run -it --rm -v "$(pwd):/app" alpine:latest sh -c "echo test && ls"`,
			expected: []string{`docker run -it --rm -v "$(pwd):/app" alpine:latest sh -c "echo test && ls"`},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseCommands(tt.command)
			if len(result) != len(tt.expected) {
				t.Errorf("ParseCommands(%q) = %v (len %d), want %v (len %d)", tt.command, result, len(result), tt.expected, len(tt.expected))
				return
			}
			for i := range result {
				if result[i] != tt.expected[i] {
					t.Errorf("ParseCommands(%q)[%d] = %q, want %q", tt.command, i, result[i], tt.expected[i])
				}
			}
		})
	}
}
