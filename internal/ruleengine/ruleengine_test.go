package ruleengine

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPermissionRule_Validate(t *testing.T) {
	tests := []struct {
		name    string
		rule    PermissionRule
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid rule with allow patterns",
			rule: PermissionRule{
				Tool:  "bash",
				Allow: []string{"ls", "pwd", "git status"},
			},
			wantErr: false,
		},
		{
			name: "valid rule with deny patterns",
			rule: PermissionRule{
				Tool: "bash",
				Deny: []string{"rm -rf /", "dd if="},
			},
			wantErr: false,
		},
		{
			name: "valid rule with both allow and deny",
			rule: PermissionRule{
				Tool:  "edit",
				Allow: []string{"*.go", "*.md"},
				Deny:  []string{"*.key", "*.pem"},
			},
			wantErr: false,
		},
		{
			name: "valid rule with regex flag",
			rule: PermissionRule{
				Tool:  "grep",
				Allow: []string{"^import", "^func main"},
				Regex: true,
			},
			wantErr: false,
		},
		{
			name: "valid rule with custom message",
			rule: PermissionRule{
				Tool:    "download",
				Deny:    []string{"*.exe", "*.sh"},
				Message: "Executable downloads are not allowed",
			},
			wantErr: false,
		},
		{
			name: "invalid rule - no tool specified",
			rule: PermissionRule{
				Allow: []string{"ls"},
			},
			wantErr: true,
			errMsg:  "tool name is required",
		},
		{
			name: "valid rule - empty rule uses default effect",
			rule: PermissionRule{
				Tool: "bash", // Empty rule - uses DefaultEffect from RuleSet
			},
			wantErr: false,
		},
		{
			name: "valid rule - empty allow and deny uses default effect",
			rule: PermissionRule{
				Tool:  "bash",
				Allow: []string{},
				Deny:  []string{}, // Empty patterns - uses DefaultEffect
			},
			wantErr: false,
		},
		{
			name: "valid rule - allow_all without patterns",
			rule: PermissionRule{
				Tool:     "mcp-tool",
				AllowAll: true,
			},
			wantErr: false,
		},
		{
			name: "valid rule - deny_all without patterns",
			rule: PermissionRule{
				Tool:    "dangerous-tool",
				DenyAll: true,
			},
			wantErr: false,
		},
		{
			name: "valid rule - both allow_all and deny_all",
			rule: PermissionRule{
				Tool:     "some-tool",
				AllowAll: true,
				DenyAll:  true,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.rule.Validate()
			if tt.wantErr {
				require.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCompiledRule_Match(t *testing.T) {
	tests := []struct {
		name        string
		rule        PermissionRule
		request     PermissionRequest
		expectMatch bool
		expectDeny  bool
		rootDir     string
	}{
		// Bash command tests
		{
			name: "bash allow - simple command match",
			rule: PermissionRule{
				Tool:  "bash",
				Allow: []string{"ls", "pwd", "git status"},
			},
			request: PermissionRequest{
				Tool:    "bash",
				Command: "ls",
			},
			expectMatch: true,
			expectDeny:  false,
		},
		{
			name: "bash allow - command not in list",
			rule: PermissionRule{
				Tool:  "bash",
				Allow: []string{"ls", "pwd"},
			},
			request: PermissionRequest{
				Tool:    "bash",
				Command: "rm -rf /",
			},
			expectMatch: false,
		},
		{
			name: "bash deny - matches deny pattern",
			rule: PermissionRule{
				Tool: "bash",
				Deny: []string{"rm -rf /", "dd if="},
			},
			request: PermissionRequest{
				Tool:    "bash",
				Command: "rm -rf /",
			},
			expectMatch: true,
			expectDeny:  true,
		},
		{
			name: "bash deny - prefix match",
			rule: PermissionRule{
				Tool: "bash",
				Deny: []string{"rm "},
			},
			request: PermissionRequest{
				Tool:    "bash",
				Command: "rm important.txt",
			},
			expectMatch: true,
			expectDeny:  true,
		},
		{
			name: "bash deny - prefix with word boundary check (should match)",
			rule: PermissionRule{
				Tool:  "bash",
				Allow: []string{"ls "},
			},
			request: PermissionRequest{
				Tool:    "bash",
				Command: "lsdangerous /etc/passwd", // Should NOT match "ls "
			},
			expectMatch: false,
			expectDeny:  false,
		},
		{
			name: "bash allow - prefix with word boundary check (should allow)",
			rule: PermissionRule{
				Tool:  "bash",
				Allow: []string{"ls "},
			},
			request: PermissionRequest{
				Tool:    "bash",
				Command: "ls -la",
			},
			expectMatch: true,
			expectDeny:  false,
		},
		// Edit/write tests with glob patterns
		{
			name: "edit allow - glob pattern match",
			rule: PermissionRule{
				Tool:  "edit",
				Allow: []string{"**/*.go", "**/*.md"},
			},
			request: PermissionRequest{
				Tool: "edit",
				Path: "/home/user/project/main.go",
			},
			expectMatch: true,
			expectDeny:  false,
		},
		{
			name: "edit allow - no glob match",
			rule: PermissionRule{
				Tool:  "edit",
				Allow: []string{"**/*.go", "**/*.md"},
			},
			request: PermissionRequest{
				Tool: "edit",
				Path: "/home/user/project/config.json",
			},
			expectMatch: false,
		},
		{
			name: "edit deny - sensitive file pattern",
			rule: PermissionRule{
				Tool: "edit",
				Deny: []string{"**/*.key", "**/*.pem", "**/.env"},
			},
			request: PermissionRequest{
				Tool: "edit",
				Path: "/home/user/project/secret.key",
			},
			expectMatch: true,
			expectDeny:  true,
		},
		// Download tests
		{
			name: "download allow - specific URL",
			rule: PermissionRule{
				Tool:  "download",
				Allow: []string{"https://github.com/**", "https://raw.githubusercontent.com/**"},
			},
			request: PermissionRequest{
				Tool: "download",
				URL:  "https://github.com/charmbracelet/crush/archive/refs/heads/main.zip",
			},
			expectMatch: true,
			expectDeny:  false,
		},
		{
			name: "download deny - executable file",
			rule: PermissionRule{
				Tool: "download",
				Deny: []string{"**/*.exe", "**/*.sh"},
			},
			request: PermissionRequest{
				Tool: "download",
				URL:  "https://example.com/malware.exe",
			},
			expectMatch: true,
			expectDeny:  true,
		},
		// Regex tests
		{
			name: "grep regex match",
			rule: PermissionRule{
				Tool:  "grep",
				Allow: []string{"^import ", "^package "},
				Regex: true,
			},
			request: PermissionRequest{
				Tool:    "grep",
				Pattern: "import foo",
			},
			expectMatch: true,
			expectDeny:  false,
		},
		{
			name: "grep regex no match",
			rule: PermissionRule{
				Tool:  "grep",
				Allow: []string{"^import ", "^package "},
				Regex: true,
			},
			request: PermissionRequest{
				Tool:    "grep",
				Pattern: "func main",
			},
			expectMatch: false,
		},
		// Mismatching tool
		{
			name: "different tool - no match",
			rule: PermissionRule{
				Tool:  "bash",
				Allow: []string{"ls"},
			},
			request: PermissionRequest{
				Tool:    "edit",
				Command: "ls",
			},
			expectMatch: false,
		},
		// Compound command tests (most restrictive)
		{
			name: "compound command - subcommand matches deny",
			rule: PermissionRule{
				Tool: "bash",
				Deny: []string{"rm "},
			},
			request: PermissionRequest{
				Tool:    "bash",
				Command: "git status && rm -rf /",
			},
			expectMatch: true,
			expectDeny:  true,
		},
		{
			name: "compound command - first allowed, second denied",
			rule: PermissionRule{
				Tool:  "bash",
				Allow: []string{"git status"},
				Deny:  []string{"rm "},
			},
			request: PermissionRequest{
				Tool:    "bash",
				Command: "git status && rm file.txt",
			},
			expectMatch: true,
			expectDeny:  true,
		},
		{
			name: "edit - path within root directory - allowed",
			rule: PermissionRule{
				Tool:  "edit",
				Allow: []string{"**/*.go"},
			},
			request: PermissionRequest{
				Tool: "edit",
				Path: "/home/user/project/main.go",
			},
			rootDir:     "/home/user/project",
			expectMatch: true,
			expectDeny:  false,
		},
		{
			name: "edit - path outside root directory - blocked",
			rule: PermissionRule{
				Tool:  "edit",
				Allow: []string{"**/*.go"},
			},
			request: PermissionRequest{
				Tool: "edit",
				Path: "/etc/passwd",
			},
			rootDir:     "/home/user/project",
			expectMatch: false,
			expectDeny:  false,
		},
		{
			name: "edit - path traversal attempt - blocked",
			rule: PermissionRule{
				Tool:  "edit",
				Allow: []string{"**/*.txt"},
			},
			request: PermissionRequest{
				Tool: "edit",
				Path: "/home/user/project/../../etc/passwd",
			},
			rootDir:     "/home/user/project",
			expectMatch: false,
			expectDeny:  false,
		},
		{
			name: "allow_all - matches any command",
			rule: PermissionRule{
				Tool:     "mcp-some-tool",
				AllowAll: true,
			},
			request: PermissionRequest{
				Tool:    "mcp-some-tool",
				Command: "anything goes here",
			},
			expectMatch: true,
			expectDeny:  false,
		},
		{
			name: "allow_all - different tool does not match",
			rule: PermissionRule{
				Tool:     "mcp-some-tool",
				AllowAll: true,
			},
			request: PermissionRequest{
				Tool:    "other-tool",
				Command: "anything",
			},
			expectMatch: false,
			expectDeny:  false,
		},
		{
			name: "deny_all - matches and denies any command",
			rule: PermissionRule{
				Tool:    "dangerous-tool",
				DenyAll: true,
			},
			request: PermissionRequest{
				Tool:    "dangerous-tool",
				Command: "anything",
			},
			expectMatch: true,
			expectDeny:  true,
		},
		{
			name: "deny_all takes precedence over allow_all",
			rule: PermissionRule{
				Tool:     "conflicting-tool",
				AllowAll: true,
				DenyAll:  true,
			},
			request: PermissionRequest{
				Tool:    "conflicting-tool",
				Command: "anything",
			},
			expectMatch: true,
			expectDeny:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compiled, err := CompileRule(tt.rule, tt.rootDir)
			require.NoError(t, err)

			matched, isDeny := compiled.Match(tt.request)
			assert.Equal(t, tt.expectMatch, matched, "match result mismatch")
			assert.Equal(t, tt.expectDeny, isDeny, "deny result mismatch")
		})
	}
}

func TestEvaluateRules(t *testing.T) {
	tests := []struct {
		name          string
		rules         []PermissionRule
		request       PermissionRequest
		defaultEffect Effect
		expected      Effect
		expectMatch   bool
	}{
		{
			name: "allow match - first rule wins",
			rules: []PermissionRule{
				{
					Tool:  "bash",
					Allow: []string{"ls", "pwd"},
				},
				{
					Tool: "bash",
					Deny: []string{"rm "},
				},
			},
			request: PermissionRequest{
				Tool:    "bash",
				Command: "ls",
			},
			defaultEffect: Deny,
			expected:      Allow,
			expectMatch:   true,
		},
		{
			name: "deny match - takes precedence",
			rules: []PermissionRule{
				{
					Tool:  "bash",
					Allow: []string{"git status"},
				},
				{
					Tool: "bash",
					Deny: []string{"rm "},
				},
			},
			request: PermissionRequest{
				Tool:    "bash",
				Command: "rm file.txt",
			},
			defaultEffect: Allow,
			expected:      Deny,
			expectMatch:   true,
		},
		{
			name: "no match - use default effect",
			rules: []PermissionRule{
				{
					Tool:  "bash",
					Allow: []string{"ls", "pwd"},
				},
			},
			request: PermissionRequest{
				Tool:    "bash",
				Command: "curl evil.com",
			},
			defaultEffect: Ask,
			expected:      Ask,
			expectMatch:   false,
		},
		{
			name: "tool mismatch - no match",
			rules: []PermissionRule{
				{
					Tool:  "bash",
					Allow: []string{"ls"},
				},
			},
			request: PermissionRequest{
				Tool:    "edit",
				Command: "ls",
			},
			defaultEffect: Deny,
			expected:      Deny,
			expectMatch:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ruleSet := RuleSet{
				Rules:         tt.rules,
				DefaultEffect: tt.defaultEffect,
			}

			// Compile rules before evaluation
			err := ruleSet.Compile()
			require.NoError(t, err, "rule compilation should succeed")

			effect, matchedRule := EvaluateRules(&ruleSet, tt.request)
			assert.Equal(t, tt.expected, effect, "effect mismatch")

			if tt.expectMatch {
				assert.NotNil(t, matchedRule, "expected matched rule")
			} else {
				assert.Nil(t, matchedRule, "expected no matched rule")
			}
		})
	}
}

func TestRuleSet_Validate(t *testing.T) {
	tests := []struct {
		name    string
		ruleSet *RuleSet
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid rule set",
			ruleSet: &RuleSet{
				Rules: []PermissionRule{
					{
						Tool:  "bash",
						Allow: []string{"ls"},
					},
					{
						Tool: "edit",
						Deny: []string{"*.key"},
					},
				},
				DefaultEffect: Ask,
			},
			wantErr: false,
		},
		{
			name: "rule_set_with_empty_rule",
			ruleSet: &RuleSet{
				Rules: []PermissionRule{
					{
						Tool: "bash", // Empty rule - uses DefaultEffect
					},
				},
				DefaultEffect: Deny,
			},
			wantErr: false, // Empty rules are now valid (use DefaultEffect)
		},
		{
			name: "empty rule set with default effect",
			ruleSet: &RuleSet{
				Rules:         []PermissionRule{},
				DefaultEffect: Allow,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.ruleSet.Validate()
			if tt.wantErr {
				require.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestRuleSet_Compile(t *testing.T) {
	tests := []struct {
		name    string
		ruleSet *RuleSet
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid rule set",
			ruleSet: &RuleSet{
				Rules: []PermissionRule{
					{
						Tool:  "bash",
						Allow: []string{"ls", "pwd"},
					},
					{
						Tool:  "edit",
						Allow: []string{"**/*.go", "**/*.md"},
						Deny:  []string{"**/*.key", "**/.env"},
					},
				},
				DefaultEffect: Ask,
			},
			wantErr: false,
		},
		{
			name: "rule set with invalid regex pattern",
			ruleSet: &RuleSet{
				Rules: []PermissionRule{
					{
						Tool:  "grep",
						Allow: []string{"["}, // Invalid regex
						Regex: true,
					},
				},
				DefaultEffect: Deny,
			},
			wantErr: true,
			errMsg:  "invalid allow regex pattern",
		},
		{
			name: "rule_set_with_empty_rule",
			ruleSet: &RuleSet{
				Rules: []PermissionRule{
					{
						Tool: "bash", // Empty rule - uses DefaultEffect
					},
				},
				DefaultEffect: Allow,
			},
			wantErr: false, // Empty rules are now valid (use DefaultEffect)
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.ruleSet.Compile()
			if tt.wantErr {
				require.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
				// Verify compiled rules count matches input
				assert.Len(t, tt.ruleSet.compiledRules, len(tt.ruleSet.Rules))
			}
		})
	}
}

func TestEvaluateRules_WithCompiledCache(t *testing.T) {
	ruleSet := RuleSet{
		Rules: []PermissionRule{
			{
				Tool:  "bash",
				Allow: []string{"ls", "pwd"},
			},
			{
				Tool: "bash",
				Deny: []string{"rm "},
			},
		},
		DefaultEffect: Ask,
	}

	// Compile the rules
	err := ruleSet.Compile()
	require.NoError(t, err)

	// Evaluate multiple times - should use cached compiled rules
	req := PermissionRequest{
		Tool:    "bash",
		Command: "ls",
	}

	effect1, rule1 := EvaluateRules(&ruleSet, req)
	effect2, rule2 := EvaluateRules(&ruleSet, req)

	assert.Equal(t, Allow, effect1)
	assert.Equal(t, Allow, effect2)
	assert.NotNil(t, rule1)
	assert.NotNil(t, rule2)
	assert.Equal(t, rule1, rule2, "should return same compiled rule instance")
}

func TestValidateRegexPattern(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid simple pattern",
			pattern: "^ls$",
			wantErr: false,
		},
		{
			name:    "valid pattern with quantifiers",
			pattern: "(a+)b",
			wantErr: false,
		},
		{
			name:    "pattern too long",
			pattern: strings.Repeat("a", 201),
			wantErr: true,
			errMsg:  "exceeds maximum length of 200",
		},
		// Go's regexp package uses the RE2 engine which is immune to ReDoS
		// These patterns would be problematic in backtracking engines but are safe in Go
		{
			name:    "nested quantifiers - safe in Go's RE2 engine",
			pattern: "(a+)+b",
			wantErr: false,
		},
		{
			name:    "another nested quantifier pattern",
			pattern: "(a*)*c",
			wantErr: false,
		},
		{
			name:    "group with quantifier followed by quantifier",
			pattern: "(a+)*d",
			wantErr: false,
		},
		{
			name:    "multiple quantifiers (syntax checked by regexp.Compile)",
			pattern: "a**+",
			wantErr: false, // regexp.Compile will handle syntax validation
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRegexPattern(tt.pattern)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateGlobPattern(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid simple glob",
			pattern: "*.go",
			wantErr: false,
		},
		{
			name:    "valid glob with doublestar",
			pattern: "**/*.go",
			wantErr: false,
		},
		{
			name:    "pattern too long",
			pattern: strings.Repeat("*", 201),
			wantErr: true,
			errMsg:  "exceeds maximum length of 200",
		},
		{
			name:    "too many doublestar sequences",
			pattern: "**/**/**/**/file.go",
			wantErr: true,
			errMsg:  "too many ** sequences",
		},
		{
			name:    "too many wildcards",
			pattern: "*?[*?]*?[*?]*?[*?]*?[*?]*?[*?]*?[*?]*?[*?]*?[*?]*?[*?]*?[*?]*?[*?]*",
			wantErr: true,
			errMsg:  "too many wildcards",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateGlobPattern(tt.pattern)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
