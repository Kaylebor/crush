package ruleengine

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRuleSet_MatchesExplicitAllow tests explicit allow pattern detection for bash block list integration
func TestRuleSet_MatchesExplicitAllow(t *testing.T) {
	tests := []struct {
		name           string
		rules          []PermissionRule
		tool           string
		command        string
		expectExplicit bool
	}{
		{
			name: "explicit allow pattern matches",
			rules: []PermissionRule{
				{Tool: "bash", Allow: []string{"curl example.com"}},
			},
			tool:           "bash",
			command:        "curl example.com",
			expectExplicit: true,
		},
		{
			name: "explicit allow pattern does not match different command",
			rules: []PermissionRule{
				{Tool: "bash", Allow: []string{"curl example.com"}},
			},
			tool:           "bash",
			command:        "curl evil.com",
			expectExplicit: false,
		},
		{
			name: "allow_all does not count as explicit allow",
			rules: []PermissionRule{
				{Tool: "bash", AllowAll: true},
			},
			tool:           "bash",
			command:        "curl example.com",
			expectExplicit: false,
		},
		{
			name: "deny_all is ignored for explicit allow check",
			rules: []PermissionRule{
				{Tool: "bash", DenyAll: true},
			},
			tool:           "bash",
			command:        "curl example.com",
			expectExplicit: false,
		},
		{
			name: "glob pattern can be explicit allow",
			rules: []PermissionRule{
				{Tool: "bash", Allow: []string{"curl *"}},
			},
			tool:           "bash",
			command:        "curl example.com",
			expectExplicit: true,
		},
		{
			name: "rule for different tool does not match",
			rules: []PermissionRule{
				{Tool: "edit", Allow: []string{"*.go"}},
			},
			tool:           "bash",
			command:        "curl example.com",
			expectExplicit: false,
		},
		{
			name: "prefix pattern matches",
			rules: []PermissionRule{
				{Tool: "bash", Allow: []string{"git "}},
			},
			tool:           "bash",
			command:        "git status",
			expectExplicit: true,
		},
		{
			name: "prefix pattern without space matches blocked command",
			rules: []PermissionRule{
				{Tool: "bash", Allow: []string{"curl"}},
			},
			tool:           "bash",
			command:        "curl https://api.github.com",
			expectExplicit: true,
		},
		{
			name: "multiple rules with one matching",
			rules: []PermissionRule{
				{Tool: "bash", Deny: []string{"rm -rf *"}},
				{Tool: "bash", Allow: []string{"curl *", "wget *"}},
				{Tool: "bash", AllowAll: true},
			},
			tool:           "bash",
			command:        "curl example.com",
			expectExplicit: true,
		},
		{
			name: "rule with only deny patterns has no explicit allow",
			rules: []PermissionRule{
				{Tool: "bash", Deny: []string{"rm *"}},
			},
			tool:           "bash",
			command:        "curl example.com",
			expectExplicit: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create and compile rule set
			ruleSet := &RuleSet{
				Rules:         tt.rules,
				DefaultEffect: Ask,
			}
			err := ruleSet.Compile()
			require.NoError(t, err, "failed to compile rule set")

			// Check explicit allow
			result := ruleSet.MatchesExplicitAllow(tt.tool, tt.command)
			assert.Equal(t, tt.expectExplicit, result,
				"MatchesExplicitAllow(%q, %q) = %v, want %v",
				tt.tool, tt.command, result, tt.expectExplicit)
		})
	}
}

// TestEvaluateRules_BashIntegration tests rule evaluation behavior related to bash
func TestEvaluateRules_BashIntegration(t *testing.T) {
	tests := []struct {
		name          string
		rules         []PermissionRule
		request       PermissionRequest
		defaultEffect Effect
		expectAllowed bool
		expectDeny    bool
	}{
		{
			name: "explicit allow with deny takes precedence",
			rules: []PermissionRule{
				{Tool: "bash", Allow: []string{"curl *"}, Deny: []string{"curl evil.com"}},
			},
			request: PermissionRequest{
				Tool:    "bash",
				Command: "curl evil.com",
			},
			defaultEffect: Ask,
			expectAllowed: false,
			expectDeny:    true,
		},
		{
			name: "allow_all still allows commands",
			rules: []PermissionRule{
				{Tool: "bash", AllowAll: true},
			},
			request: PermissionRequest{
				Tool:    "bash",
				Command: "curl example.com",
			},
			defaultEffect: Ask,
			expectAllowed: true,
			expectDeny:    false,
		},
		{
			name: "no rule match uses default effect allow",
			rules: []PermissionRule{
				{Tool: "bash", Allow: []string{"git status"}},
			},
			request: PermissionRequest{
				Tool:    "bash",
				Command: "npm test",
			},
			defaultEffect: Allow,
			// No expectAllowed/expectDeny - we just check default effect
		},
		{
			name: "no rule match uses default effect deny",
			rules: []PermissionRule{
				{Tool: "bash", Allow: []string{"git status"}},
			},
			request: PermissionRequest{
				Tool:    "bash",
				Command: "npm test",
			},
			defaultEffect: Deny,
			// No expectAllowed/expectDeny - we just check default effect
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ruleSet := &RuleSet{
				Rules:         tt.rules,
				DefaultEffect: tt.defaultEffect,
			}
			err := ruleSet.Compile()
			require.NoError(t, err)

			effect, matchedRule := EvaluateRules(ruleSet, tt.request)

			if tt.expectDeny {
				assert.Equal(t, Deny, effect, "Expected Deny effect")
				assert.NotNil(t, matchedRule, "Expected a matched rule")
			} else if tt.expectAllowed {
				assert.Equal(t, Allow, effect, "Expected Allow effect")
				assert.NotNil(t, matchedRule, "Expected a matched rule")
			} else {
				assert.Equal(t, tt.defaultEffect, effect, "Expected default effect")
				assert.Nil(t, matchedRule, "Expected no matched rule")
			}
		})
	}
}
