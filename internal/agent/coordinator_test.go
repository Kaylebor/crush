package agent

import (
	"context"
	"testing"

	"github.com/charmbracelet/crush/internal/config"
	"github.com/charmbracelet/crush/internal/ruleengine"
	"github.com/stretchr/testify/require"
)

func TestShouldMakeToolAvailable(t *testing.T) {
	tests := []struct {
		name        string
		agent       config.Agent
		permissions *config.Permissions
		toolName    string
		want        bool
		description string
	}{
		{
			name: "rule_engine_allow_explicit",
			agent: config.Agent{
				ID:   "test-agent",
				Name: "Test Agent",
			},
			permissions: &config.Permissions{
				Rules: []ruleengine.PermissionRule{
					{
						Tool:  "bash",
						Allow: []string{"*"},
					},
				},
				DefaultEffect: ruleengine.Deny,
			},
			toolName:    "bash",
			want:        true,
			description: "Tool should be available when rule explicitly allows it",
		},
		{
			name: "rule_engine_deny_explicit",
			agent: config.Agent{
				ID:   "test-agent",
				Name: "Test Agent",
			},
			permissions: &config.Permissions{
				Rules: []ruleengine.PermissionRule{
					{
						Tool: "bash",
						Deny: []string{"*"},
					},
				},
				DefaultEffect: ruleengine.Allow,
			},
			toolName:    "bash",
			want:        false,
			description: "Tool should NOT be available when rule explicitly denies it",
		},
		{
			name: "rule_engine_default_allow",
			agent: config.Agent{
				ID:   "test-agent",
				Name: "Test Agent",
			},
			permissions: &config.Permissions{
				Rules:         []ruleengine.PermissionRule{},
				DefaultEffect: ruleengine.Allow,
			},
			toolName:    "bash",
			want:        true,
			description: "Tool should be available when no rules match and default is allow",
		},
		{
			name: "rule_engine_default_deny",
			agent: config.Agent{
				ID:   "test-agent",
				Name: "Test Agent",
			},
			permissions: &config.Permissions{
				Rules:         []ruleengine.PermissionRule{},
				DefaultEffect: ruleengine.Deny,
			},
			toolName:    "bash",
			want:        false,
			description: "Tool should NOT be available when no rules match and default is deny",
		},
		{
			name: "rule_engine_default_ask",
			agent: config.Agent{
				ID:   "test-agent",
				Name: "Test Agent",
			},
			permissions: &config.Permissions{
				Rules:         []ruleengine.PermissionRule{},
				DefaultEffect: ruleengine.Ask,
			},
			toolName:    "bash",
			want:        true,
			description: "Tool should be available when default is ask (tools are created, permissions checked at runtime)",
		},
		{
			name: "rule_engine_specific_command_allow",
			agent: config.Agent{
				ID:   "test-agent",
				Name: "Test Agent",
			},
			permissions: &config.Permissions{
				Rules: []ruleengine.PermissionRule{
					{
						Tool:  "bash",
						Allow: []string{"ls", "pwd"},
					},
				},
				DefaultEffect: ruleengine.Deny,
			},
			toolName:    "bash",
			want:        true,
			description: "Tool should be available when it has allow rules (even if specific commands are restricted)",
		},
		{
			name: "legacy_allowed_tools_fallback",
			agent: config.Agent{
				ID:           "test-agent",
				Name:         "Test Agent",
				AllowedTools: []string{"bash", "edit"},
			},
			permissions: &config.Permissions{
				Rules:         []ruleengine.PermissionRule{},
				DefaultEffect: ruleengine.Ask,
			},
			toolName:    "bash",
			want:        true,
			description: "Should fall back to legacy AllowedTools when no rules configured",
		},
		{
			name: "legacy_allowed_tools_not_allowed",
			agent: config.Agent{
				ID:           "test-agent",
				Name:         "Test Agent",
				AllowedTools: []string{"bash"},
			},
			permissions: &config.Permissions{
				Rules:         []ruleengine.PermissionRule{},
				DefaultEffect: ruleengine.Ask,
			},
			toolName:    "edit",
			want:        false,
			description: "Tool should NOT be available when not in legacy AllowedTools",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup coordinator with permissions
			coordinator := &coordinator{
				cfg: &config.Config{
					Permissions: tt.permissions,
				},
			}

			// Compile rules if present
			if coordinator.cfg.Permissions != nil {
				err := coordinator.cfg.Permissions.CompileRules()
				require.NoError(t, err, "Rule compilation should not fail")
			}

			// Test shouldMakeToolAvailable
			got := coordinator.shouldMakeToolAvailable(tt.agent, tt.toolName)
			require.Equal(t, tt.want, got, tt.description)
		})
	}
}

func TestBuildToolsWithRules(t *testing.T) {
	// Test that buildTools respects rules when creating tools
	permissions := &config.Permissions{
		Rules: []ruleengine.PermissionRule{
			{
				Tool:  "bash",
				Allow: []string{"*"},
			},
			{
				Tool: "edit",
				Deny: []string{"*"},
			},
		},
		DefaultEffect: ruleengine.Ask,
	}

	// Compile rules
	err := permissions.CompileRules()
	require.NoError(t, err)

	coordinator := &coordinator{
		cfg: &config.Config{
			Permissions: permissions,
			Options: &config.Options{
				Attribution: &config.Attribution{
					TrailerStyle:  config.TrailerStyleAssistedBy,
					GeneratedWith: true,
				},
			},
			Tools: config.Tools{
				Ls: config.ToolLs{},
			},
		},
	}

	agent := config.Agent{
		ID:   "test-agent",
		Name: "Test Agent",
	}

	// Build tools
	tools, err := coordinator.buildTools(context.Background(), agent)
	require.NoError(t, err)

	// Should have bash tool but not edit tool
	toolNames := make([]string, 0, len(tools))
	for _, tool := range tools {
		toolNames = append(toolNames, tool.Info().Name)
	}

	require.Contains(t, toolNames, "bash", "bash tool should be available")
	require.NotContains(t, toolNames, "edit", "edit tool should not be available when denied by rule")
}

func TestBuildToolsLegacyFallback(t *testing.T) {
	// Test that buildTools falls back to legacy AllowedTools when no rules
	coordinator := &coordinator{
		cfg: &config.Config{
			Permissions: &config.Permissions{
				Rules:         []ruleengine.PermissionRule{},
				DefaultEffect: ruleengine.Ask,
			},
			Options: &config.Options{
				Attribution: &config.Attribution{
					TrailerStyle:  config.TrailerStyleAssistedBy,
					GeneratedWith: true,
				},
			},
			Tools: config.Tools{
				Ls: config.ToolLs{},
			},
		},
	}

	agent := config.Agent{
		ID:           "test-agent",
		Name:         "Test Agent",
		AllowedTools: []string{"bash", "ls", "grep"},
	}

	// Build tools
	tools, err := coordinator.buildTools(context.Background(), agent)
	require.NoError(t, err)

	// Should only have tools in AllowedTools
	toolNames := make([]string, 0, len(tools))
	for _, tool := range tools {
		toolNames = append(toolNames, tool.Info().Name)
	}

	require.Contains(t, toolNames, "bash")
	require.Contains(t, toolNames, "ls")
	require.Contains(t, toolNames, "grep")

	// Should not have tools not in AllowedTools
	require.NotContains(t, toolNames, "edit")
	require.NotContains(t, toolNames, "write")
}

func TestBuildToolsDualModePriority(t *testing.T) {
	// Test that rule engine takes priority over legacy AllowedTools
	permissions := &config.Permissions{
		Rules: []ruleengine.PermissionRule{
			{
				Tool: "bash",
				Deny: []string{"*"},
			},
		},
		DefaultEffect: ruleengine.Allow,
	}

	err := permissions.CompileRules()
	require.NoError(t, err)

	coordinator := &coordinator{
		cfg: &config.Config{
			Permissions: permissions,
			Options: &config.Options{
				Attribution: &config.Attribution{
					TrailerStyle:  config.TrailerStyleAssistedBy,
					GeneratedWith: true,
				},
			},
			Tools: config.Tools{
				Ls: config.ToolLs{},
			},
		},
	}

	agent := config.Agent{
		ID:           "test-agent",
		Name:         "Test Agent",
		AllowedTools: []string{"bash"}, // Legacy allows bash
	}

	// Build tools
	tools, err := coordinator.buildTools(context.Background(), agent)
	require.NoError(t, err)

	// Rule engine denies bash, so it should not be available even though AllowedTools includes it
	toolNames := make([]string, 0, len(tools))
	for _, tool := range tools {
		toolNames = append(toolNames, tool.Info().Name)
	}

	require.NotContains(t, toolNames, "bash", "bash tool should not be available when denied by rule engine, even if in AllowedTools")
}
