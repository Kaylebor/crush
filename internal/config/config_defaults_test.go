package config

import (
	"testing"

	"github.com/charmbracelet/crush/internal/ruleengine"
	"github.com/stretchr/testify/assert"
)

// TestDefaultRulesCompleteness audits that DefaultRules includes all tools
// This test hardcodes the expected configuration to catch missing tools
func TestDefaultRulesCompleteness(t *testing.T) {
	tests := []struct {
		tool           string
		expectAllowAll bool // Should this tool have AllowAll: true?
		expectDenyAll  bool // Should this tool have DenyAll: true?
	}{
		// Read-only tools (should have AllowAll: true)
		{tool: "glob", expectAllowAll: true},
		{tool: "grep", expectAllowAll: true},
		{tool: "ls", expectAllowAll: true},
		{tool: "sourcegraph", expectAllowAll: true},
		{tool: "view", expectAllowAll: true},

		// Potentially unsafe tools (no AllowAll, uses DefaultEffect)
		{tool: "agent", expectAllowAll: false},
		{tool: "bash", expectAllowAll: false},
		{tool: "job_output", expectAllowAll: false},
		{tool: "job_kill", expectAllowAll: false},
		{tool: "download", expectAllowAll: false},
		{tool: "edit", expectAllowAll: false},
		{tool: "multiedit", expectAllowAll: false},
		{tool: "lsp_diagnostics", expectAllowAll: false},
		{tool: "lsp_references", expectAllowAll: false},
		{tool: "fetch", expectAllowAll: false},
		{tool: "agentic_fetch", expectAllowAll: false},
		{tool: "write", expectAllowAll: false},
	}

	for _, tt := range tests {
		t.Run(tt.tool, func(t *testing.T) {
			// Find the rule for this tool
			var foundRule *ruleengine.PermissionRule
			for i := range DefaultRules {
				if DefaultRules[i].Tool == tt.tool {
					foundRule = &DefaultRules[i]
					break
				}
			}

			// Every tool MUST have a rule
			assert.NotNil(t, foundRule, "Tool %s is missing from DefaultRules", tt.tool)

			// Verify AllowAll setting
			assert.Equal(t, tt.expectAllowAll, foundRule.AllowAll,
				"Tool %s: expected AllowAll=%v, got AllowAll=%v", tt.tool, tt.expectAllowAll, foundRule.AllowAll)

			// Verify no DenyAll in defaults
			assert.False(t, foundRule.DenyAll, "Tool %s should not have DenyAll=true in defaults", tt.tool)

			// Verify no unexpected Allow patterns (should be empty for unsafe tools)
			if !tt.expectAllowAll {
				assert.Empty(t, foundRule.Allow, "Tool %s should not have Allow patterns in defaults", tt.tool)
			}

			// Verify no Deny patterns in defaults (except for config/sensitive file protection)
			if tt.tool == "bash" || tt.tool == "edit" || tt.tool == "write" {
				// These tools have legitimate deny patterns for config file protection
				assert.NotEmpty(t, foundRule.Deny, "Tool %s should have Deny patterns for config file protection", tt.tool)
			} else {
				assert.Empty(t, foundRule.Deny, "Tool %s should not have Deny patterns in defaults", tt.tool)
			}

			// Verify no Regex flag in defaults
			assert.False(t, foundRule.Regex, "Tool %s should not have Regex=true in defaults", tt.tool)
		})
	}
}

// TestAgentCoderToolsCompleteness audits that AgentCoderTools has all tools
func TestAgentCoderToolsCompleteness(t *testing.T) {
	// Hardcode the expected tools for coder agent
	// This MUST match the actual AgentCoderTools constant
	expectedCoderTools := []string{
		"agent",
		"bash",
		"job_output",
		"job_kill",
		"download",
		"edit",
		"multiedit",
		"lsp_diagnostics",
		"lsp_references",
		"fetch",
		"agentic_fetch",
		"glob",
		"grep",
		"ls",
		"sourcegraph",
		"view",
		"write",
	}

	// Verify count matches
	assert.Equal(t, len(expectedCoderTools), len(AgentCoderTools),
		"AgentCoderTools count mismatch: expected %d tools, got %d", len(expectedCoderTools), len(AgentCoderTools))

	// Every expected tool must be present
	for _, expectedTool := range expectedCoderTools {
		assert.Contains(t, AgentCoderTools, expectedTool,
			"Tool %s is missing from AgentCoderTools", expectedTool)
	}

	// No extra tools should be present
	for _, actualTool := range AgentCoderTools {
		assert.Contains(t, expectedCoderTools, actualTool,
			"Tool %s is in AgentCoderTools but not expected", actualTool)
	}
}

// TestAgentTaskToolsCompleteness audits that AgentTaskTools has correct read-only tools
func TestAgentTaskToolsCompleteness(t *testing.T) {
	// Hardcode the expected tools for task agent
	// This MUST match the actual AgentTaskTools constant
	expectedTaskTools := []string{
		"glob",
		"grep",
		"ls",
		"sourcegraph",
		"view",
	}

	// Verify count matches
	assert.Equal(t, len(expectedTaskTools), len(AgentTaskTools),
		"AgentTaskTools count mismatch: expected %d tools, got %d", len(expectedTaskTools), len(AgentTaskTools))

	// Every expected tool must be present
	for _, expectedTool := range expectedTaskTools {
		assert.Contains(t, AgentTaskTools, expectedTool,
			"Tool %s is missing from AgentTaskTools", expectedTool)
	}

	// No extra tools should be present
	for _, actualTool := range AgentTaskTools {
		assert.Contains(t, expectedTaskTools, actualTool,
			"Tool %s is in AgentTaskTools but not expected", actualTool)
	}

	// Verify all tools in AgentTaskTools are read-only (in DefaultRules)
	for _, tool := range AgentTaskTools {
		var foundRule *ruleengine.PermissionRule
		for i := range DefaultRules {
			if DefaultRules[i].Tool == tool {
				foundRule = &DefaultRules[i]
				break
			}
		}

		assert.NotNil(t, foundRule, "Tool %s in AgentTaskTools must be in DefaultRules", tool)
		assert.True(t, foundRule.AllowAll, "Tool %s in AgentTaskTools must have AllowAll=true (be read-only)", tool)
	}
}

// TestSystemAgentDefinitionsCompleteness audits system agent definitions
func TestSystemAgentDefinitionsCompleteness(t *testing.T) {
	definitions := SystemAgentDefinitions()

	// Must have both coder and task agents
	assert.Len(t, definitions, 2, "SystemAgentDefinitions must return exactly 2 agents")

	var coderDef, taskDef *SystemAgentDefinition
	for i := range definitions {
		if definitions[i].ID == AgentCoder {
			coderDef = &definitions[i]
		}
		if definitions[i].ID == AgentTask {
			taskDef = &definitions[i]
		}
	}

	assert.NotNil(t, coderDef, "Coder agent definition must exist")
	assert.NotNil(t, taskDef, "Task agent definition must exist")

	// Verify coder agent has all tools
	assert.Equal(t, AgentCoderTools, coderDef.AllowedTools,
		"Coder agent AllowedTools must match AgentCoderTools constant")

	// Verify task agent has read-only tools
	assert.Equal(t, AgentTaskTools, taskDef.AllowedTools,
		"Task agent AllowedTools must match AgentTaskTools constant")

	// Verify MCP restrictions
	assert.Nil(t, coderDef.AllowedMCP, "Coder agent should have no MCP restrictions")
	assert.NotNil(t, taskDef.AllowedMCP, "Task agent should have MCP restrictions")
	assert.Empty(t, taskDef.AllowedMCP, "Task agent should have empty MCP list")
}

// TestDefaultRulesAreValid ensures all default rules are structurally valid
func TestDefaultRulesAreValid(t *testing.T) {
	for _, rule := range DefaultRules {
		t.Run(rule.Tool, func(t *testing.T) {
			// Each rule must validate
			err := rule.Validate()
			assert.NoError(t, err, "Default rule for %s must be valid", rule.Tool)

			// Each rule must compile
			compiledRule, err := ruleengine.CompileRule(rule, "")
			assert.NoError(t, err, "Default rule for %s must compile", rule.Tool)
			assert.NotNil(t, compiledRule, "Compiled rule for %s must not be nil", rule.Tool)
		})
	}
}
