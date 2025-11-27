package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSystemAgentDefinitions tests that system agent definitions are properly structured
func TestSystemAgentDefinitions(t *testing.T) {
	definitions := SystemAgentDefinitions()

	require.Len(t, definitions, 2, "Should have 2 default system agents")

	// Find coder and task agents
	var coderDef, taskDef *SystemAgentDefinition
	for i := range definitions {
		if definitions[i].ID == AgentCoder {
			coderDef = &definitions[i]
		}
		if definitions[i].ID == AgentTask {
			taskDef = &definitions[i]
		}
	}

	require.NotNil(t, coderDef, "Coder agent definition should exist")
	require.NotNil(t, taskDef, "Task agent definition should exist")

	// Verify coder has all tools
	assert.Equal(t, AgentCoderTools, coderDef.AllowedTools)
	assert.Nil(t, coderDef.AllowedMCP, "Coder should have no MCP restrictions")

	// Verify task has read-only tools
	assert.Equal(t, AgentTaskTools, taskDef.AllowedTools)
	assert.NotNil(t, taskDef.AllowedMCP, "Task should have MCP restrictions")
	assert.Empty(t, taskDef.AllowedMCP, "Task should have empty MCP list")
}

// TestBuildAgentFromDefinition tests agent construction from definitions
func TestBuildAgentFromDefinition(t *testing.T) {
	cfg := &Config{
		Options: &Options{
			ContextPaths:  []string{"/test/context"},
			DisabledTools: []string{"edit", "download"},
		},
	}

	def := SystemAgentDefinition{
		ID:           "test-agent",
		Name:         "Test Agent",
		Description:  "A test agent",
		ModelType:    SelectedModelTypeLarge,
		AllowedTools: []string{"view", "edit", "write", "download"},
		AllowedMCP:   map[string][]string{"test-mcp": {"tool1", "tool2"}},
	}

	agent := cfg.BuildAgentFromDefinition(def)

	// Verify basic fields
	assert.Equal(t, "test-agent", agent.ID)
	assert.Equal(t, "Test Agent", agent.Name)
	assert.Equal(t, "A test agent", agent.Description)
	assert.Equal(t, SelectedModelTypeLarge, agent.Model)
	assert.Equal(t, []string{"/test/context"}, agent.ContextPaths)

	// Verify disabled tools were filtered out
	assert.Equal(t, []string{"view", "write"}, agent.AllowedTools, "edit and download should be filtered")

	// Verify MCP settings preserved
	assert.Equal(t, map[string][]string{"test-mcp": {"tool1", "tool2"}}, agent.AllowedMCP)
}

// TestSetupAgentsUsesDefinitions verifies SetupAgents uses the definitions
func TestSetupAgentsUsesDefinitions(t *testing.T) {
	cfg := &Config{
		Options: &Options{
			DisabledTools: []string{"edit"},
		},
		Permissions: &Permissions{},
	}

	cfg.SetupAgents()

	require.Len(t, cfg.Agents, 2)

	coderAgent, exists := cfg.Agents[AgentCoder]
	require.True(t, exists)

	// Verify coder agent has all tools except disabled ones
	assert.NotContains(t, coderAgent.AllowedTools, "edit", "edit should be filtered from coder")
	assert.Contains(t, coderAgent.AllowedTools, "view", "view should be available")
	assert.Contains(t, coderAgent.AllowedTools, "bash", "bash should be available")
}

// TestAddingNewAgentType demonstrates how easy it is to add new agent types
func TestAddingNewAgentType(t *testing.T) {
	t.Run("CustomAnalyzerAgent", func(t *testing.T) {
		// This test shows how the new structure makes it easy to add agents
		// In the future, this could come from user config

		cfg := &Config{
			Options: &Options{
				DisabledTools: []string{},
			},
		}

		// Define a custom analyzer agent (e.g., for static analysis tasks)
		analyzerDef := SystemAgentDefinition{
			ID:          "analyzer",
			Name:        "Analyzer",
			Description: "An agent specialized for code analysis and quality checks",
			ModelType:   SelectedModelTypeSmall, // Might use smaller model for analysis
			AllowedTools: []string{
				"glob", "grep", "ls", "view", // Read-only exploration
				"lsp_diagnostics", "lsp_references", // LSP for deeper analysis
				"sourcegraph", // Code search
				"write",       // Can write analysis reports
			},
			AllowedMCP: map[string][]string{
				"sonarqube": nil, // All SonarQube tools
			},
		}

		agent := cfg.BuildAgentFromDefinition(analyzerDef)

		assert.Equal(t, "analyzer", agent.ID)
		assert.Equal(t, SelectedModelTypeSmall, agent.Model)
		assert.Contains(t, agent.AllowedTools, "lsp_diagnostics")
		assert.Contains(t, agent.AllowedMCP, "sonarqube")
	})
}
