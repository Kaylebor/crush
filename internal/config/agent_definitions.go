package config

import "slices"

// SystemAgentDefinition defines metadata for system agents
type SystemAgentDefinition struct {
	ID           string
	Name         string
	Description  string
	ModelType    SelectedModelType
	AllowedTools []string
	AllowedMCP   map[string][]string
}

// SystemAgentDefinitions returns the default system agent definitions.
// This is a function rather than a variable to allow for potential future dynamic configuration.
func SystemAgentDefinitions() []SystemAgentDefinition {
	return []SystemAgentDefinition{
		{
			ID:           AgentCoder,
			Name:         "Coder",
			Description:  "An agent that helps with executing coding tasks.",
			ModelType:    SelectedModelTypeLarge,
			AllowedTools: AgentCoderTools,
			AllowedMCP:   nil, // All MCPs available
		},
		{
			ID:           AgentTask,
			Name:         "Task",
			Description:  "An agent that helps with searching for context and finding implementation details.",
			ModelType:    SelectedModelTypeLarge,
			AllowedTools: AgentTaskTools,
			AllowedMCP:   map[string][]string{}, // No MCPs by default
		},
	}
}

// BuildAgentFromDefinition creates an Agent instance from a definition,
// applying disabled tool filtering.
func (c *Config) BuildAgentFromDefinition(def SystemAgentDefinition) Agent {
	// Filter tools based on disabled tools list
	filteredTools := make([]string, 0, len(def.AllowedTools))
	for _, tool := range def.AllowedTools {
		if !slices.Contains(c.Options.DisabledTools, tool) {
			filteredTools = append(filteredTools, tool)
		}
	}

	return Agent{
		ID:           def.ID,
		Name:         def.Name,
		Description:  def.Description,
		Model:        def.ModelType,
		ContextPaths: c.Options.ContextPaths,
		AllowedTools: filteredTools,
		AllowedMCP:   def.AllowedMCP,
	}
}
