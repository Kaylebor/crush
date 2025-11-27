package ruleengine

import (
	"fmt"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/charmbracelet/crush/internal/shell"
)

// Effect represents the outcome of a permission rule
type Effect string

const (
	// Allow permits the action
	Allow Effect = "allow"
	// Deny blocks the action
	Deny Effect = "deny"
	// Ask prompts the user for permission
	Ask Effect = "ask"
)

// PermissionRule defines a single permission rule for a specific tool
type PermissionRule struct {
	// Tool is the name of the tool (e.g., "bash", "edit", "download")
	Tool string `json:"tool"`
	// AllowAll indicates this tool is completely allowed (no pattern matching needed)
	// Useful for dynamic/MCP tools where patterns can't be predefined
	AllowAll bool `json:"allow_all,omitempty"`
	// DenyAll indicates this tool is completely denied (no pattern matching needed)
	// Takes precedence over AllowAll if both are set
	DenyAll bool `json:"deny_all,omitempty"`
	// Allow is a list of patterns that explicitly allow actions
	Allow []string `json:"allow,omitempty"`
	// Deny is a list of patterns that explicitly deny actions
	Deny []string `json:"deny,omitempty"`
	// Regex indicates whether to use regex matching instead of prefix/glob
	Regex bool `json:"regex,omitempty"`
	// Message is a custom message to show when denying (optional)
	Message string `json:"message,omitempty"`
}

// Validate checks if the rule is valid
func (r PermissionRule) Validate() error {
	if r.Tool == "" {
		return fmt.Errorf("tool name is required")
	}
	// A rule is valid if it has a tool name
	// AllowAll, DenyAll, Allow patterns, and Deny patterns are optional
	// An empty rule (no patterns, no all flags) is valid and uses DefaultEffect
	return nil
}

// PermissionRequest contains the details of a permission check
type PermissionRequest struct {
	// SessionID is the session identifier
	SessionID string
	// Tool is the tool name (e.g., "bash", "edit")
	Tool string
	// Action is the tool action
	Action string
	// Path is the file path for file operations
	Path string
	// Command is the command string for bash
	Command string
	// URL is the URL for fetch/download tools
	URL string
	// Pattern is the pattern for grep/glob tools
	Pattern string
}

// RuleSet is a collection of rules with a default effect
type RuleSet struct {
	mu sync.RWMutex
	// Rules is the list of permission rules
	Rules []PermissionRule `json:"rules"`
	// DefaultEffect is the effect when no rule matches
	DefaultEffect Effect `json:"default_effect"`
	// RootDirectory is the base directory for path-based rules (empty means no restriction)
	RootDirectory string `json:"root_directory,omitempty"`
	// compiledRules is the cached compiled version of Rules
	compiledRules []*CompiledRule
	// compiledFlag indicates whether rules have been successfully compiled
	compiledFlag bool
}

// CompiledRule is an internal representation of a compiled permission rule
type CompiledRule struct {
	rule          PermissionRule
	allowREs      []*regexp.Regexp
	denyREs       []*regexp.Regexp
	allowGlobs    []string
	denyGlobs     []string
	allowPrefixes []string
	denyPrefixes  []string
	isRegex       bool
	rootDirectory string // Base directory for path-based rules (from RuleSet)
}

// Rule returns the original PermissionRule for this compiled rule.
func (c *CompiledRule) Rule() PermissionRule {
	return c.rule
}

// validateRegexPattern checks if a regex pattern is valid and safe.
// Go's regexp package uses the RE2 engine which is immune to ReDoS attacks
// by design (linear time complexity, no catastrophic backtracking).
// We only check for reasonable length limits to prevent resource exhaustion.
func validateRegexPattern(pattern string) error {
	// Check pattern length limit (max 200 characters)
	if len(pattern) > 200 {
		return fmt.Errorf("regex pattern exceeds maximum length of 200 characters (got %d)", len(pattern))
	}
	return nil
}

// validateGlobPattern checks if a glob pattern is safe from resource exhaustion attacks
func validateGlobPattern(pattern string) error {
	// Check pattern length limit (max 200 characters)
	if len(pattern) > 200 {
		return fmt.Errorf("glob pattern exceeds maximum length of 200 characters (got %d)", len(pattern))
	}

	// Count ** occurrences
	doubleStarCount := 0
	for i := 0; i < len(pattern)-1; i++ {
		if pattern[i] == '*' && pattern[i+1] == '*' {
			doubleStarCount++
			i++ // Skip next character to avoid overlapping matches
		}
	}
	if doubleStarCount > 3 {
		return fmt.Errorf("glob pattern contains too many ** sequences (max 3, got %d)", doubleStarCount)
	}

	// Count total wildcards to detect overly complex patterns
	wildcardCount := 0
	for _, char := range pattern {
		switch char {
		case '*', '?', '[', ']':
			wildcardCount++
		}
	}
	if wildcardCount > 20 {
		return fmt.Errorf("glob pattern contains too many wildcards (max 20, got %d)", wildcardCount)
	}

	return nil
}

// CompileRule compiles a PermissionRule into a CompiledRule for efficient matching
func CompileRule(rule PermissionRule, rootDirectory string) (*CompiledRule, error) {
	if err := rule.Validate(); err != nil {
		return nil, err
	}

	compiled := &CompiledRule{
		rule:          rule,
		allowREs:      make([]*regexp.Regexp, 0, len(rule.Allow)),
		denyREs:       make([]*regexp.Regexp, 0, len(rule.Deny)),
		allowGlobs:    make([]string, 0, len(rule.Allow)),
		denyGlobs:     make([]string, 0, len(rule.Deny)),
		allowPrefixes: make([]string, 0, len(rule.Allow)),
		denyPrefixes:  make([]string, 0, len(rule.Deny)),
		isRegex:       rule.Regex,
		rootDirectory: rootDirectory,
	}

	if rule.Regex {
		// Compile regex patterns with ReDoS validation
		for _, pattern := range rule.Allow {
			// Validate pattern before compiling
			if err := validateRegexPattern(pattern); err != nil {
				return nil, fmt.Errorf("invalid allow regex pattern %q: %w", pattern, err)
			}
			re, err := regexp.Compile(pattern)
			if err != nil {
				return nil, fmt.Errorf("invalid allow regex pattern %q: %w", pattern, err)
			}
			compiled.allowREs = append(compiled.allowREs, re)
		}
		for _, pattern := range rule.Deny {
			// Validate pattern before compiling
			if err := validateRegexPattern(pattern); err != nil {
				return nil, fmt.Errorf("invalid deny regex pattern %q: %w", pattern, err)
			}
			re, err := regexp.Compile(pattern)
			if err != nil {
				return nil, fmt.Errorf("invalid deny regex pattern %q: %w", pattern, err)
			}
			compiled.denyREs = append(compiled.denyREs, re)
		}
	} else {
		// Separate glob patterns from prefix patterns
		// ** is treated as glob, not prefix
		for _, pattern := range rule.Allow {
			if strings.Contains(pattern, "*") || strings.Contains(pattern, "?") || strings.Contains(pattern, "[") {
				// Validate glob pattern before using it
				if err := validateGlobPattern(pattern); err != nil {
					return nil, fmt.Errorf("invalid allow glob pattern %q: %w", pattern, err)
				}
				compiled.allowGlobs = append(compiled.allowGlobs, pattern)
			} else {
				compiled.allowPrefixes = append(compiled.allowPrefixes, pattern)
			}
		}
		for _, pattern := range rule.Deny {
			if strings.Contains(pattern, "*") || strings.Contains(pattern, "?") || strings.Contains(pattern, "[") {
				// Validate glob pattern before using it
				if err := validateGlobPattern(pattern); err != nil {
					return nil, fmt.Errorf("invalid deny glob pattern %q: %w", pattern, err)
				}
				compiled.denyGlobs = append(compiled.denyGlobs, pattern)
			} else {
				compiled.denyPrefixes = append(compiled.denyPrefixes, pattern)
			}
		}
	}

	return compiled, nil
}

// matchPatterns checks if a value matches any pattern in the provided sets
// Returns (matched, isDeny) where isDeny indicates if this was a deny match
func matchPatterns(value string, isDeny bool, regexes []*regexp.Regexp, prefixes []string, globs []string, isRegexMode bool) (bool, bool) {
	if isRegexMode {
		for _, re := range regexes {
			if re.MatchString(value) {
				return true, isDeny
			}
		}
		return false, false
	}

	// Check prefix matches - ensure we're matching at word boundaries
	for _, prefix := range prefixes {
		if strings.HasPrefix(value, prefix) {
			// If the prefix ends with a space, it's already a complete match
			// (the space is the boundary marker)
			if len(prefix) > 0 && prefix[len(prefix)-1] == ' ' {
				return true, isDeny
			}

			// For non-space-ending prefixes, check we're at a boundary
			rest := value[len(prefix):]
			if len(rest) == 0 {
				// Exact match
				return true, isDeny
			}

			// Check if we're at a word boundary (space, tab, dash, semicolon, ampersand, pipe,
			// parentheses, dollar sign, newline, or carriage return)
			// This prevents "ls" from matching "lsdangerous" or "rm" from matching "rmfile.txt"
			if rest[0] == ' ' || rest[0] == '\t' || rest[0] == '-' || rest[0] == ';' || rest[0] == '&' || rest[0] == '|' || rest[0] == '(' || rest[0] == ')' || rest[0] == '$' || rest[0] == '\n' || rest[0] == '\r' {
				return true, isDeny
			}
		}
	}

	// Check glob matches using only doublestar for consistency
	for _, glob := range globs {
		if matched, err := doublestar.Match(glob, value); err == nil && matched {
			return true, isDeny
		}
	}

	return false, false
}

// matchAgainstAllow checks if the value matches any allow pattern
func (c *CompiledRule) matchAgainstAllow(value string) (bool, bool) {
	return matchPatterns(value, false, c.allowREs, c.allowPrefixes, c.allowGlobs, c.isRegex)
}

// matchAgainstDeny checks if the value matches any deny pattern
func (c *CompiledRule) matchAgainstDeny(value string) (bool, bool) {
	return matchPatterns(value, true, c.denyREs, c.denyPrefixes, c.denyGlobs, c.isRegex)
}

// Match checks if the rule matches the permission request
// Returns (matched, isDeny)
func (c *CompiledRule) Match(req PermissionRequest) (bool, bool) {
	// Tool must match
	if c.rule.Tool != req.Tool {
		return false, false
	}

	// If this rule denies all operations for this tool, match immediately (deny precedence)
	if c.rule.DenyAll {
		return true, true // matched, is a deny rule
	}

	// If this rule allows all operations for this tool, match immediately
	if c.rule.AllowAll {
		return true, false // matched, not a deny rule
	}

	// Extract the value to match based on tool type
	var value string
	switch req.Tool {
	case "bash":
		value = req.Command
	case "edit", "write", "view":
		if req.Path == "" {
			return false, false
		}

		// Validate against root directory if specified
		if c.rootDirectory != "" {
			// Get absolute paths for both root and target
			absRoot, err := filepath.Abs(filepath.Clean(c.rootDirectory))
			if err != nil {
				return false, false // Invalid root directory
			}

			absPath, err := filepath.Abs(req.Path)
			if err != nil {
				return false, false // Invalid path
			}

			// Check if path is contained within root directory
			rel, err := filepath.Rel(absRoot, absPath)
			if err != nil || strings.HasPrefix(rel, "..") {
				return false, false // Path outside allowed root
			}
		}

		// Resolve symbolic links and normalize path to prevent traversal attacks
		// If EvalSymlinks fails (e.g., path doesn't exist), fall back to Clean()
		cleanPath, err := filepath.EvalSymlinks(req.Path)
		if err != nil {
			// Path might not exist yet (e.g., in write operations) or no permissions
			// Fall back to just cleaning the path
			value = filepath.Clean(req.Path)
		} else {
			value = filepath.Clean(cleanPath)
		}
	case "download":
		if req.URL == "" {
			return false, false
		}
		// Normalize URL to prevent spoofing attacks
		u, err := url.Parse(req.URL)
		if err != nil {
			return false, false // Invalid URL shouldn't match
		}
		// Normalize scheme and host to lowercase
		u.Scheme = strings.ToLower(u.Scheme)
		u.Host = strings.ToLower(u.Host)
		value = u.String()
	case "grep", "glob":
		value = req.Pattern
	default:
		// For unknown tools, use command if available
		if req.Command != "" {
			value = req.Command
		} else {
			// No matchable value
			return false, false
		}
	}

	if value == "" {
		return false, false
	}

	// For compound bash commands, check each sub-command separately
	// and return the most restrictive result
	if req.Tool == "bash" && shell.ContainsCompoundOperator(value) {
		return c.matchCompoundCommand(value)
	}

	return c.matchSingleValue(value)
}

// matchSingleValue matches a single value against the rule patterns
func (c *CompiledRule) matchSingleValue(value string) (bool, bool) {
	// Check deny patterns first (deny takes precedence)
	matched, _ := c.matchAgainstDeny(value)
	if matched {
		return true, true
	}

	// Check allow patterns
	matched, _ = c.matchAgainstAllow(value)
	if matched {
		return true, false
	}

	return false, false
}

// matchCompoundCommand handles compound commands by splitting and checking each part
func (c *CompiledRule) matchCompoundCommand(command string) (bool, bool) {
	// Split on all compound operators simultaneously using shell parser
	parts := shell.ParseCommands(command)

	if len(parts) <= 1 {
		// No split occurred or single empty command
		return c.matchSingleValue(command)
	}

	// Check each part and find the most restrictive result
	// Deny takes precedence over allow
	var hasAllow bool

	for _, part := range parts {
		if part == "" {
			continue
		}

		matched, isDeny := c.matchSingleValue(part)
		if matched && isDeny {
			return true, true // Deny found, return immediately
		}
		if matched && !isDeny {
			hasAllow = true
		}
	}

	// If we found allow matches but no denies, return allow
	if hasAllow {
		return true, false
	}

	// No matches
	return false, false
}

// EvaluateRules evaluates a set of rules against a permission request
// Returns the effect and the matching rule (if any)
func EvaluateRules(ruleSet *RuleSet, req PermissionRequest) (Effect, *CompiledRule) {
	// Use helper to get rules to check
	ruleSet.mu.RLock()
	rulesToCheck := ruleSet.compiledRules
	ruleSet.mu.RUnlock()

	// Check each rule
	for _, compiled := range rulesToCheck {
		matched, isDeny := compiled.Match(req)
		if matched {
			if isDeny {
				return Deny, compiled
			}
			return Allow, compiled
		}
	}

	// No rule matched, return default effect
	return ruleSet.DefaultEffect, nil
}

// Compile compiles all rules in the RuleSet and caches them
func (rs *RuleSet) Compile() error {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	// Reset compiled flag
	rs.compiledFlag = false

	rs.compiledRules = make([]*CompiledRule, 0, len(rs.Rules))
	for i, rule := range rs.Rules {
		compiled, err := CompileRule(rule, rs.RootDirectory)
		if err != nil {
			return fmt.Errorf("rule %d: %w", i, err)
		}
		rs.compiledRules = append(rs.compiledRules, compiled)
	}

	rs.compiledFlag = true
	return nil
}

// IsCompiled returns whether the rule set has been successfully compiled.
func (rs *RuleSet) IsCompiled() bool {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	return rs.compiledFlag
}

// Validate checks if the rule set is valid
func (rs *RuleSet) Validate() error {
	for i, rule := range rs.Rules {
		if err := rule.Validate(); err != nil {
			return fmt.Errorf("rule %d: %w", i, err)
		}
	}
	switch rs.DefaultEffect {
	case Allow, Deny, Ask:
		// Valid
	default:
		return fmt.Errorf("invalid default effect: %s", rs.DefaultEffect)
	}
	return nil
}

// HasToolRule checks if the rule set has any rules for the specified tool.
func (rs *RuleSet) HasToolRule(toolName string) bool {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	if !rs.compiledFlag {
		return false
	}

	for _, compiledRule := range rs.compiledRules {
		if compiledRule.rule.Tool == toolName {
			return true
		}
	}
	return false
}

// GetCompiledRules returns a copy of the compiled rules for iteration.
// Returns nil if the rules haven't been compiled yet.
func (rs *RuleSet) GetCompiledRules() []*CompiledRule {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	if !rs.compiledFlag {
		return nil
	}

	// Return a copy to prevent external modification
	rules := make([]*CompiledRule, len(rs.compiledRules))
	copy(rules, rs.compiledRules)
	return rules
}

// MatchesExplicitAllow checks if a tool and command matches any explicit allow pattern
// This is used to determine if hardcoded security blocks should be bypassed
func (rs *RuleSet) MatchesExplicitAllow(tool, command string) bool {
	// Lock for reading
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	if !rs.compiledFlag {
		return false
	}

	// Create a permission request for matching
	req := PermissionRequest{
		Tool:    tool,
		Command: command,
	}

	// Check each compiled rule for the tool
	for _, compiled := range rs.compiledRules {
		if compiled.rule.Tool != tool {
			continue
		}

		// Skip deny_all and allow_all rules - only check explicit patterns
		if compiled.rule.DenyAll || compiled.rule.AllowAll {
			continue
		}

		// Only rules with allow patterns can explicitly allow
		if len(compiled.rule.Allow) == 0 {
			continue
		}

		// Check if command matches this rule's allow patterns
		matched, isDeny := compiled.Match(req)
		if matched && !isDeny {
			return true
		}
	}

	return false
}
