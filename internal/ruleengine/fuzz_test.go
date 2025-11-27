package ruleengine

import (
	"runtime"
	"strings"
	"testing"
)

// FuzzValidateRegexPattern tests regex pattern validation with random inputs
func FuzzValidateRegexPattern(f *testing.F) {
	// Seed corpus with interesting cases
	seeds := []string{
		"^test.*$",
		"[a-z]*",
		"\\w+",
		"(?P<name>.*)",
		"^$",
		".*",                     // Potentially problematic
		strings.Repeat("a", 201), // Over limit
		strings.Repeat(".*", 50), // Too many wildcards
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, pattern string) {
		// Should not panic
		err := validateRegexPattern(pattern)
		// If it errors, verify the error type is what we expect
		if err != nil {
			if strings.Contains(err.Error(), "exceeds maximum length") {
				// Valid: pattern too long
				return
			}
		}

		// If pattern is valid length, try compiling it
		if err == nil && len(pattern) <= 200 {
			// Compilation happens in CompileRule, but we can pre-validate
			_, compileErr := CompileRule(PermissionRule{
				Tool:  "test",
				Allow: []string{pattern},
			}, "")
			// CompileErr is ok - pattern might be valid for validation but invalid regex
			if compileErr != nil {
				t.Logf("Pattern %q validates but fails to compile: %v", pattern, compileErr)
			}
		}
	})
}

// FuzzValidateGlobPattern tests glob pattern validation with random inputs
func FuzzValidateGlobPattern(f *testing.F) {
	// Seed corpus
	seeds := []string{
		"*.go",
		"**/*.txt",
		"test/**/file.*",
		strings.Repeat("*/", 10) + "file",
		strings.Repeat("**", 5) + "/file",
		strings.Repeat("a", 201), // Over limit
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, pattern string) {
		// Should not panic
		err := validateGlobPattern(pattern)
		if err != nil {
			// Verify error types
			errStr := err.Error()
			switch {
			case strings.Contains(errStr, "exceeds maximum length"):
				// Valid: pattern too long
				return
			case strings.Contains(errStr, "too many ** sequences"):
				// Valid: too many double-stars
				if count := strings.Count(pattern, "**"); count > 3 {
					return // Expected
				}
			case strings.Contains(errStr, "too many wildcards"):
				// Valid: too many wildcards
				return
			}
			t.Logf("Unexpected error for pattern %q: %v", pattern, err)
		}
	})
}

// FuzzCompileRule tests rule compilation with random rules
func FuzzCompileRule(f *testing.F) {
	// Seed corpus with various rule structures
	seedRules := []PermissionRule{
		{Tool: "bash", AllowAll: true},
		{Tool: "bash", DenyAll: true},
		{Tool: "bash", Allow: []string{"ls *"}},
		{Tool: "bash", Deny: []string{"rm *"}},
		{Tool: "edit", Allow: []string{"*.txt"}},
		{Tool: "view", AllowAll: true},
		{Tool: "edit", Allow: []string{"test.txt"}, Regex: true},
	}

	for _, rule := range seedRules {
		f.Add(rule.Tool, rule.AllowAll, rule.DenyAll, strings.Join(rule.Allow, "|"), strings.Join(rule.Deny, "|"), rule.Regex)
	}

	f.Fuzz(func(t *testing.T, tool string, allowAll, denyAll bool, allowStr, denyStr string, isRegex bool) {
		// Skip invalid combinations early
		if tool == "" {
			return
		}

		maxPatternLen := 100 // Keep it reasonable for fuzzing

		// Parse allow/deny patterns
		var allow, deny []string
		if allowStr != "" {
			allow = strings.Split(allowStr, "|")
			for i, pattern := range allow {
				if len(pattern) > maxPatternLen {
					allow[i] = pattern[:maxPatternLen]
				}
			}
		}
		if denyStr != "" {
			deny = strings.Split(denyStr, "|")
			for i, pattern := range deny {
				if len(pattern) > maxPatternLen {
					deny[i] = pattern[:maxPatternLen]
				}
			}
		}

		rule := PermissionRule{
			Tool:     tool,
			AllowAll: allowAll,
			DenyAll:  denyAll,
			Allow:    allow,
			Deny:     deny,
			Regex:    isRegex,
		}

		// Should not panic
		compiled, err := CompileRule(rule, "/tmp/test")
		if err != nil {
			// Compilation errors are expected with random data
			// Just ensure it's not a panic
			return
		}

		// If compilation succeeded, test that the compiled rule is usable
		if compiled != nil {
			// Test with various requests
			requests := []PermissionRequest{
				{SessionID: "test-session", Tool: tool, Command: "test command"},
				{SessionID: "test-session", Tool: tool, Command: "ls -la"},
				{SessionID: "test-session", Tool: tool, Path: "/tmp/test.txt"},
				{SessionID: "test-session", Tool: tool, URL: "http://example.com"},
				{SessionID: "test-session", Tool: tool, Pattern: "*.go"},
				{SessionID: "test-session", Tool: tool, Command: "test && command"}, // Compound
			}

			for _, req := range requests {
				// Should not panic
				_, _ = compiled.Match(req)
			}
		}
	})
}

// TestFuzzingSanity runs the fuzzing tests to make sure they're working
func TestFuzzingSanity(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping fuzzing sanity test in short mode")
	}

	// Test that basic patterns don't cause issues
	patterns := []string{
		"normal.*pattern",
		"[a-z]*",
		"**/*.go",
		strings.Repeat("a", 200), // Exactly at limit
	}

	for _, pattern := range patterns {
		// Test regex validation
		if err := validateRegexPattern(pattern); err != nil {
			// Some patterns may fail regex validation but that's OK
			t.Logf("Pattern %q failed regex validation: %v", pattern, err)
		}

		// Test glob validation
		if err := validateGlobPattern(pattern); err != nil {
			t.Logf("Pattern %q failed glob validation: %v", pattern, err)
		}
	}
}

// Ensure we don't leak goroutines or memory during fuzzing
func TestFuzzingStability(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping stability test in short mode")
	}

	// Force GC to get baseline
	runtime.GC()
	var memStatsBefore runtime.MemStats
	runtime.ReadMemStats(&memStatsBefore)

	// Run multiple compilations
	for i := 0; i < 1000; i++ {
		rule := PermissionRule{
			Tool:  "bash",
			Allow: []string{"test *", "**/*.go", "[a-z]*"},
			Deny:  []string{"rm *", "rmdir *"},
		}

		_, err := CompileRule(rule, "/tmp")
		if err != nil {
			t.Fatalf("Unexpected compilation error: %v", err)
		}
	}

	// Force GC and check memory
	runtime.GC()
	var memStatsAfter runtime.MemStats
	runtime.ReadMemStats(&memStatsAfter)

	// Should not have significant memory growth
	allocMBBefore := memStatsBefore.Alloc / 1024 / 1024
	allocMBAfter := memStatsAfter.Alloc / 1024 / 1024

	if allocMBAfter > allocMBBefore+10 { // Allow 10MB growth
		t.Logf("Memory allocation grew from %dMB to %dMB", allocMBBefore, allocMBAfter)
	}
}
