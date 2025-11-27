package ruleengine

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestPathTraversalEdgeCases tests additional path traversal edge cases
func TestPathTraversalEdgeCases(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping symlink tests on Windows")
	}

	tempDir := t.TempDir()
	rootDir := filepath.Join(tempDir, "root")
	safeDir := filepath.Join(rootDir, "safe")

	// Create directory structure
	os.MkdirAll(safeDir, 0o755)
	os.WriteFile(filepath.Join(safeDir, "file.txt"), []byte("safe"), 0o644)

	// Create a symlink to outside the root
	outsideFile := filepath.Join(tempDir, "outside.txt")
	os.WriteFile(outsideFile, []byte("outside"), 0o644)
	symlinkPath := filepath.Join(safeDir, "symlink-to-outside")
	os.Symlink(outsideFile, symlinkPath)

	// Create symlink loop
	loop1 := filepath.Join(safeDir, "loop1")
	loop2 := filepath.Join(safeDir, "loop2")
	os.Symlink(loop2, loop1)
	os.Symlink(loop1, loop2)

	// Create complex path with multiple traversals
	complexTarget := filepath.Join(rootDir, "subdir")
	os.MkdirAll(complexTarget, 0o755)
	os.WriteFile(filepath.Join(complexTarget, "target.txt"), []byte("target"), 0o644)

	tests := []struct {
		name        string
		rule        PermissionRule
		requestPath string
		rootDir     string
		expectMatch bool
		expectDeny  bool
	}{
		{
			name: "symlink_to_outside_root_blocked",
			rule: PermissionRule{
				Tool:  "view",
				Allow: []string{"safe/**"},
			},
			requestPath: symlinkPath,
			rootDir:     rootDir,
			expectMatch: false, // Should not match because symlink points outside
			expectDeny:  false,
		},
		{
			name: "symlink_loop",
			rule: PermissionRule{
				Tool:  "view",
				Allow: []string{"safe/**"},
			},
			requestPath: loop1,
			rootDir:     rootDir,
			expectMatch: false, // Should not match because it's a loop
			expectDeny:  false,
		},
		{
			name: "complex_traversal_multiple_dots",
			rule: PermissionRule{
				Tool:  "edit",
				Allow: []string{"subdir/**"},
			},
			requestPath: filepath.Join(rootDir, "safe", "..", "subdir", "..", "..", "etc", "passwd"),
			rootDir:     rootDir,
			expectMatch: false, // Should not match, outside root
			expectDeny:  false,
		},
		{
			name: "absolute_path_inside_root",
			rule: PermissionRule{
				Tool:  "view",
				Allow: []string{"**/*.txt"}, // Allow any txt file within root
			},
			requestPath: filepath.Join(rootDir, "safe", "file.txt"),
			rootDir:     rootDir,
			expectMatch: true, // Should match, inside root
			expectDeny:  false,
		},
		{
			name: "double_slash_normalization",
			rule: PermissionRule{
				Tool:  "view",
				Allow: []string{"**/*.txt"}, // Allow any txt file
			},
			requestPath: filepath.Join(rootDir, "safe//file.txt"), // Double slash
			rootDir:     rootDir,
			expectMatch: true, // Should match after normalization
			expectDeny:  false,
		},
		{
			name: "dot_slash_normalization",
			rule: PermissionRule{
				Tool:  "view",
				Allow: []string{"**/*.txt"}, // Allow any txt file
			},
			requestPath: filepath.Join(rootDir, "safe", ".", "file.txt"), // ./ in path
			rootDir:     rootDir,
			expectMatch: true, // Should match after normalization
			expectDeny:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ruleSet := &RuleSet{
				Rules:         []PermissionRule{tt.rule},
				DefaultEffect: Ask,
				RootDirectory: tt.rootDir,
			}

			if err := ruleSet.Compile(); err != nil {
				t.Fatalf("Failed to compile rules: %v", err)
			}

			compiledRules := ruleSet.GetCompiledRules()
			if len(compiledRules) != 1 {
				t.Fatalf("Expected 1 compiled rule, got %d", len(compiledRules))
			}

			req := PermissionRequest{
				SessionID: "test-session",
				Tool:      tt.rule.Tool,
				Path:      tt.requestPath,
			}

			matched, isDeny := compiledRules[0].Match(req)

			if matched != tt.expectMatch {
				t.Errorf("Expected match=%v, got match=%v", tt.expectMatch, matched)
			}
			if matched && isDeny != tt.expectDeny {
				t.Errorf("Expected deny=%v, got deny=%v", tt.expectDeny, isDeny)
			}
		})
	}
}

// TestCompileRulePanic tests that rule compilation doesn't panic on edge cases
func TestCompileRulePanic(t *testing.T) {
	panicTestCases := []struct {
		name string
		rule PermissionRule
	}{
		{
			name: "nil_slices",
			rule: PermissionRule{
				Tool:  "bash",
				Allow: nil,
				Deny:  nil,
			},
		},
		{
			name: "empty_patterns",
			rule: PermissionRule{
				Tool:  "bash",
				Allow: []string{"", "   "}, // Empty and whitespace-only
				Deny:  []string{""},
			},
		},
		{
			name: "very_long_tool_name",
			rule: PermissionRule{
				Tool:  string(make([]byte, 10000)), // 10KB tool name
				Allow: []string{"test"},
			},
		},
		{
			name: "both_all_flags_set",
			rule: PermissionRule{
				Tool:     "bash",
				AllowAll: true,
				DenyAll:  true, // Both set - deny should take precedence
			},
		},
		{
			name: "regex_patterns_that_look_like_globs",
			rule: PermissionRule{
				Tool:  "bash",
				Allow: []string{".*", "(test|prod)"},
				Regex: true,
			},
		},
	}

	for _, tt := range panicTestCases {
		t.Run(tt.name, func(t *testing.T) {
			// Should not panic
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("CompileRule panicked on %s: %v", tt.name, r)
				}
			}()

			_, _ = CompileRule(tt.rule, "/tmp")
		})
	}
}
