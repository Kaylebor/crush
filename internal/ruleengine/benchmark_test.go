package ruleengine

import (
	"fmt"
	"testing"
)

// BenchmarkRuleCompilation benchmarks rule compilation performance
func BenchmarkRuleCompilation(b *testing.B) {
	// Simple rule
	simpleRule := PermissionRule{
		Tool:  "bash",
		Allow: []string{"ls *", "pwd", "whoami"},
		Deny:  []string{"rm *", "rmdir *"},
	}

	// Complex rule with many patterns
	var manyPatterns []string
	for i := 0; i < 100; i++ {
		manyPatterns = append(manyPatterns, fmt.Sprintf("pattern%d*", i))
	}

	complexRule := PermissionRule{
		Tool:  "bash",
		Allow: manyPatterns,
		Deny:  manyPatterns,
	}

	// Regex rule
	regexRule := PermissionRule{
		Tool:  "bash",
		Allow: []string{"^ls(-l)?$", "^pwd$", "^echo .*$"},
		Deny:  []string{"^rm .*$", "^rmdir .*$"},
		Regex: true,
	}

	b.Run("SimpleRule", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, err := CompileRule(simpleRule, "")
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("ComplexRule", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, err := CompileRule(complexRule, "")
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("RegexRule", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, err := CompileRule(regexRule, "")
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkRuleEvaluation benchmarks rule matching performance
func BenchmarkRuleEvaluation(b *testing.B) {
	// Create a rule set with multiple rules
	rules := []PermissionRule{
		{Tool: "glob", AllowAll: true},
		{Tool: "grep", AllowAll: true},
		{Tool: "ls", AllowAll: true},
		{Tool: "sourcegraph", AllowAll: true},
		{Tool: "view", AllowAll: true},
		{Tool: "bash", Allow: []string{"ls *", "pwd", "whoami"}},
		{Tool: "edit", Allow: []string{"**/*.txt", "**/*.go"}},
		{Tool: "write", Allow: []string{"**/*.md"}},
	}

	ruleSet := &RuleSet{
		Rules:         rules,
		DefaultEffect: Ask,
	}

	if err := ruleSet.Compile(); err != nil {
		b.Fatal(err)
	}

	// Test requests
	requests := []PermissionRequest{
		{Tool: "glob", Pattern: "*.go"},
		{Tool: "grep", Pattern: "func main"},
		{Tool: "ls", Path: "/home/user"},
		{Tool: "view", Path: "/home/user/file.txt"},
		{Tool: "bash", Command: "ls -la"},
		{Tool: "edit", Path: "/home/user/test.txt"},
		{Tool: "write", Path: "/home/user/doc.md"},
	}

	b.Run("EvaluateRules", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			req := requests[i%len(requests)]
			_, _ = EvaluateRules(ruleSet, req)
		}
	})
}

// BenchmarkCompoundCommandParsing benchmarks compound command parsing
func BenchmarkCompoundCommandParsing(b *testing.B) {
	simpleCompound := "ls && pwd"
	complexCompound := "cd /tmp && ls -la && grep pattern *.txt || echo not found"

	b.Run("SimpleCompound", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			rule := PermissionRule{
				Tool:  "bash",
				Allow: []string{"ls *", "pwd"},
			}
			compiled, _ := CompileRule(rule, "")

			req := PermissionRequest{
				Tool:    "bash",
				Command: simpleCompound,
			}
			_, _ = compiled.Match(req)
		}
	})

	b.Run("ComplexCompound", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			rule := PermissionRule{
				Tool:  "bash",
				Allow: []string{"cd *", "ls *", "grep *", "echo *"},
			}
			compiled, _ := CompileRule(rule, "")

			req := PermissionRequest{
				Tool:    "bash",
				Command: complexCompound,
			}
			_, _ = compiled.Match(req)
		}
	})
}

// BenchmarkPatternMatching benchmarks different pattern types
func BenchmarkPatternMatching(b *testing.B) {
	prefixRule := PermissionRule{Tool: "bash", Allow: []string{"ls "}}
	globRule := PermissionRule{Tool: "bash", Allow: []string{"ls *"}}
	regexRule := PermissionRule{Tool: "bash", Allow: []string{"^ls("}, Regex: true}

	prefixCompiled, _ := CompileRule(prefixRule, "")
	globCompiled, _ := CompileRule(globRule, "")
	regexCompiled, _ := CompileRule(regexRule, "")

	commands := []string{
		"ls -la",
		"ls /home/user",
		"ls -R /tmp",
	}

	b.Run("PrefixMatching", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			req := PermissionRequest{
				Tool:    "bash",
				Command: commands[i%len(commands)],
			}
			_, _ = prefixCompiled.Match(req)
		}
	})

	b.Run("GlobMatching", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			req := PermissionRequest{
				Tool:    "bash",
				Command: commands[i%len(commands)],
			}
			_, _ = globCompiled.Match(req)
		}
	})

	b.Run("RegexMatching", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			req := PermissionRequest{
				Tool:    "bash",
				Command: commands[i%len(commands)],
			}
			_, _ = regexCompiled.Match(req)
		}
	})
}

// BenchmarkRuleSetSizes benchmarks performance with different rule set sizes
func BenchmarkRuleSetSizes(b *testing.B) {
	createRuleSet := func(size int) *RuleSet {
		rules := make([]PermissionRule, size)
		for i := 0; i < size; i++ {
			rules[i] = PermissionRule{
				Tool:  "bash",
				Allow: []string{"cmd" + string(rune(i)) + " *"},
			}
		}

		ruleSet := &RuleSet{
			Rules:         rules,
			DefaultEffect: Ask,
		}

		if err := ruleSet.Compile(); err != nil {
			b.Fatal(err)
		}

		return ruleSet
	}

	sizes := []int{10, 50, 100}

	for _, size := range sizes {
		ruleSet := createRuleSet(size)
		req := PermissionRequest{Tool: "bash", Command: "cmd0 test"}

		b.Run(fmt.Sprintf("RuleSetSize%d", size), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_, _ = EvaluateRules(ruleSet, req)
			}
		})
	}
}
