package cmd

import (
	"fmt"
	"os"

	"charm.land/lipgloss/v2"
	"charm.land/lipgloss/v2/table"
	"github.com/charmbracelet/x/term"
	"github.com/spf13/cobra"
)

var validatePermissionsCmd = &cobra.Command{
	Use:   "validate-permissions",
	Short: "Validate and display the permission configuration",
	Long: `Validate and display the permission configuration including rule structure,
compiled patterns, and fallback behavior. This command helps debug permission issues
and verify that the rule engine is configured correctly.`,
	Example: `
# Validate current permissions configuration
crush validate-permissions

# Validate with detailed rule information
crush validate-permissions --verbose
`,
	RunE: func(cmd *cobra.Command, args []string) error {
		verbose, _ := cmd.Flags().GetBool("verbose")
		debug, _ := cmd.Flags().GetBool("debug-permissions")

		app, err := setupApp(cmd)
		if err != nil {
			return err
		}
		defer app.Shutdown()

		perms := app.Config().Permissions
		if perms == nil {
			return fmt.Errorf("no permissions configured")
		}

		fmt.Println(lipgloss.NewStyle().Bold(true).Render("Permission Configuration Validation"))
		fmt.Println()

		// Summary section
		if term.IsTerminal(os.Stdout.Fd()) {
			t := table.New().
				Border(lipgloss.RoundedBorder()).
				StyleFunc(func(row, col int) lipgloss.Style {
					return lipgloss.NewStyle().Padding(0, 2)
				})

			t.Row("Skip Requests", fmt.Sprintf("%v", perms.SkipRequests()))
			t.Row("Rules Configured", fmt.Sprintf("%v", len(perms.Rules) > 0))

			if perms.RuleSet() != nil {
				compiledRules := perms.RuleSet().GetCompiledRules()
				t.Row("Compiled Rules", fmt.Sprintf("%d", len(compiledRules)))
			} else {
				t.Row("Compiled Rules", "0 (no rule set)")
			}

			if perms.DefaultEffect != "" {
				t.Row("Default Effect", string(perms.DefaultEffect))
			} else {
				t.Row("Default Effect", "allow (not set)")
			}

			fmt.Println(t)
		} else {
			fmt.Printf("Skip Requests: %v\n", perms.SkipRequests())
			fmt.Printf("Rules Configured: %v\n", len(perms.Rules) > 0)
			if perms.RuleSet() != nil {
				fmt.Printf("Compiled Rules: %d\n", len(perms.RuleSet().GetCompiledRules()))
			} else {
				fmt.Println("Compiled Rules: 0 (no rule set)")
			}
			if perms.DefaultEffect != "" {
				fmt.Printf("Default Effect: %s\n", perms.DefaultEffect)
			} else {
				fmt.Println("Default Effect: allow (not set)")
			}
		}

		fmt.Println()

		// Rules section
		if len(perms.Rules) > 0 {
			fmt.Println(lipgloss.NewStyle().Bold(true).Render("Configured Rules"))
			fmt.Println()

			for i, rule := range perms.Rules {
				fmt.Printf("Rule %d:\n", i+1)

				if term.IsTerminal(os.Stdout.Fd()) {
					t := table.New().
						Border(lipgloss.HiddenBorder()).
						StyleFunc(func(row, col int) lipgloss.Style {
							return lipgloss.NewStyle().Padding(0, 2)
						})

					t.Row("  Tool", rule.Tool)
					if len(rule.Allow) > 0 {
						t.Row("  Allow Patterns", fmt.Sprintf("%d pattern(s)", len(rule.Allow)))
					}
					if len(rule.Deny) > 0 {
						t.Row("  Deny Patterns", fmt.Sprintf("%d pattern(s)", len(rule.Deny)))
					}
					if rule.DenyAll {
						t.Row("  Deny All", "true")
					}
					if rule.AllowAll {
						t.Row("  Allow All", "true")
					}
					if rule.Regex {
						t.Row("  Use Regex", "true")
					}
					if rule.Message != "" {
						t.Row("  Custom Message", rule.Message)
					}

					fmt.Println(t)
				} else {
					fmt.Printf("  Tool: %s\n", rule.Tool)
					if len(rule.Allow) > 0 {
						fmt.Printf("  Allow Patterns: %d pattern(s)\n", len(rule.Allow))
					}
					if len(rule.Deny) > 0 {
						fmt.Printf("  Deny Patterns: %d pattern(s)\n", len(rule.Deny))
					}
					if rule.DenyAll {
						fmt.Println("  Deny All: true")
					}
					if rule.AllowAll {
						fmt.Println("  Allow All: true")
					}
					if rule.Regex {
						fmt.Println("  Use Regex: true")
					}
					if rule.Message != "" {
						fmt.Printf("  Custom Message: %s\n", rule.Message)
					}
				}

				// Detailed pattern information if verbose
				if verbose {
					if len(rule.Allow) > 0 {
						fmt.Printf("    Allow patterns:\n")
						for j, pattern := range rule.Allow {
							fmt.Printf("      %d. %s\n", j+1, pattern)
						}
					}
					if len(rule.Deny) > 0 {
						fmt.Printf("    Deny patterns:\n")
						for j, pattern := range rule.Deny {
							fmt.Printf("      %d. %s\n", j+1, pattern)
						}
					}
				}

				fmt.Println()
			}
		} else {
			fmt.Println("No rules configured.")
			fmt.Println()
		}

		// Analysis section
		fmt.Println(lipgloss.NewStyle().Bold(true).Render("Analysis"))
		fmt.Println()

		if perms.RuleSet() != nil {
			compiledRules := perms.RuleSet().GetCompiledRules()
			if len(compiledRules) > 0 {
				fmt.Printf("✓ Rule engine is active with %d compiled rules\n", len(compiledRules))

				if perms.DefaultEffect != "" {
					fmt.Printf("✓ Default effect is set to: %s\n", perms.DefaultEffect)
				} else {
					fmt.Println("✓ Using implicit default effect: allow")
				}

				if debug {
					fmt.Println()
					fmt.Println("Debug: Compiled rules are ready for evaluation")
				}
			} else {
				fmt.Println("⚠ Rules exist but none were compiled (possibly empty rules)")
				fmt.Println("  The system will fall back to AllowedTools or default allow behavior")
			}
		} else {
			fmt.Println("⚠ No rule engine configured")
			if len(perms.Rules) > 0 {
				fmt.Println("⚠ Rules exist but failed to compile")
			}
			fmt.Println("  The system will use AllowedTools or default allow behavior")
		}

		fmt.Println()
		fmt.Println("Configuration is valid for use")

		return nil
	},
}

func init() {
	validatePermissionsCmd.Flags().BoolP("verbose", "v", false, "Show detailed rule information including patterns")
}
