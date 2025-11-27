package permission

import (
	"regexp"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// ASTSafetyChecker provides AST-based safety-critical command detection
type ASTSafetyChecker struct {
	parser  *syntax.Parser
	printer *syntax.Printer

	// Known dangerous shells
	dangerousShells map[string]bool

	// Wrapper commands that need recursive parsing
	wrapperCommands map[string]bool
}

// NewASTSafetyChecker creates a new AST-based safety checker
func NewASTSafetyChecker() *ASTSafetyChecker {
	return &ASTSafetyChecker{
		parser:  syntax.NewParser(),
		printer: syntax.NewPrinter(),
		// Dangerous shells based on safety critical block rules
		dangerousShells: map[string]bool{
			"sh":          true,
			"bash":        true,
			"zsh":         true,
			"dash":        true,
			"ksh":         true,
			"fish":        true,
			"csh":         true,
			"tcsh":        true,
			"python":      true,
			"python3":     true,
			"node":        true,
			"perl":        true,
			"ruby":        true,
			"awk":         true,
			"expect":      true,
			"env":         true,
			"sudo":        true,
			"timeout":     true,
			"stdbuf":      true,
			"socat":       true,
			"script":      true,
			"xargs":       true,
			"parallel":    true,
			"ionice":      true,
			"cgexec":      true,
			"firejail":    true,
			"chroot":      true,
			"systemd-run": true,
			"pkexec":      true,
			"ssh":         true,
			"scp":         true,
			"rsync":       true,
			"rsh":         true,
			"telnet":      true,
			"nc":          true,
			"ftp":         true,
			"tftp":        true,
			"wget":        true,
			"curl":        true,
			"lynx":        true,
			"links":       true,
			"w3m":         true,
			"whois":       true,
			"dig":         true,
			"host":        true,
			"nslookup":    true,
		},
		wrapperCommands: map[string]bool{
			"sh":          true,
			"bash":        true,
			"zsh":         true,
			"dash":        true,
			"ksh":         true,
			"fish":        true,
			"csh":         true,
			"tcsh":        true,
			"python":      true,
			"python3":     true,
			"node":        true,
			"perl":        true,
			"ruby":        true,
			"awk":         true,
			"docker":      true,
			"kubectl":     true,
			"podman":      true,
			"lxc":         true,
			"lxd":         true,
			"systemd-run": true,
			"firejail":    true,
			"chroot":      true,
			"schroot":     true,
		},
	}
}

// checkInteractiveTerminalApp checks if the command is an interactive terminal application
// that requires a TTY and will hang in a non-interactive subprocess
func (a *ASTSafetyChecker) checkInteractiveTerminalApp(n *syntax.CallExpr) bool {
	if len(n.Args) == 0 {
		return false
	}

	// Get the command name (first word)
	cmdName := a.wordToString(n.Args[0])
	if cmdName == "" {
		return false
	}

	// Pattern matching for interactive applications
	patterns := []string{
		// Rails family (console commands that hang and shouldn't be AI-accessible)
		`^rails\s+(c|console)`,
		`^bundle\s+exec\s+rails\s+(c|console)`,
		`^bundle\s+exec\s+rake\s+console`,
		`^bundle\s+exec\s+rake\s+console.*`,
		`^bin/rails\s+(c|console)`,
		
		// REPLs (will hang without input, AI should not access directly)
		`^python\d*$`,           // python3 with no args = REPL mode
		`^irb$`,
		`^node$`,                // node without script argument
		`^php\s+-a`,            // PHP interactive mode
		`^lua$`,
		`^guile$`,
		
		// Databases (direct DB access is a security risk - AI should use application APIs, not DB CLIs)
		`^psql`,         // Block ALL psql commands - direct DB access bypasses application logic
		`^mysql`,        // Block ALL mysql commands - security boundary violation
		`^sqlite3`,      // Block ALL sqlite3 commands - not appropriate for AI access
		
		// Editors (hang without TTY, AI should use edit/write tools)
		`^vim(\s|$)`, `^vi(\s|$)`, `^nano(\s|$)`, 
		`^emacs(\s|$)`, `^less(\s|$)`, `^more(\s|$)`,
		`^pico(\s|$)`, `^joe(\s|$)`,
		
		// Process managers (hang, not useful for AI)
		`^top(\s|$)`, `^htop(\s|$)`, `^atop(\s|$)`,
		`^screen(\s|$)`, `^tmux(\s|$)`,
		
		// Other interactive/unsafe tools
		`^ssh(\s|$)`,           // SSH prompts for passwords
		`^ftp(\s|$)`,           // FTP is interactive
		`^telnet(\s|$)`,        // Telnet is interactive
		`^script(\s|$)`,        // script creates TTY log
		`^expect(\s|$)`,        // expect is for interactive automation
		`^whiptail(\s|$)`,      // TUI dialogs fail without TTY
		`^dialog(\s|$)`,        // TUI dialogs fail without TTY
	}
	
	// First, check if it's a simple command (no arguments or only whitespace)
	if len(n.Args) == 1 && (cmdName == "python" || cmdName == "python3" || cmdName == "irb" || cmdName == "node") {
		// These launch REPL when called with no arguments
		return true
	}
	
	// For compound commands, get the full command string to match patterns
	var cmdBuilder strings.Builder
	cmdBuilder.WriteString(cmdName)
	for i, arg := range n.Args {
		if i == 0 {
			continue
		}
		argStr := a.wordToString(arg)
		if argStr != "" {
			cmdBuilder.WriteString(" ")
			cmdBuilder.WriteString(argStr)
		}
	}
	fullCmd := cmdBuilder.String()
	
	// Check against patterns
	for _, pattern := range patterns {
		if matched, _ := regexp.MatchString(pattern, fullCmd); matched {
			return true
		}
	}
	
	// Also check command name itself (for aliases, functions, etc.)
	// This catches cases where the command is aliased to something dangerous
	for _, pattern := range patterns {
		// Extract just the command name pattern for this check
		if strings.HasPrefix(pattern, `^`+regexp.QuoteMeta(cmdName)+`\s`) {
			if matched, _ := regexp.MatchString(pattern, cmdName+" "); matched {
				return true
			}
		}
	}
	
	return false
}

// IsCritical checks if a command is safety-critical
func (a *ASTSafetyChecker) IsCritical(command string) bool {
	file, err := a.parser.Parse(strings.NewReader(command), "")
	if err != nil {
		// If we can't parse it, err on the side of caution
		return true
	}

	return a.checkNode(file)
}

// checkNode recursively checks a node for dangerous patterns
func (a *ASTSafetyChecker) checkNode(node syntax.Node) bool {
	if node == nil {
		return false
	}

	switch n := node.(type) {
	case *syntax.File:
		// Check all statements in the file
		for _, stmt := range n.Stmts {
			if a.checkNode(stmt) {
				return true
			}
		}
		return false

	case *syntax.Stmt:
		// Check the command in the statement
		if n.Cmd != nil {
			return a.checkNode(n.Cmd)
		}
		return false

	case *syntax.BinaryCmd:
		// Check if this is a pipe to a dangerous shell
		if n.Op == syntax.Pipe || n.Op == syntax.PipeAll {
			return a.isDangerousPipe(n.X, n.Y)
		}
		// Check both sides of other binary operations
		return a.checkNode(n.X) || a.checkNode(n.Y)

	case *syntax.CallExpr:
		// Check arguments recursively for dangerous patterns (like command substitution)
		for _, arg := range n.Args {
			if a.checkNode(arg) {
				return true
			}
		}
		// Check for rm commands
		if a.checkRMCommand(n) {
			return true
		}
		// Check for other dangerous filesystem commands
		if a.checkDangerousFSCommand(n) {
			return true
		}
		// Check for wrapper patterns like sh -c
		if a.checkWrapperCommand(n) {
			return true
		}
		// Check for interactive-only terminal applications (will hang in non-TTY)
		return a.checkInteractiveTerminalApp(n)

	case *syntax.CmdSubst:
		// Command substitution - recursively check inner commands
		for _, stmt := range n.Stmts {
			if a.checkNode(stmt) {
				return true
			}
		}
		return false

	case *syntax.Subshell:
		// Subshell - recursively check inner commands
		for _, stmt := range n.Stmts {
			if a.checkNode(stmt) {
				return true
			}
		}
		return false

	case *syntax.Word:
		// Check if any part of the word contains dangerous patterns (like command substitution)
		for _, part := range n.Parts {
			if a.checkNode(part) {
				return true
			}
		}
		// Don't check for dangerous network commands here - they're only dangerous in pipe context
		return false
	}

	return false
}

// isDangerousPipe checks if a pipe is dangerous (e.g., curl | sh)
func (a *ASTSafetyChecker) isDangerousPipe(left, right syntax.Node) bool {
	// Check if right side is a dangerous shell
	if stmt, ok := right.(*syntax.Stmt); ok {
		if call, ok := stmt.Cmd.(*syntax.CallExpr); ok {
			if len(call.Args) > 0 {
				firstArg := a.wordToString(call.Args[0])
				if a.dangerousShells[firstArg] {
					// Right side is sh/bash/etc. - check if left side is a network command
					if a.isNetworkCommandNode(left) {
						return true
					}
				}
			}
		}
	}
	// Also check if left side is dangerous
	return a.checkNode(left) || a.checkNode(right)
}

// checkWrapperCommand checks for wrapper commands like sh -c "command"
func (a *ASTSafetyChecker) checkWrapperCommand(call *syntax.CallExpr) bool {
	if len(call.Args) == 0 {
		return false
	}

	// Get the command name
	cmdName := a.wordToString(call.Args[0])

	// Check if this is a wrapper command
	if !a.wrapperCommands[cmdName] {
		return false
	}

	// Look for -c / --command flag
	hasCFlag := false
	commandStr := ""

	for i := 1; i < len(call.Args); i++ {
		argStr := a.wordToString(call.Args[i])

		if argStr == "-c" || argStr == "--command" {
			hasCFlag = true
			// Next argument should be the command string
			if i+1 < len(call.Args) {
				commandStr = a.wordToString(call.Args[i+1])
				break
			}
		}
		// Some commands allow -c"command" or --command="command"
		if strings.HasPrefix(argStr, "-c") && len(argStr) > 2 {
			hasCFlag = true
			commandStr = argStr[2:]
			break
		}
		if strings.HasPrefix(argStr, "--command=") {
			hasCFlag = true
			commandStr = strings.TrimPrefix(argStr, "--command=")
			break
		}
	}

	if hasCFlag && commandStr != "" {
		// Clean quotes from command string
		commandStr = strings.Trim(commandStr, `"'`)

		// Check if the embedded command is dangerous
		return a.IsCritical(commandStr)
	}

	// Handle special cases like docker exec, kubectl exec without explicit -c
	if cmdName == "docker" || cmdName == "podman" || cmdName == "kubectl" || cmdName == "lxc" || cmdName == "lxd" {
		// For these commands, any argument that looks like shell code might be dangerous
		for i := 1; i < len(call.Args); i++ {
			argStr := a.wordToString(call.Args[i])
			argStr = strings.Trim(argStr, `"'`)

			// Simple heuristic: if it contains shell operators, parse it
			if strings.ContainsAny(argStr, "|;&$") || strings.Contains(argStr, "(") {
				if a.IsCritical(argStr) {
					return true
				}
			}
		}
	}

	return false
}

// checkRMCommand checks if an rm command is dangerous (e.g., rm -rf /)
func (a *ASTSafetyChecker) checkRMCommand(call *syntax.CallExpr) bool {
	if len(call.Args) < 2 {
		return false
	}

	// Check for -rf, -fr, -r -f, etc. flags
	hasRFlag := false
	hasFFlag := false

	for i := 1; i < len(call.Args); i++ {
		arg := a.wordToString(call.Args[i])

		if arg == "-r" || arg == "-R" || arg == "--recursive" {
			hasRFlag = true
		}
		if arg == "-f" || arg == "--force" {
			hasFFlag = true
		}
		// Combined flags like -rf, -fr
		if strings.HasPrefix(arg, "-") && len(arg) > 2 {
			for _, ch := range arg[1:] {
				if ch == 'r' || ch == 'R' {
					hasRFlag = true
				}
				if ch == 'f' {
					hasFFlag = true
				}
			}
		}
	}

	// Check if it has both r and f flags
	if !hasRFlag || !hasFFlag {
		return false
	}

	// Check if the target is dangerous (/, /etc, /usr, /bin, etc.)
	for i := 1; i < len(call.Args); i++ {
		arg := a.wordToString(call.Args[i])
		if !strings.HasPrefix(arg, "-") {
			// This is the target path
			target := strings.TrimSpace(arg)
			target = strings.Trim(target, "'")
			target = strings.Trim(target, `"`)

			// Dangerous targets
			if target == "/" || target == "/root" ||
				target == "/etc" || target == "/usr" ||
				target == "/bin" || target == "/sbin" ||
				target == "/lib" || target == "/lib64" ||
				target == "/boot" || target == "/dev" ||
				target == "/sys" || target == "/proc" ||
				target == "/home" || target == "/var" {
				return true
			}
		}
	}

	return false
}

// isDangerousNetworkCommand checks if this word is a dangerous network command
func (a *ASTSafetyChecker) isDangerousNetworkCommand(word string) bool {
	dangerousNetworks := map[string]bool{
		"curl":   true,
		"wget":   true,
		"ftp":    true,
		"tftp":   true,
		"nc":     true,
		"telnet": true,
		"ssh":    true,
		"scp":    true,
		"rsync":  true,
		"rsh":    true,
		"lynx":   true,
		"links":  true,
		"w3m":    true,
	}

	return dangerousNetworks[word]
}

// isNetworkCommandNode checks if a node represents a network command
func (a *ASTSafetyChecker) isNetworkCommandNode(node syntax.Node) bool {
	switch n := node.(type) {
	case *syntax.CallExpr:
		if len(n.Args) > 0 {
			cmdName := a.wordToString(n.Args[0])
			return a.isDangerousNetworkCommand(cmdName)
		}
	case *syntax.Stmt:
		if n.Cmd != nil {
			return a.isNetworkCommandNode(n.Cmd)
		}
	}
	return false
}

// checkDangerousFSCommand checks for dangerous filesystem commands (mkfs, dd, wipefs, shred, chmod setuid)
func (a *ASTSafetyChecker) checkDangerousFSCommand(call *syntax.CallExpr) bool {
	if len(call.Args) == 0 {
		return false
	}

	cmdName := a.wordToString(call.Args[0])

	// mkfs on devices
	if strings.HasPrefix(cmdName, "mkfs") && len(call.Args) > 1 {
		for _, arg := range call.Args[1:] {
			argStr := a.wordToString(arg)
			if strings.HasPrefix(argStr, "/dev/") {
				return true
			}
		}
	}

	// dd writing to device
	if cmdName == "dd" && len(call.Args) > 1 {
		var hasDeviceOutput bool
		var hasDangerousInput bool

		for _, arg := range call.Args[1:] {
			argStr := a.wordToString(arg)
			// Check for output to device
			if strings.HasPrefix(argStr, "of=/dev/") {
				hasDeviceOutput = true
			}
			// Check for dangerous input (zeros, random)
			if argStr == "if=/dev/zero" || argStr == "if=/dev/random" || argStr == "if=/dev/urandom" {
				hasDangerousInput = true
			}
		}

		if hasDeviceOutput && hasDangerousInput {
			return true
		}
	}

	// wipefs on devices with -a or --all
	if cmdName == "wipefs" && len(call.Args) > 1 {
		var hasAllFlag bool
		var hasDevice bool

		for _, arg := range call.Args[1:] {
			argStr := a.wordToString(arg)
			if argStr == "-a" || argStr == "--all" {
				hasAllFlag = true
			}
			if strings.HasPrefix(argStr, "/dev/") {
				hasDevice = true
			}
		}

		if hasAllFlag && hasDevice {
			return true
		}
	}

	// shred on devices
	if cmdName == "shred" && len(call.Args) > 1 {
		for _, arg := range call.Args[1:] {
			argStr := a.wordToString(arg)
			if strings.HasPrefix(argStr, "/dev/") {
				return true
			}
		}
	}

	// chmod with setuid bit
	if cmdName == "chmod" && len(call.Args) > 1 {
		for _, arg := range call.Args[1:] {
			argStr := a.wordToString(arg)
			// Check for setuid bit (4xxx) or u+s/g+s
			if len(argStr) == 4 && argStr[0] == '4' && argStr[1] >= '0' && argStr[1] <= '7' {
				return true
			}
			if argStr == "u+s" || argStr == "g+s" {
				return true
			}
		}
	}

	// Fork bomb detection (simple pattern match)
	if strings.Contains(cmdName, ":(){") {
		return true
	}
	// Check all args for fork bomb pattern
	if len(call.Args) > 1 {
		for _, arg := range call.Args[1:] {
			argStr := a.wordToString(arg)
			if strings.Contains(argStr, ":(){") {
				return true
			}
		}
	}

	return false
}

// wordToString converts a word to string
func (a *ASTSafetyChecker) wordToString(word *syntax.Word) string {
	if word == nil || len(word.Parts) == 0 {
		return ""
	}

	var result strings.Builder
	for _, part := range word.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			result.WriteString(p.Value)
		case *syntax.DblQuoted:
			result.WriteString(`"`)
			for _, quotedPart := range p.Parts {
				if lit, ok := quotedPart.(*syntax.Lit); ok {
					result.WriteString(lit.Value)
				}
			}
			result.WriteString(`"`)
		case *syntax.CmdSubst:
			result.WriteString("$(...)")
		}
	}
	return result.String()
}
