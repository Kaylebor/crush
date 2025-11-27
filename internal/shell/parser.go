package shell

import (
	"strings"
)

// ParseCommands splits a compound command string into individual commands.
// It properly handles quoted strings and recognizes all compound operators
// at the same level: &&, ||, ;
//
// This is more secure than sequential splitting as it prevents
// bypassing security checks by mixing operators.
//
// The function returns a slice of cleaned-up command parts with leading/trailing
// whitespace removed.
func ParseCommands(command string) []string {
	return parseCommandsInternal(command, false)
}

// ParseCommandsWithOperators splits a command string into alternating
// commands and operators. This preserves the operator information
// which is needed for safety-critical command detection.
//
// Returns: [cmd1, operator, cmd2, operator, cmd3, ...]
// Example: "curl http://example.com | sh" → ["curl http://example.com", "|", "sh"]
func ParseCommandsWithOperators(command string) []string {
	return parseCommandsInternal(command, true)
}

// parseCommandsInternal is the shared implementation for parsing commands
// with optional operator preservation.
func parseCommandsInternal(command string, withOperators bool) []string {
	var commands []string

	if command == "" {
		return commands
	}

	// State machine states
	const (
		stateNormal = iota
		stateSingleQuote
		stateDoubleQuote
		stateEscape
	)

	var current strings.Builder
	state := stateNormal
	i := 0

	// Helper to flush current command (with whitespace normalization)
	flushCommand := func() {
		if current.Len() > 0 {
			cmd := current.String()

			// Normalize whitespace: trim, collapse multiple spaces/tabs to single space
			cmd = strings.TrimSpace(cmd)
			for strings.Contains(cmd, "  ") || strings.Contains(cmd, "\t") {
				cmd = strings.ReplaceAll(cmd, "  ", " ")
				cmd = strings.ReplaceAll(cmd, "\t", " ")
			}

			if cmd != "" {
				commands = append(commands, cmd)
			}
			current.Reset()
		}
	}

	for i < len(command) {
		ch := command[i]

		switch state {
		case stateEscape:
			// After an escape, always go back to normal state
			current.WriteByte(ch)
			state = stateNormal
			i++

		case stateSingleQuote:
			if ch == '\'' {
				state = stateNormal
			} else if ch == '\\' && i+1 < len(command) && command[i+1] == '\'' {
				// Handle escaped single quote inside single quotes
				current.WriteByte(ch) // Write the backslash
				i++
				if i < len(command) {
					current.WriteByte(command[i]) // Write the escaped quote
				}
				i++
				continue
			}
			current.WriteByte(ch)
			i++

		case stateDoubleQuote:
			if ch == '"' {
				state = stateNormal
			} else if ch == '\\' && i+1 < len(command) {
				// Handle escape sequences in double quotes
				next := command[i+1]
				if next == '"' || next == '\\' || next == '$' || next == '`' {
					current.WriteByte(ch) // Write the backslash
					i++
					current.WriteByte(next)
					i += 1
					continue
				}
			}
			current.WriteByte(ch)
			i++

		case stateNormal:
			switch ch {
			case '\\':
				// Enter escape state
				state = stateEscape
				current.WriteByte(ch)
				i++

			case '\'':
				state = stateSingleQuote
				current.WriteByte(ch)
				i++

			case '"':
				state = stateDoubleQuote
				current.WriteByte(ch)
				i++

			case ';':
				flushCommand()
				if withOperators {
					commands = append(commands, ";")
				}
				i++
				// Skip following whitespace
				for i < len(command) && command[i] == ' ' {
					i++
				}

			case '|':
				// Check if it's a pipe operator or part of ||
				if i+1 < len(command) && command[i+1] == '|' {
					// || operator
					flushCommand()
					if withOperators {
						commands = append(commands, "||")
					}
					i += 2
					// Skip following whitespace
					for i < len(command) && command[i] == ' ' {
						i++
					}
				} else {
					// Single pipe - also treated as command separator for security
					flushCommand()
					if withOperators {
						commands = append(commands, "|")
					}
					i++
					// Skip following whitespace
					for i < len(command) && command[i] == ' ' {
						i++
					}
				}

			case '&':
				// Check for && operator
				if i+1 < len(command) && command[i+1] == '&' {
					flushCommand()
					if withOperators {
						commands = append(commands, "&&")
					}
					i += 2
					// Skip following whitespace
					for i < len(command) && command[i] == ' ' {
						i++
					}
				} else {
					// Single & (shouldn't happen in shell, but handle it)
					current.WriteByte(ch)
					i++
				}

			default:
				current.WriteByte(ch)
				i++
			}
		}
	}

	// Flush any remaining command
	flushCommand()

	return commands
}

// ParsedCommand represents a parsed command with operators preserved.
// This structure is used for safety-critical command detection.
type ParsedCommand struct {
	// FullCommand is the original command string
	FullCommand string
	// Parts contains alternating commands and operators: [cmd1, op, cmd2, op, cmd3, ...]
	// Example: "curl http://example.com | sh" → ["curl http://example.com", "|", "sh"]
	Parts []string
	// Commands contains just the command parts (every other element from Parts)
	Commands []string
	// Operators contains just the operator parts
	Operators []string
}

// ParseEnhanced parses a command and returns a ParsedCommand structure
// with commands and operators separated for easy iteration.
func ParseEnhanced(command string) ParsedCommand {
	parts := ParseCommandsWithOperators(command)

	result := ParsedCommand{
		FullCommand: command,
		Parts:       parts,
		Commands:    make([]string, 0),
		Operators:   make([]string, 0),
	}

	// Separate commands and operators
	for i, part := range parts {
		if i%2 == 0 {
			result.Commands = append(result.Commands, part)
		} else {
			result.Operators = append(result.Operators, part)
		}
	}

	return result
}

// ContainsCompoundOperator checks if a command contains compound operators.
// This is a simpler, faster check than ParseCommands when we just need to know
// if there are any operators present.
func ContainsCompoundOperator(command string) bool {
	// State machine states
	const (
		stateNormal = iota
		stateSingleQuote
		stateDoubleQuote
		stateEscape
	)

	state := stateNormal
	i := 0

	for i < len(command) {
		ch := command[i]

		switch state {
		case stateEscape:
			state = stateNormal
			i++

		case stateSingleQuote:
			if ch == '\'' {
				state = stateNormal
			} else if ch == '\\' && i+1 < len(command) && command[i+1] == '\'' {
				i++
			}
			i++

		case stateDoubleQuote:
			if ch == '"' {
				state = stateNormal
			} else if ch == '\\' && i+1 < len(command) {
				next := command[i+1]
				if next == '"' || next == '\\' || next == '$' || next == '`' {
					i++
				}
			}
			i++

		case stateNormal:
			switch ch {
			case '\\':
				state = stateEscape
				i++

			case '\'':
				state = stateSingleQuote
				i++

			case '"':
				state = stateDoubleQuote
				i++

			case ';':
				return true

			case '|':
				// Single pipe or double pipe both indicate compound command
				return true

			case '&':
				if i+1 < len(command) && command[i+1] == '&' {
					return true
				}
				i++

			default:
				i++
			}
		}
	}

	return false
}
