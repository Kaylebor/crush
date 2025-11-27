# Crush Permissions & Security Model

Crush uses a rule-based permission system to control access to tools, providing fine-grained control over what operations can be performed automatically, what requires approval, and what is denied.

## Overview

The permission system evaluates each tool call against a set of rules to determine whether to **allow**, **deny**, or **ask** (prompt the user) for permission. Rules are matched based on the tool name and optional patterns for the tool's arguments or target paths.

### Key Concepts

- **Rules**: Define permissions for specific tools
- **Effects**: `allow`, `deny`, or `ask` (the default)
- **Patterns**: Prefix, glob, or regex matching for fine-grained control
- **Default Effect**: The fallback behavior when no rules match
- **Agent Integration**: Different agents can have different permission sets

## Configuration

Permissions are configured in your `crush.json` file:

```json
{
  "$schema": "https://charm.land/crush.json",
  "permissions": {
    "rules": [
      {
        "tool": "bash",
        "allow": ["ls", "pwd", "git status"]
      },
      {
        "tool": "edit",
        "allow": ["**/*.go", "**/*.md"],
        "deny": ["**/.env", "**/*.key", "**/*.pem"]
      }
    ],
    "default": "ask"
  }
}
```

## Rule Structure

Each rule in your configuration has the following fields:

```json
{
  "tool": "bash",                          // Tool name (required)
  "allow_all": false,                      // Allow all uses of this tool
  "deny_all": false,                       // Deny all uses of this tool
  "allow": ["pattern1", "pattern2"],       // Patterns to explicitly allow
  "deny": ["pattern1", "pattern2"],        // Patterns to explicitly deny
  "regex": false,                          // Use regex instead of glob
  "message": "Custom denial message"       // Optional custom message
}
```

### Rule Fields Explained

#### `tool` (required)
The name of the tool to control. Common tools include:

**Read-only tools** (generally safe to allow broadly):
- `glob` - Find files by pattern
- `grep` - Search file contents
- `ls` - List directory contents
- `view` - Read file contents
- `sourcegraph` - Search code across repositories

**Potentially destructive tools** (use with caution):
- `edit` - Modify existing files
- `write` - Create or overwrite files
- `bash` - Execute shell commands
- `download` - Download files from URLs
- `agent` - Execute sub-agents

**Specialized tools**:
- `fetch` / `agentic_fetch` - Fetch and process web content
- `mcp_*` - MCP server tools

#### `allow_all` / `deny_all`
Set `allow_all: true` to permit all uses of a tool, or `deny_all: true` to block all uses. These are mutually exclusive.

Example:
```json
{
  "tool": "grep",
  "allow_all": true
}
```

#### `allow` / `deny`
Lists of patterns to explicitly allow or deny. Deny patterns take precedence over allow patterns.

Example:
```json
{
  "tool": "edit",
  "allow": ["**/*.go", "**/*.md"],
  "deny": ["**/.env", "**/*.key"]
}
```

#### `regex`
When `true`, patterns are treated as regular expressions instead of glob patterns.

Example:
```json
{
  "tool": "edit",
  "allow": ["^.*\\.go$"],
  "regex": true
}
```

#### `message`
Optional custom message to display when denying access.

Example:
```json
{
  "tool": "edit",
  "deny": ["**/.env"],
  "message": "Editing .env files is not permitted for security reasons"
}
```

## Pattern Matching

### Glob Patterns (Default)

Glob patterns use the `**` and `*` wildcards for flexible matching:

- `**` matches zero or more directories (recursive)
- `*` matches any sequence of characters within a directory
- `?` matches a single character
- `[abc]` matches any character in the set
- `[a-z]` matches any character in the range

**Common patterns:**

```json
// Match any file in the current directory
"*.go"

// Match any .go file in any subdirectory
"**/*.go"

// Match only in the src directory
"src/**/*.go"

// Match specific file types
"**/*.{go,md,json}"

// Match files starting with test
"**/test*.go"
```

### Prefix Matching

Patterns that don't contain glob wildcards (`*` or `?`) are treated as prefix matches:

```json
// Allow any bash command starting with "git"
{
  "tool": "bash",
  "allow": ["git"]
}

// Will match:
// - "git status"
// - "git commit -m 'message'"
// - "git push origin main"
```

### Regex Patterns

Set `regex: true` to use regular expressions for matching:

```json
// Match only specific file extensions
{
  "tool": "write",
  "allow": ["^.*\\.(go|md|txt)$"],
  "regex": true
}
```

Regex patterns are matched against the full command string or path.

## Evaluation Order

Rules are evaluated in the following order:

1. **Tool name match**: Only rules matching the tool being used are considered
2. **Deny patterns**: If a pattern in `deny` matches, the request is denied
3. **Allow patterns**: If a pattern in `allow` matches, the request is allowed
4. **Default effect**: If no patterns match, use the configured default (usually "ask")

### Precedence

- `deny_all` takes highest precedence (overrides everything)
- `deny` patterns override `allow` patterns
- More specific patterns don't automatically win—first match in evaluation order wins
- The `default` effect is used when no rule patterns match

## Default Configuration

If no permissions are configured, Crush uses a safe default set of rules that:

1. Allows common read-only operations (viewing files, searching code)
2. Prompts for potentially destructive operations (editing files, running commands)
3. Blocks the most dangerous operations (`rm -rf`, system file modifications)

### Bash Tool: Hardcoded Security Blocks

**Important**: The `bash` tool has an additional hardcoded security layer for defense-in-depth:

**Commands always blocked** (even with `allow_all: true`):
- Network: `curl`, `wget`, `nc`, `telnet`, `ssh`, `scp`
- Privilege: `sudo`, `su`, `doas`
- Package managers: `apt`, `apt-get`, `dnf`, `yum`, `pacman`, `brew`, `npm`, `pip`, etc.
- System: `fdisk`, `mkfs`, `systemctl`, `iptables`, `crontab`

**Why?** These commands can modify your system, exfiltrate data, or install malicious software. The hardcoded block list provides an emergency brake that can't be accidentally disabled.

**How to override:** Use explicit patterns in your config. Patterns work as **prefix matches**, **glob patterns**, or **exact matches**:

```json
{
  "tool": "bash",
  "allow": [
    "curl",                    // Prefix: allows any curl command
    "curl https://api.github.com/repos/*",  // Glob: specific URLs only
    "git status",              // Exact: only git status
    "git "                     // Prefix: any git subcommand
  ]
}
```

**Behavior comparison:**
```json
// Still blocks curl, ssh, etc (defense in depth)
{"tool": "bash", "allow_all": true}

// Allows any curl command (prefix match overrides block)
{"tool": "bash", "allow": ["curl"]}

// Allows specific curl URLs (glob pattern)
{"tool": "bash", "allow": ["curl https://safe-api.com/*"]}
```

### Default Rules

The default rules (from `internal/config/config.go`):

```json
[
  // Read-only tools (allow_all)
  {"tool": "glob", "allow_all": true},
  {"tool": "grep", "allow_all": true},
  {"tool": "ls", "allow_all": true},
  {"tool": "view", "allow_all": true},
  {"tool": "sourcegraph", "allow_all": true},
  {"tool": "references", "allow_all": true},
  
  // Interactive tools (will ask by default)
  {"tool": "bash"},
  {"tool": "edit"},
  {"tool": "write"},
  {"tool": "download"},
  {"tool": "fetch"},
  {"tool": "agentic_fetch"},
  {"tool": "agent"},
  {"tool": "multiedit"},
  
  // System tools
  {"tool": "job_output", "allow_all": true},
  {"tool": "job_kill", "allow_all": true}
]
```

### Agent Tool Sets

Different agents have access to different tool sets:

**Coder Agent** (`AgentCoderTools`) - 17 tools for full development:
`agent`, `bash`, `download`, `edit`, `fetch`, `glob`, `grep`, `job_kill`, `job_output`, `ls`, `multiedit`, `references`, `sourcegraph`, `view`, `web_fetch`, `agentic_fetch`, `write`

**Task Agent** (`AgentTaskTools`) - 5 read/search tools:
`glob`, `grep`, `ls`, `sourcegraph`, `view`

## Practical Examples

### Example 1: Safe Development Environment

Allow reading and searching code, but prompt for any modifications:

```json
{
  "permissions": {
    "rules": [
      {
        "tool": "glob",
        "allow_all": true
      },
      {
        "tool": "grep",
        "allow_all": true
      },
      {
        "tool": "view",
        "allow_all": true
      },
      {
        "tool": "edit",
        "allow": ["**/*.go", "**/*.md"],
        "deny": ["**/.env"]
      },
      {
        "tool": "bash",
        "allow": ["git", "go test", "go build"]
      }
    ],
    "default": "ask"
  }
}
```

### Example 2: Restrictive Security Policy

Only allow specific safe operations, deny everything else:

```json
{
  "permissions": {
    "rules": [
      {
        "tool": "view",
        "allow": ["*.md", "*.txt", "*.go"]
      },
      {
        "tool": "ls",
        "allow_all": true
      },
      {
        "tool": "grep",
        "allow_all": true
      },
      {
        "tool": "bash",
        "allow": ["ls", "pwd", "git status"]
      },
      {
        "tool": "download",
        "deny_all": true,
        "message": "File downloads are not permitted in this environment"
      }
    ],
    "default": "deny"
  }
}
```

### Example 3: Automated Testing Setup

Allow test commands to run without prompting:

```json
{
  "permissions": {
    "rules": [
      {
        "tool": "bash",
        "allow": ["npm test", "go test", "pytest"]
      },
      {
        "tool": "edit",
        "allow": ["**/test/**/*.js", "**/*_test.go"]
      },
      {
        "tool": "write",
        "allow": ["**/testdata/**"]
      }
    ],
    "default": "ask"
  }
}
```

### Example 4: Document Editing Focus

Allow editing documentation freely, restrict code changes:

```json
{
  "permissions": {
    "rules": [
      {
        "tool": "edit",
        "allow": ["**/*.md", "**/*.rst", "**/*.txt"],
        "deny": ["**/README.md"]
      },
      {
        "tool": "write",
        "allow": ["docs/**", "**/*.md"]
      },
      {
        "tool": "view",
        "allow_all": true
      }
    ],
    "default": "ask"
  }
}
```

### Example 5: Using Regex for Complex Patterns

```json
{
  "permissions": {
    "rules": [
      {
        "tool": "edit",
        "allow": ["^.*\\.(go|js|ts)$", "^.*\\.(md|txt|json)$"],
        "deny": ["^[.].*", ".*test[.]"],
        "regex": true
      }
    ],
    "default": "ask"
  }
}
```

## Migration from `allowed_tools` (Legacy)

The previous `allowed_tools` format is still supported for backwards compatibility:

```json
{
  "permissions": {
    "allowed_tools": ["view", "ls", "grep", "fetch"]
  }
}
```

However, this only allows/denies entire tools. To migrate to the new rule-based system:

### Simple Migration (Direct Equivalent)

**Before:**
```json
{
  "permissions": {
    "allowed_tools": ["view", "ls", "grep", "glob"]
  }
}
```

**After:**
```json
{
  "permissions": {
    "rules": [
      {"tool": "view", "allow_all": true},
      {"tool": "ls", "allow_all": true},
      {"tool": "grep", "allow_all": true},
      {"tool": "glob", "allow_all": true}
    ]
  }
}
```

### Enhanced Migration (Add Granularity)

**Before:**
```json
{
  "permissions": {
    "allowed_tools": ["view", "ls", "grep", "edit"]
  }
}
```

**After:** (with restrictions)
```json
{
  "permissions": {
    "rules": [
      {"tool": "view", "allow_all": true},
      {"tool": "ls", "allow_all": true},
      {"tool": "grep", "allow_all": true},
      {
        "tool": "edit",
        "allow": ["**/*.go", "**/*.md"],
        "deny": ["**/vendor/**", "**/.env"]
      }
    ],
    "default": "ask"
  }
}
```

### Migration Script

Use the `crush validate-permissions` command to check your configuration:

```bash
# Validate current configuration
crush validate-permissions

# Enable debug mode to see rule evaluation
crush --debug
```

## Best Practices

### 1. Start Restrictive, Then Loosen

Begin with a restrictive policy and add permissions as needed:

```json
{
  "permissions": {
    "rules": [
      {"tool": "view", "allow": ["*.md"]}
    ],
    "default": "deny"
  }
}
```

### 2. Prefer Explicit Patterns Over Broad Access

Instead of:
```json
{"tool": "edit", "allow_all": true}
```

Use:
```json
{
  "tool": "edit",
  "allow": ["src/**/*.go", "docs/**/*.md"],
  "deny": ["**/.env", "**/*.key"]
}
```

### 3. Use Deny Patterns for Sensitive Files

Always add deny patterns for:
- Environment files: `**/.env`, `**/.env.*`
- Key files: `**/*.key`, `**/*.pem`, `**/*.crt`
- Configuration with secrets: `**/*config*.json`
- Backup files: `**/*~`, `**/*.bak`

### 4. Document Your Security Policy

Add comments in your configuration (use a separate documentation file) or maintain a `SECURITY.md` describing your permission strategy.

### 5. Test Your Configuration

Use `--yolo` flag testing with logging:

```bash
# Run with permissive logging to see what would be denied
crush --debug 2>&1 | grep permissions

# Test specific rules
crush validate-permissions
```

### 6. Consider Different Environments

Use different configurations for different contexts:

**Development** (`.crush.json` in project):
```json
{
  "permissions": {
    "default": "ask",
    "rules": [
      {"tool": "bash", "allow": ["go test", "npm test"]}
    ]
  }
}
```

**Production** (`$HOME/.config/crush/crush.json`):
```json
{
  "permissions": {
    "default": "deny",
    "rules": [
      {"tool": "view", "allow": ["*.log", "config/*.yaml"]}
    ]
  }
}
```

### 7. Use Git to Track Changes

Commit your `.crush.json` to version control to track permission changes:

```bash
git add .crush.json
git commit -m "security: restrict edit permissions to source files only"
```

## Security Considerations

### Attack Vectors Addressed

The permission system protects against:

1. **Path Traversal**: Requests like `view ../../../etc/passwd` are blocked
2. **Symlink Exploits**: Attempts to access files via symlinks outside allowed paths
3. **Command Injection**: The bash tool uses proper shell escaping
4. **Information Disclosure**: Restrict viewing of sensitive files
5. **Unauthorized Modifications**: Control which files can be edited or created

### Limitations

The permission system:

- **Does not** prevent denial-of-service attacks (intentional or accidental)
- **Does not** enforce resource limits (disk space, network bandwidth)
- **Does not** provide audit logging (though tool usage is logged)
- **Does** rely on correct rule configuration—misconfiguration can create vulnerabilities

### For Production Environments

Additional considerations:

1. **Run Crush with minimal privileges** (non-root user)
2. **Use restrictive default policies** (`"default": "deny"`)
3. **Review and test all rules** before deployment
4. **Monitor tool usage** via logs in `.crush/logs/`
5. **Regular security audits** of permission configurations
6. **Consider sandboxing** for high-risk operations

## Troubleshooting

### Debug Rule Evaluation

Enable debug mode to see permission decisions:

```bash
crush --debug
```

Look for log entries containing `[permissions]` to see rule evaluation.

### Common Issues

**Issue: Tool is always asking for permission**
- Solution: Check that rules are in the correct tool's section
- Solution: Verify pattern syntax (glob vs regex)
- Solution: Ensure `allow_all` or matching `allow` patterns exist

**Issue: Pattern not matching as expected**
- Solution: Test patterns with `crush validate-permissions`
- Solution: Check for leading/trailing whitespace
- Solution: Verify regex patterns are valid

**Issue: Changes not taking effect**
- Solution: Ensure you're editing the correct config file (check priority order)
- Solution: Restart Crush after config changes
- Solution: Check for JSON syntax errors

### Getting Help

- Run `crush validate-permissions --help` for built-in validation
- Check logs in `./.crush/logs/crush.log` for permission errors
- Review the [README.md](./README.md#allowing-tools) basics
- See [SECURITY.md](./SECURITY.md) for security-related guidance

## API Reference

### PermissionRule Fields

All fields are in JSON format (Go types shown for reference):

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `tool` | string | Yes | Tool name to control |
| `allow_all` | boolean | No | Allow all uses of this tool (overrides patterns) |
| `deny_all` | boolean | No | Deny all uses of this tool (highest precedence) |
| `allow` | []string | No | Patterns to explicitly allow |
| `deny` | []string | No | Patterns to explicitly deny |
| `regex` | boolean | No | Treat patterns as regex (default: false = glob) |
| `message` | string | No | Custom message when denying |

### Permissions Configuration

```json
{
  "permissions": {
    "rules": [ /* PermissionRule objects */ ],
    "default": "ask" | "allow" | "deny"
  }
}
```

### Legacy Format (Still Supported)

```json
{
  "permissions": {
    "allowed_tools": ["tool1", "tool2", /* ... */ ]
  }
}
```

See [MIGRATION.md](./MIGRATION.md) for details on upgrading to rule-based permissions.
