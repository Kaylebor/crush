# Permission Rules Quick Reference

## Common Patterns by Use Case

### 🛡️ Conservative (Safe)

Only allow viewing and searching:

```json
{
  "permissions": {
    "rules": [
      {"tool": "view", "allow": ["*.md", "*.txt"]},
      {"tool": "ls", "allow_all": true},
      {"tool": "grep", "allow_all": true},
      {"tool": "glob", "allow_all": true}
    ],
    "default": "deny"
  }
}
```

### 💻 Developer Default

Good for general development work:

```json
{
  "permissions": {
    "rules": [
      {"tool": "view", "allow_all": true},
      {"tool": "ls", "allow_all": true},
      {"tool": "grep", "allow_all": true},
      {"tool": "glob", "allow_all": true},
      {"tool": "sourcegraph", "allow_all": true},
      {"tool": "edit", "allow": ["**/*.{go,js,ts,py,md,json}"], "deny": ["**/.env", "**/*.key"]},
      {"tool": "bash", "allow": ["git", "test", "build", "lint"]}
    ],
    "default": "ask"
  }
}
```

### 🚀 Full Access (Use with Caution)

Trust the agent with most operations:

```json
{
  "permissions": {
    "rules": [
      {"tool": "view", "allow_all": true},
      {"tool": "ls", "allow_all": true},
      {"tool": "grep", "allow_all": true},
      {"tool": "glob", "allow_all": true},
      {"tool": "edit", "allow": ["**/*"], "deny": ["**/.env"]},
      {"tool": "write", "allow": ["**/*"], "deny": ["**/.env"]},
      {"tool": "bash", "allow_all": true}
    ],
    "default": "ask"
  }
}
```

## Tool-by-Tool Examples

### 🔍 Glob (Find Files)

```json
// Basic: Allow globbing any files
{"tool": "glob", "allow_all": true}

// Specific: Only in src/ directory
{"tool": "glob", "allow": ["src/**/*.go"]}

// Multiple patterns
{"tool": "glob", "allow": ["*.go", "*.md", "*.json"]}
```

### 🔍 Grep (Search Content)

```json
// Basic: Allow all file searching
{"tool": "grep", "allow_all": true}

// Note: grep patterns match file content, not filenames
// These are passed as arguments to grep itself
```

### 📄 Ls (List Directories)

```json
// Basic: Allow listing any directory
{"tool": "ls", "allow_all": true}

// Specific directories only
{"tool": "ls", "allow": ["src", "tests", "docs"]}
```

### 👁️ View (Read Files)

```json
// Allow all file viewing
{"tool": "view", "allow_all": true}

// Specific file types
{"tool": "view", "allow": ["**/*.go", "**/*.md", "**/*.json", "**/*.txt"]}

// Exclude sensitive files
{
  "tool": "view",
  "allow": ["**/*"],
  "deny": ["**/.env", "**/*.key", "**/*.pem", "**/*secret*"]
}
```

### ✏️ Edit (Modify Files)

```json
// Allow editing source files
{
  "tool": "edit",
  "allow": ["src/**/*.go", "tests/**/*.go"],
  "deny": ["**/vendor/**"]
}

// Documentation only
{
  "tool": "edit",
  "allow": ["**/*.md", "**/*.rst", "**/*.txt"],
  "deny": ["README.md"]
}

// Web development
{
  "tool": "edit",
  "allow": ["src/**/*.{js,ts,jsx,tsx}", "src/**/*.css", "**/*.md"]
}
```

### ✏️ Write (Create Files)

```json
// Generic write permissions
{
  "tool": "write",
  "allow": ["**/*.{go,md,json}"],
  "deny": ["**/.env"]
}

// Only in specific directories
{
  "tool": "write",
  "allow": ["src/**/*", "tests/**/*", "docs/**/*"],
  "deny": ["**/vendor/**"]
}
```

### 👨‍💻 Bash (Run Commands)

```json
// Git commands only
{
  "tool": "bash",
  "allow": ["git"]
}

// Testing commands
{
  "tool": "bash",
  "allow": ["npm test", "go test", "pytest", "cargo test"]
}

// Build tools
{
  "tool": "bash",
  "allow": ["npm run build", "go build", "make", "cargo build"]
}

// Safe system commands
{
  "tool": "bash",
  "allow": ["ls", "pwd", "which", "git", "test"]
}
```

**⚠️ Important**: Some commands (curl, ssh, sudo, apt, etc.) are **always blocked** even with `allow_all: true`. Use explicit patterns to override: `{"allow": ["curl https://api.github.com/*"]}` (see main PERMISSIONS.md for details)

### 📥 Download (From URLs)

```json
// Allow all downloads (caution!)
{"tool": "download", "allow_all": true}

// Specific domains only
{
  "tool": "download",
  "allow": ["https://github.com/*", "https://raw.githubusercontent.com/*"]
}
```

### 🌐 Fetch / Web_Fetch (Web Content)

```json
// Allow fetching web content
{"tool": "fetch", "allow_all": true}

// Specific sites only
{
  "tool": "fetch",
  "allow": ["https://api.github.com/*", "https://docs.rs/*"]
}
```

### 🤖 Agent (Sub-agents)

```json
// Allow using sub-agents
{"tool": "agent", "allow_all": true}

// Consider restricting in sensitive environments
{"tool": "agent", "deny_all": true}
```

### 🔧 Specialized Tools

```json
// Sourcegraph code search
{"tool": "sourcegraph", "allow_all": true}

// Find references in code
{"tool": "references", "allow_all": true}

// Multiple file edits
{"tool": "multiedit", "allow": ["**/*.{go,js,md}"]}
```

## Pattern Wildcards Guide

| Pattern | Matches | Example |
|---------|---------|---------|
| `*` | Any characters within a directory | `*.go` → `main.go`, `test.go` |
| `**` | Zero or more directories (recursive) | `**/*.go` → `src/main.go`, `test.go` |
| `?` | Single character | `file?.txt` → `file1.txt` |
| `[abc]` | Any character in set | `file[123].txt` → `file1.txt`, `file2.txt` |
| `[a-z]` | Character in range | `file[a-c].txt` → `filea.txt`, `fileb.txt` |
| `!` | Negation (in some contexts) | `!**/.env` (use deny instead) |

## Common File Patterns

```json
// Source code
"**/*.{go,js,ts,jsx,tsx,py,rs,java,c,cpp,h,hpp}"

// Configuration
"**/*.{json,yaml,yml,toml,xml,ini}"

// Documentation
"**/*.{md,rst,txt,adoc}"

// Web assets
"**/*.{html,css,scss,less,js}"

// Build files
"**/{Makefile,makefile,CMakeLists.txt,*.mk}"

// Project files
"**/{package.json,go.mod,requirements.txt,Cargo.toml}"

// Test files
"**/*{test,spec}*"
```

## Quick Decision Tree

**I want to allow reading files:**
→ Use `"tool": "view"` with file patterns

**I want to allow searching code:**
→ Use `"tool": "grep"` with `allow_all: true`

**I want to allow running tests:**
→ Use `"tool": "bash"` with `["npm test", "go test"]`

**I want to allow editing code but not configs:**
→ Use `"tool": "edit"` with `allow: ["**/*.go"]` and `deny: ["**/.env"]`

**I want to be very restrictive:**
→ Set `"default": "deny"` and only add specific `allow` rules

**I want to trust Crush completely:**
→ Set `"default": "allow"` (⚠️ not recommended)

## Testing Your Rules

Validate your configuration:

```bash
# Check syntax
crush validate-permissions

# Test with debug logging
crush --debug

# Monitor decisions in logs
tail -f ./.crush/logs/crush.log | grep permissions
```

For more details, see [PERMISSIONS.md](./PERMISSIONS.md).
