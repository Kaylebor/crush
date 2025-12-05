package permission

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestPermissionService_CommandPatternSessionGrants verifies that session grants
// are command-specific and don't allow other commands
func TestPermissionService_CommandPatternSessionGrants(t *testing.T) {
	service := NewPermissionService("/tmp", false, []string{}, nil)
	sessionID := "test-session"

	// User grants permission for session for 'git commit'
	grantPerm := PermissionRequest{
		ToolName:       "bash",
		Action:         "execute",
		SessionID:      sessionID,
		Path:           "/tmp",
		CommandPattern: "git commit",  // This is what we expect to be stored
	}
	service.GrantPersistent(grantPerm)

	// Now request 'git commit' again - should auto-approve
	result2 := service.RequestWithDetails(CreatePermissionRequest{
		SessionID:   sessionID,
		ToolName:    "bash",
		Action:      "execute",
		Description: "Execute command: git commit",
		Params:      map[string]any{"command": "git commit"},
		Path:        "/tmp",
	})

	require.True(t, result2.Allowed, "git commit should be auto-approved from session grant")
	require.False(t, result2.SafetyBlock)

	// Now request 'git push' - should NOT auto-approve
	result3 := service.RequestWithDetails(CreatePermissionRequest{
		SessionID:   sessionID,
		ToolName:    "bash",
		Action:      "execute",
		Description: "Execute command: git push",
		Params:      map[string]any{"command": "git push"},
		Path:        "/tmp",
	})

	require.False(t, result3.Allowed, "git push should NOT be auto-approved from git commit session grant")
	require.False(t, result3.SafetyBlock)
}

// TestPermissionService_SimpleCommandSessionGrants verifies that simple commands
// like 'ls' are auto-approved for all flags
func TestPermissionService_SimpleCommandSessionGrants(t *testing.T) {
	service := NewPermissionService("/tmp", false, []string{}, nil)
	sessionID := "test-session"

	// Grant permission for 'ls'
	lsGrant := PermissionRequest{
		ToolName:       "bash",
		Action:         "execute",
		SessionID:      sessionID,
		Path:           "/tmp",
		CommandPattern: "ls", // Simple command pattern
	}
	service.GrantPersistent(lsGrant)

	// Now request 'ls -la' - should auto-approve (same command pattern)
	result2 := service.RequestWithDetails(CreatePermissionRequest{
		SessionID:   sessionID,
		ToolName:    "bash",
		Action:      "execute",
		Description: "Execute command: ls -la",
		Params:      map[string]any{"command": "ls -la"},
		Path:        "/tmp",
	})

	require.True(t, result2.Allowed, "ls -la should be auto-approved from ls session grant")
	require.False(t, result2.SafetyBlock)
}
