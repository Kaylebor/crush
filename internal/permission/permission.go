package permission

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"

	"github.com/charmbracelet/crush/internal/config"
	"github.com/charmbracelet/crush/internal/csync"
	"github.com/charmbracelet/crush/internal/pubsub"
	"github.com/charmbracelet/crush/internal/ruleengine"
	"github.com/google/uuid"
)

var (
	ErrorPermissionDenied         = errors.New("user denied permission")
	ErrorBlockedBySafetyPolicy    = errors.New("command blocked by safety policy")
	ErrorBlockedByRules           = errors.New("command blocked by security rules")
)

type CreatePermissionRequest struct {
	SessionID        string `json:"session_id"`
	ToolCallID       string `json:"tool_call_id"`
	ToolName         string `json:"tool_name"`
	Description      string `json:"description"`
	Action           string `json:"action"`
	Params           any    `json:"params"`
	Path             string `json:"path"`
	IsInteractiveCLI bool   `json:"is_interactive_cli"` // True if Crush parent is running in TUI mode
}

// PermissionResult contains detailed information about a permission request result
type PermissionResult struct {
	Allowed              bool
	ExplicitAllow        bool // True if the allow came from an explicit pattern match (not allow_all)
	SafetyBlock          bool // True if command was blocked by safety-critical detection (non-bypassable)
	NonInteractiveDenial bool // True if denied due to non-interactive mode (not a user decision)
}

type PermissionNotification struct {
	ToolCallID string `json:"tool_call_id"`
	Granted    bool   `json:"granted"`
	Denied     bool   `json:"denied"`
}

type PermissionRequest struct {
	ID          string `json:"id"`
	SessionID   string `json:"session_id"`
	ToolCallID  string `json:"tool_call_id"`
	ToolName    string `json:"tool_name"`
	Description string `json:"description"`
	Action      string `json:"action"`
	Params      any    `json:"params"`
	Path        string `json:"path"`
}

type Service interface {
	pubsub.Suscriber[PermissionRequest]
	GrantPersistent(permission PermissionRequest)
	Grant(permission PermissionRequest)
	Deny(permission PermissionRequest)
	Request(opts CreatePermissionRequest) (bool, error)
	RequestWithDetails(opts CreatePermissionRequest) PermissionResult
	AutoApproveSession(sessionID string)
	SetSkipRequests(skip bool)
	SkipRequests() bool
	SubscribeNotifications(ctx context.Context) <-chan pubsub.Event[PermissionNotification]
}

type permissionService struct {
	*pubsub.Broker[PermissionRequest]

	notificationBroker    *pubsub.Broker[PermissionNotification]
	workingDir            string
	sessionPermissions    []PermissionRequest
	sessionPermissionsMu  sync.RWMutex
	pendingRequests       *csync.Map[string, chan bool]
	autoApproveSessions   map[string]bool
	autoApproveSessionsMu sync.RWMutex
	skip                  bool
	allowedTools          []string
	config                *config.Config

	// used to make sure we only process one request at a time
	requestMu     sync.Mutex
	activeRequest *PermissionRequest

	// AST-based safety checker for bash commands
	astChecker *ASTSafetyChecker
}

// isInteractive returns true if Crush is running in TUI mode with interactive prompts
// This is passed from the parent process, not detected from subprocess TTY state
func (s *permissionService) isInteractive() bool {
	// Default to non-interactive if we don't have a request context
	// The actual interactive state should be set in CreatePermissionRequest.IsInteractiveCLI
	return false
}

func (s *permissionService) GrantPersistent(permission PermissionRequest) {
	s.notificationBroker.Publish(pubsub.CreatedEvent, PermissionNotification{
		ToolCallID: permission.ToolCallID,
		Granted:    true,
	})
	respCh, ok := s.pendingRequests.Get(permission.ID)
	if ok {
		respCh <- true
	}

	s.sessionPermissionsMu.Lock()
	s.sessionPermissions = append(s.sessionPermissions, permission)
	s.sessionPermissionsMu.Unlock()
}

func (s *permissionService) Grant(permission PermissionRequest) {
	s.notificationBroker.Publish(pubsub.CreatedEvent, PermissionNotification{
		ToolCallID: permission.ToolCallID,
		Granted:    true,
	})
	respCh, ok := s.pendingRequests.Get(permission.ID)
	if ok {
		respCh <- true
	}
}

func (s *permissionService) Deny(permission PermissionRequest) {
	s.notificationBroker.Publish(pubsub.CreatedEvent, PermissionNotification{
		ToolCallID: permission.ToolCallID,
		Granted:    false,
		Denied:     true,
	})
	respCh, ok := s.pendingRequests.Get(permission.ID)
	if ok {
		respCh <- false
	}
}

// extractPermissionRequest converts CreatePermissionRequest.Params into ruleengine.PermissionRequest
func (s *permissionService) extractPermissionRequest(opts CreatePermissionRequest) ruleengine.PermissionRequest {
	req := ruleengine.PermissionRequest{
		SessionID: opts.SessionID,
		Tool:      opts.ToolName,
		Action:    opts.Action,
		Path:      opts.Path,
	}

	// Extract tool-specific fields from Params using type assertions
	if opts.Params == nil {
		return req
	}

	switch opts.ToolName {
	case "bash":
		// Check for Command field in bash params
		if params, ok := opts.Params.(map[string]interface{}); ok {
			if cmd, exists := params["command"]; exists {
				if cmdStr, ok := cmd.(string); ok {
					req.Command = cmdStr
				}
			}
		}
	case "edit", "write", "view":
		// Check for FilePath field
		if params, ok := opts.Params.(map[string]interface{}); ok {
			if path, exists := params["file_path"]; exists {
				if pathStr, ok := path.(string); ok {
					req.Path = pathStr
				}
			}
		}
	case "download":
		// Check for URL field
		if params, ok := opts.Params.(map[string]interface{}); ok {
			if url, exists := params["url"]; exists {
				if urlStr, ok := url.(string); ok {
					req.URL = urlStr
				}
			}
		}
	case "grep", "glob":
		// Check for Pattern field
		if params, ok := opts.Params.(map[string]interface{}); ok {
			if pattern, exists := params["pattern"]; exists {
				if patternStr, ok := pattern.(string); ok {
					req.Pattern = patternStr
				}
			}
		}
	}

	return req
}

func (s *permissionService) Request(opts CreatePermissionRequest) (bool, error) {
	result := s.RequestWithDetails(opts)
	
	if result.Allowed {
		return true, nil
	}
	
	// Permission was denied - determine why
	if result.SafetyBlock {
		return false, ErrorBlockedBySafetyPolicy
	}
	if result.NonInteractiveDenial {
		return false, fmt.Errorf("operation requires interactive approval but running in non-interactive mode")
	}
	
	// Check if blocked by rules (either explicit deny or default effect = deny)
	if s.config != nil && s.config.Permissions != nil {
		if s.config.Permissions.DefaultEffect == ruleengine.Deny {
			return false, ErrorBlockedByRules
		}
		// Check if a specific deny rule matched
		ruleReq := s.extractPermissionRequest(opts)
		ruleSet := s.config.Permissions.RuleSet()
		if ruleSet != nil && ruleSet.IsCompiled() {
			_, matchedRule := ruleengine.EvaluateRules(ruleSet, ruleReq)
			if matchedRule != nil {
				// A rule matched and it wasn't an allow (since result.Allowed = false)
				return false, ErrorBlockedByRules
			}
		}
	}
	
	// User explicitly denied or no approval obtained
	return false, ErrorPermissionDenied
}

func (s *permissionService) AutoApproveSession(sessionID string) {
	s.autoApproveSessionsMu.Lock()
	s.autoApproveSessions[sessionID] = true
	s.autoApproveSessionsMu.Unlock()
}

func (s *permissionService) SubscribeNotifications(ctx context.Context) <-chan pubsub.Event[PermissionNotification] {
	return s.notificationBroker.Subscribe(ctx)
}

func (s *permissionService) SetSkipRequests(skip bool) {
	s.skip = skip
}

func (s *permissionService) SkipRequests() bool {
	return s.skip
}

func NewPermissionService(workingDir string, skip bool, allowedTools []string, cfg *config.Config) Service {
	return &permissionService{
		Broker:              pubsub.NewBroker[PermissionRequest](),
		notificationBroker:  pubsub.NewBroker[PermissionNotification](),
		workingDir:          workingDir,
		sessionPermissions:  make([]PermissionRequest, 0),
		autoApproveSessions: make(map[string]bool),
		skip:                skip,
		allowedTools:        allowedTools,
		config:              cfg,
		pendingRequests:     csync.NewMap[string, chan bool](),
		astChecker:          NewASTSafetyChecker(),
	}
}

// RequestWithDetails checks permission and returns detailed result including explicit allow detection
func (s *permissionService) RequestWithDetails(opts CreatePermissionRequest) PermissionResult {
	result := PermissionResult{
		Allowed:       false,
		ExplicitAllow: false,
	}

	// Safety-critical check (TRULY NON-BYPASSABLE)
	// This runs before skip mode to prevent catastrophic commands.
	// There are no legitimate use cases for these commands, even in yolo mode.
	if opts.ToolName == "bash" {
		command := extractCommandFromParams(opts.Params)
		if s.astChecker.IsCritical(command) {
			result.SafetyBlock = true
			result.Allowed = false
			return result
		}
	}

	// Skip mode check (for non-critical commands only)
	if s.skip {
		result.Allowed = true
		return result
	}

	// Check legacy allowlist
	// Backward compatibility: check hardcoded allowedTools from legacy config format
	commandKey := opts.ToolName + ":" + opts.Action
	if slices.Contains(s.allowedTools, commandKey) || slices.Contains(s.allowedTools, opts.ToolName) {
		result.Allowed = true
		return result
	}

	// Check auto-approve sessions
	s.autoApproveSessionsMu.RLock()
	autoApprove := s.autoApproveSessions[opts.SessionID]
	s.autoApproveSessionsMu.RUnlock()

	if autoApprove {
		result.Allowed = true
		return result
	}

	// Check using rule engine
	if s.config != nil && s.config.Permissions != nil {
		ruleReq := s.extractPermissionRequest(opts)
		ruleSet := s.config.Permissions.RuleSet()

		if ruleSet != nil && ruleSet.IsCompiled() {
			// Check for explicit allow patterns first
			result.ExplicitAllow = ruleSet.MatchesExplicitAllow(opts.ToolName, extractCommandFromParams(opts.Params))

			// Evaluate rules normally
			ruleResult, matchedRule := ruleengine.EvaluateRules(ruleSet, ruleReq)
			if matchedRule != nil {
				result.Allowed = (ruleResult == ruleengine.Allow)
				return result
			}

			// No rule matched, use default effect
			defaultEffect := s.config.Permissions.DefaultEffect
			switch defaultEffect {
			case ruleengine.Allow:
				result.Allowed = true
				return result
			case ruleengine.Deny:
				result.Allowed = false
				return result
			}
			// defaultEffect is "ask" - fall through to manual approval
		}
	}

	// If the parent CLI is not interactive, we cannot wait for user input
	// Only apply this check if we have a configured permission system
	// and no one is subscribed to handle manual approval
	if !opts.IsInteractiveCLI && s.config != nil && s.config.Permissions != nil {
		// In non-interactive mode with configured permissions, deny for security
		// This prevents hangs in scripts/automation when default effect is "ask"
		result.NonInteractiveDenial = true
		result.Allowed = false
		return result
	}

	// Fall back to manual approval
	permission := PermissionRequest{
		ID:          uuid.New().String(),
		Path:        dirFromPath(opts.Path, s.workingDir),
		SessionID:   opts.SessionID,
		ToolCallID:  opts.ToolCallID,
		ToolName:    opts.ToolName,
		Description: opts.Description,
		Action:      opts.Action,
		Params:      opts.Params,
	}

	s.requestMu.Lock()
	defer s.requestMu.Unlock()

	// Check persistent permissions
	for _, p := range s.sessionPermissions {
		if p.ToolName == permission.ToolName && p.Action == permission.Action && p.SessionID == permission.SessionID && p.Path == permission.Path {
			// Persistent permission found, auto-approve
			result.Allowed = true
			return result
		}
	}

	s.activeRequest = &permission
	defer func() { s.activeRequest = nil }()

	respCh := make(chan bool, 1)
	s.pendingRequests.Set(permission.ID, respCh)
	defer s.pendingRequests.Del(permission.ID)

	// Publish the request
	s.Publish(pubsub.CreatedEvent, permission)

	// Wait for response from UI (blocks until user responds)
	result.Allowed = <-respCh
	return result
}

// extractCommandFromParams extracts command string from permission request params
func extractCommandFromParams(params any) string {
	if params == nil {
		return ""
	}

	// Check for Command field in bash params
	if p, ok := params.(map[string]interface{}); ok {
		if cmd, exists := p["command"]; exists {
			if cmdStr, ok := cmd.(string); ok {
				return cmdStr
			}
		}
	}

	return ""
}

// dirFromPath extracts directory from path
func dirFromPath(path, workingDir string) string {
	if path == "" || path == "." {
		return workingDir
	}

	fileInfo, err := os.Stat(path)
	if err == nil {
		if fileInfo.IsDir() {
			return path
		}
		return filepath.Dir(path)
	}

	return path
}
