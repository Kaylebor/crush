package tools

import (
	"context"
)

type (
	sessionIDContextKey     string
	messageIDContextKey     string
	isInteractiveCLIContextKey string
)

const (
	SessionIDContextKey        sessionIDContextKey     = "session_id"
	MessageIDContextKey        messageIDContextKey     = "message_id"
	IsInteractiveCLIContextKey isInteractiveCLIContextKey = "is_interactive_cli"
)

func GetSessionFromContext(ctx context.Context) string {
	sessionID := ctx.Value(SessionIDContextKey)
	if sessionID == nil {
		return ""
	}
	s, ok := sessionID.(string)
	if !ok {
		return ""
	}
	return s
}

func GetMessageFromContext(ctx context.Context) string {
	messageID := ctx.Value(MessageIDContextKey)
	if messageID == nil {
		return ""
	}
	s, ok := messageID.(string)
	if !ok {
		return ""
	}
	return s
}

func GetIsInteractiveFromContext(ctx context.Context) bool {
	isInteractive := ctx.Value(IsInteractiveCLIContextKey)
	if isInteractive == nil {
		return false
	}
	b, ok := isInteractive.(bool)
	if !ok {
		return false
	}
	return b
}
