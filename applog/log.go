package applog

import (
	"context"
	"fmt"
	"io"
	"log"
	"log/slog"
	"os"

	"github.com/saltsa/authlite/internal/constants"
)

var logger *log.Logger
var slogger *slog.Logger

type AuditOperation string

const (
	AuditNewChallenge AuditOperation = "LOGIN_STARTED"
	AuditLoginfailed  AuditOperation = "LOGIN_FAILED"
	AuditLoginSuccess AuditOperation = "LOGIN_SUCCESS"
)

func init() {
	// handler := slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
	// 	Level: slog.LevelDebug,
	// })

	handler := newJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})

	slogger = slog.New(handler)
	logger = slog.NewLogLogger(handler, slog.LevelDebug)

	slog.SetDefault(slogger)
	logger.Printf("logging initialized")
}

func GetLogger() *log.Logger {
	return logger
}

func LogAuditEvent(ctx context.Context, op AuditOperation, msg string, args ...any) {
	args = append(args, auditAttrs(op))
	slog.InfoContext(ctx, msg, args...)
}

func auditAttrs(op AuditOperation) slog.Attr {
	attr := slog.String("operation", string(op))
	return attr
}

func newJSONHandler(w io.Writer, opts *slog.HandlerOptions) *jsonHandler {
	parent := slog.NewJSONHandler(w, opts)
	return &jsonHandler{*parent}
}

type jsonHandler struct {
	slog.JSONHandler
}

func (h *jsonHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	fmt.Println("with attrs")
	return h.JSONHandler.WithAttrs(attrs)
}

func (h *jsonHandler) Handle(ctx context.Context, r slog.Record) error {
	r.AddAttrs(getAdditionalAttrs(ctx)...)
	return h.JSONHandler.Handle(ctx, r)
}

func getAdditionalAttrs(ctx context.Context) []slog.Attr {
	ret := []slog.Attr{}

	if ip, ok := ctx.Value(constants.CtxClientIP).(string); ok {
		ret = append(ret, slog.String("ip", ip))
	}

	if authID, ok := ctx.Value(constants.CtxAuthID).(string); ok {
		ret = append(ret, slog.String("authId", authID))
	}

	return ret
}
