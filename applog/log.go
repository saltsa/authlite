package applog

import (
	"context"
	"io"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"

	_ "github.com/joho/godotenv/autoload"
	"github.com/saltsa/authlite/internal/constants"
)

var logger *log.Logger
var slogger *slog.Logger

var currentLogLevel = &slog.LevelVar{}

var lock sync.Mutex

type AuditOperation string

const (
	AuditNewChallenge AuditOperation = "LOGIN_STARTED"
	AuditLoginfailed  AuditOperation = "LOGIN_FAILED"
	AuditLoginSuccess AuditOperation = "LOGIN_SUCCESS"
)

func init() {
	SetupLogging()
}

func SetupLogging() {
	lock.Lock()
	defer lock.Unlock()
	if logger != nil && slogger != nil {
		return
	}
	currentLogLevel.UnmarshalText([]byte(os.Getenv("LOG_LEVEL")))

	handler := newLogHandler(os.Stderr, &slog.HandlerOptions{
		Level: currentLogLevel,
	})
	slogger = slog.New(handler)
	logger = slog.NewLogLogger(handler, slog.LevelDebug)
	slog.SetDefault(slogger)

	slog.Info("logging initialized", "currentLevel", currentLogLevel)

	// support dynamic level changes with SIGUSR1 signal
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGUSR1)

	go func() {
		for range sigs {
			changeLogLevel()
		}
	}()
}

func changeLogLevel() {
	var newLevel slog.Level
	if currentLogLevel.Level() == slog.LevelDebug {
		newLevel = slog.LevelInfo
	} else {
		newLevel = slog.LevelDebug
	}
	slog.Info("changing log levels", "newLevel", newLevel, "oldLevel", currentLogLevel)
	currentLogLevel.Set(newLevel)
}

func GetLogger() *log.Logger {
	if logger == nil {
		SetupLogging()
	}
	return logger
}

func LogAuditEvent(ctx context.Context, op AuditOperation, msg string, args ...any) {
	args = append(args, auditAttrs(op))
	slogger.InfoContext(ctx, msg, args...)
}

func auditAttrs(op AuditOperation) slog.Attr {
	attr := slog.String("event", string(op))
	return attr
}

type appLogHandler struct {
	*slog.JSONHandler
}

func newLogHandler(w io.Writer, opts *slog.HandlerOptions) slog.Handler {
	parent := slog.NewJSONHandler(w, opts)
	return &appLogHandler{parent}
}

func (h *appLogHandler) Handle(ctx context.Context, r slog.Record) error {
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
