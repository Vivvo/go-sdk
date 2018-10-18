package utils

import (
	"context"
	"github.com/Vivvo/go-sdk/middleware"
	"go.uber.org/zap"
)

var logger *zap.Logger

func init() {
	config := zap.NewProductionConfig()
	config.OutputPaths = []string{"stdout"}
	logger, _ = config.Build()
}

// WithRequestId returns a context which knows its request ID
func WithRequestId(ctx context.Context, requestId string) context.Context {
	return context.WithValue(ctx, middleware.CorrelationIdConst, requestId)
}

// Logger returns a zap logger with as much context as possible
func Logger(ctx context.Context) *zap.SugaredLogger {
	newLogger := logger
	if ctx != nil {
		if ctxRequestId, ok := ctx.Value(middleware.CorrelationIdConst).(string); ok {
			newLogger = newLogger.With(zap.String("correlation-id", ctxRequestId))
		}
	}
	return newLogger.Sugar()
}
