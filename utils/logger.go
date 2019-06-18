package utils

import (
	"context"
	"go.uber.org/zap"
	"os"
)

var logger *zap.Logger

func init() {
	var config zap.Config
	if os.Getenv("DEBUG") == "true" {
		config = zap.NewDevelopmentConfig()
	} else {
		config = zap.NewProductionConfig()
	}
	config.OutputPaths = []string{"stdout"}
	logger, _ = config.Build()
}

// WithRequestId returns a context which knows its request ID
func WithRequestId(ctx context.Context, requestId string) context.Context {
	return context.WithValue(ctx, CorrelationIdConst, requestId)
}

// Logger returns a zap logger with as much context as possible
func Logger(ctx context.Context) *zap.SugaredLogger {
	newLogger := logger
	if ctx != nil {
		if ctxRequestId, ok := ctx.Value(CorrelationIdConst).(string); ok {
			newLogger = newLogger.With(zap.String("correlation-id", ctxRequestId))
		}
	}
	return newLogger.Sugar()
}
