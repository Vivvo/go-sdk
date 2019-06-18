package utils

import (
	"context"
	"go.uber.org/zap"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

var logger *zap.Logger

func getLogger() *zap.Logger {
	if logger == nil {
		var config zap.Config
		if os.Getenv("DEBUG") == "true" {
			config = zap.NewDevelopmentConfig()
		} else {
			config = zap.NewProductionConfig()
		}
		config.OutputPaths = []string{"stdout"}
		logger, _ = config.Build()
	}
	return logger
}

// WithRequestId returns a context which knows its request ID
func WithRequestId(ctx context.Context, requestId string) context.Context {
	return context.WithValue(ctx, CorrelationIdConst, requestId)
}

// Logger returns a zap logger with as much context as possible
func Logger(ctx context.Context) *zap.SugaredLogger {
	newLogger := getLogger()
	if ctx != nil {
		if ctxRequestId, ok := ctx.Value(CorrelationIdConst).(string); ok {
			newLogger = newLogger.With(zap.String("correlation-id", ctxRequestId))
		}
	}
	return newLogger.Sugar()
}

func RequestLogger(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		lrw := NewLoggingResponseWriter(rw)

		start := time.Now()
		path := req.URL.Path
		query := req.URL.RawQuery

		logger := Logger(req.Context())

		defer func() {
			end := time.Now()
			latency := end.Sub(start)
			logger.Infow(path,
				"status", lrw.status,
				"method", req.Method,
				"path", path,
				"query", query,
				"ip", ClientIP(req),
				"user-agent", req.UserAgent(),
				"time", end.Format(time.RFC3339),
				"latency", latency,
			)
			logger.Sync()
		}()

		if handler != nil {
			handler.ServeHTTP(lrw, req)
		}
	})

}

// Create our own MyResponseWriter to wrap a standard http.ResponseWriter
// so we can store the status code.
type LoggingResponseWriter struct {
	status int
	http.ResponseWriter
}

func NewLoggingResponseWriter(res http.ResponseWriter) *LoggingResponseWriter {
	// Default the status code to 200 since its implicit if WriteHeader is not called
	return &LoggingResponseWriter{200, res}
}

// Give a way to get the status
func (w LoggingResponseWriter) Status() int {
	return w.status
}

// Satisfy the http.ResponseWriter interface
func (w LoggingResponseWriter) Header() http.Header {
	return w.ResponseWriter.Header()
}

func (w LoggingResponseWriter) Write(data []byte) (int, error) {
	return w.ResponseWriter.Write(data)
}

func (w LoggingResponseWriter) WriteHeader(statusCode int) {
	// Store the status code
	w.status = statusCode

	// Write the status code onward.
	w.ResponseWriter.WriteHeader(statusCode)
}

// ClientIP implements a best effort algorithm to return the real client IP, it parses
// X-Real-IP and X-Forwarded-For in order to work properly with reverse-proxies such us: nginx or haproxy.
// Use X-Forwarded-For before X-Real-Ip as nginx uses X-Real-Ip with the proxy's IP.
func ClientIP(r *http.Request) string {
	if r.Header.Get("X-Forwarded-For") != "" {
		return r.Header.Get("X-Forwarded-For")
	}

	if r.Header.Get("X-Real-Ip") != "" {
		return r.Header.Get("X-Real-Ip")
	}

	if ip, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr)); err == nil {
		return ip
	}

	return ""
}
