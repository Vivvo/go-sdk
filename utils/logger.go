package utils

import (
	"bufio"
	"context"
	"fmt"
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
		config.Encoding = "json"
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

		if !strings.Contains(path, "healthz") {
			defer func() {
				end := time.Now()
				latency := end.Sub(start)
				logger.Infow(path,
					"status", lrw.Status(),
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
		}

		if handler != nil {
			handler.ServeHTTP(lrw, req)
		}
	})

}

// Create our own MyResponseWriter to wrap a standard http.ResponseWriter
// so we can store the status code.
type LoggingResponseWriter struct {
	status int
	size   int
	http.ResponseWriter
}

type loggingResponseWriter interface {
	commonLoggingResponseWriter
	http.Pusher
}

type commonLoggingResponseWriter interface {
	http.ResponseWriter
	http.Flusher
	Status() int
	Size() int
}

func NewLoggingResponseWriter(w http.ResponseWriter) loggingResponseWriter {
	// Default the status code to 200 since its implicit if WriteHeader is not called
	return makeLogger(w)
}

func makeLogger(w http.ResponseWriter) loggingResponseWriter {
	var logger loggingResponseWriter = &LoggingResponseWriter{status: http.StatusOK, ResponseWriter: w}
	if _, ok := w.(http.Hijacker); ok {
		logger = &hijackLogger{LoggingResponseWriter{status: http.StatusOK, ResponseWriter: w}}
	}
	h, ok1 := logger.(http.Hijacker)
	c, ok2 := w.(http.CloseNotifier)
	if ok1 && ok2 {
		return hijackCloseNotifier{logger, h, c}
	}
	if ok2 {
		return &closeNotifyWriter{logger, c}
	}
	return logger
}

type closeNotifyWriter struct {
	loggingResponseWriter
	http.CloseNotifier
}

type hijackCloseNotifier struct {
	loggingResponseWriter
	http.Hijacker
	http.CloseNotifier
}

type hijackLogger struct {
	LoggingResponseWriter
}

func (l *hijackLogger) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h := l.ResponseWriter.(http.Hijacker)
	conn, rw, err := h.Hijack()
	if err == nil && l.status == 0 {
		// The status will be StatusSwitchingProtocols if there was no error and
		// WriteHeader has not been called yet
		l.status = http.StatusSwitchingProtocols
	}
	return conn, rw, err
}

// Give a way to get the status
func (l LoggingResponseWriter) Status() int {
	return l.status
}

// Satisfy the http.ResponseWriter interface
func (l LoggingResponseWriter) Header() http.Header {
	return l.ResponseWriter.Header()
}

func (l *LoggingResponseWriter) Write(b []byte) (int, error) {
	size, err := l.ResponseWriter.Write(b)
	l.size += size
	return size, err
}

func (l *LoggingResponseWriter) WriteHeader(s int) {
	l.ResponseWriter.WriteHeader(s)
	l.status = s
}

func (l *LoggingResponseWriter) Size() int {
	return l.size
}

func (l *LoggingResponseWriter) Flush() {
	f, ok := l.ResponseWriter.(http.Flusher)
	if ok {
		f.Flush()
	}
}

func (l *LoggingResponseWriter) Push(target string, opts *http.PushOptions) error {
	p, ok := l.ResponseWriter.(http.Pusher)
	if !ok {
		return fmt.Errorf("responseLogger does not implement http.Pusher")
	}
	return p.Push(target, opts)
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
