package utils

import (
	"context"
	"github.com/google/uuid"
	"net/http"
)

const CorrelationIdConst = "correlation-id"

func CorrelationIdMiddleware(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		logger := Logger(r.Context())
		defer logger.Sync()

		correlationId := r.Header.Get("X-Trace-Id")
		if correlationId == "" {
			correlationId = uuid.New().String()
		}

		logger.Infow("Adding correlation-id to request context", "correlation-id", correlationId)
		r = r.WithContext(context.WithValue(r.Context(), CorrelationIdConst, correlationId))
		handler.ServeHTTP(rw, r)
	})
}
