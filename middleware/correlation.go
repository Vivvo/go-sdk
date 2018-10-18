package middleware

import (
	"context"
	"github.com/Vivvo/vivvo-privacy-proxy/src/utils"
	"github.com/satori/go.uuid"
	"net/http"
)

const CorrelationIdConst = "correlation-id"

func CorrelationId(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		logger := utils.Logger(r.Context())
		defer logger.Sync()

		correlationId := r.Header.Get("X-Trace-Id")
		if correlationId == "" {
			correlationId = uuid.Must(uuid.NewV4()).String()
		}

		logger.Infow("Adding correlation-id to request context", "correlation-id", correlationId)
		r = r.WithContext(context.WithValue(r.Context(), CorrelationIdConst, correlationId))
		handler.ServeHTTP(rw, r)
	})
}
