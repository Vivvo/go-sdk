package utils

import (
	"context"
	"gopkg.in/resty.v1"
	"net/url"
)

const CorrelationId = "correlation-id"

var consul ConsulServiceInterface

func InitResty(c ConsulServiceInterface) {
	consul = c
}

func Resty(ctx context.Context) *resty.Client {
	logger := Logger(ctx)
	defer logger.Sync()

	client := resty.New()

	client.OnBeforeRequest(func(c *resty.Client, r *resty.Request) error {
		logger.Infow("Outbound Request", "method", r.Method, "url", r.URL)

		if ctxRequestId, ok := ctx.Value(CorrelationId).(string); ok {
			r.Header.Add("X-Trace-Id", ctxRequestId)
		}

		u, err := url.Parse(r.URL)
		if err != nil {
			return err
		}

		sdHost := consul.GetService(u.Host)

		u.Host = sdHost
		r.URL = u.String()
		return nil
	})

	client.OnAfterResponse(func(c *resty.Client, r *resty.Response) error {
		logger.Infow("Outbound Response", "method", r.Request.Method, "url", r.Request.URL, "statusCode", r.StatusCode(), "duration", r.Time())
		if r.StatusCode() > 299 {
			logger.Info("Outbound Response", "responseBody", string(r.Body()))
		}
		return nil
	})

	return client
}
