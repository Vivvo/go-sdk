package utils

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"github.com/Vivvo/go-sdk/mtls"
	"gopkg.in/resty.v1"
	"log"
	"net/url"
	"os"
)

const CorrelationId = "correlation-id"

var consul ConsulServiceInterface
var tlsConfiguration *tls.Config

func InitResty(c ConsulServiceInterface) {
	consul = c
}

func InitRestyWithTLSConfig(c ConsulServiceInterface, tlsConfig *tls.Config) {
	consul = c
	tlsConfiguration = tlsConfig
	resty.SetTLSClientConfig(tlsConfig)
}

func InitRestyTLS(c ConsulServiceInterface, signRequest mtls.SignRequest) {
	consul = c

	if signRequest.Authorization == "" {
		signRequest.Authorization = os.Getenv("VIVVO_CA_AUTHORIZATION_TOKEN")
	}

	if signRequest.CertificateAuthorityUrl == "" {
		signRequest.CertificateAuthorityUrl = os.Getenv("VIVVO_CA_BASEURL")
	}

	if signRequest.CommonName == "" {
		signRequest.CommonName = os.Getenv("VIVVO_CA_COMMONNAME")
	}

	caCert := mtls.RetrieveCaCertificate(signRequest)
	caCertPool, err := x509.SystemCertPool()
	if err != nil {
		log.Printf("Unable to load system cert pool")
		panic(err)
	}
	ok := caCertPool.AppendCertsFromPEM(caCert)
	if !ok {
		log.Printf("Unable to load CA into the cert pool")
	}
	tlsCert, err := mtls.RetrieveMutualAuthCertificate(signRequest, "client.crt", "client.key")
	if err != nil {
		panic(err)
	}

	tlsConfiguration = &tls.Config{
		Certificates: []tls.Certificate{*tlsCert},
		RootCAs:      caCertPool,
		ClientCAs:    caCertPool,
	}
	tlsConfiguration.BuildNameToCertificate()
	resty.SetTLSClientConfig(tlsConfiguration)
}

func Resty(ctx context.Context) *resty.Client {
	logger := Logger(ctx)
	defer logger.Sync()

	client := resty.NewWithClient(resty.GetClient())

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
