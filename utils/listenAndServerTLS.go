package utils

import (
	"crypto/tls"
	"crypto/x509"
	"github.com/Vivvo/go-sdk/mtls"
	"log"
	"net/http"
	"os"
)

func ListenAndServeTLS(port string, certName, certKey string, handler http.Handler) error {
	var signRequest mtls.SignRequest
	if os.Getenv("SERVICE_NAME") != "" {
		signRequest = mtls.BuildSignRequest()
	}

	if signRequest.Authorization == "" {
		signRequest.Authorization = os.Getenv("VIVVO_CA_AUTHORIZATION_TOKEN")
	}
	if signRequest.CertificateAuthorityUrl == "" {
		signRequest.CertificateAuthorityUrl = os.Getenv("VIVVO_CA_BASEURL")
	}
	if signRequest.CommonName == "" {
		signRequest.CommonName = os.Getenv("VIVVO_CA_COMMONNAME")
	}

	log.Printf("Creating a new CA for this environment")
	caCert := mtls.RetrieveCaCertificate(signRequest)
	caCertPool := x509.NewCertPool()
	ok := caCertPool.AppendCertsFromPEM(caCert)
	if !ok {
		log.Printf("Unable to load CA into the cert pool")
	}
	tlsCert, err := mtls.RetrieveMutualAuthCertificate(signRequest, certName, certKey)
	if err == nil {
		tlsConfig := &tls.Config{
			ClientCAs:    caCertPool,
			Certificates: []tls.Certificate{*tlsCert},
			ClientAuth:   tls.RequireAndVerifyClientCert,
		}
		tlsConfig.BuildNameToCertificate()

		server := &http.Server{
			Addr:      ":" + port,
			TLSConfig: tlsConfig,
			Handler:   handler,
		}

		log.Printf("CA Successfully Created")
		log.Printf("Starting up on port %s", port)
		return server.ListenAndServeTLS(certName, certKey) //private cert
	} else {
		panic(err)
	}
}
