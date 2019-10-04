package mtls

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"gopkg.in/resty.v1"
	"io"
	"io/ioutil"
	"log"
	"os"
)

func RetrieveMutualAuthCertificate(signRequest SignRequest) tls.Certificate {
	if _, err := os.Stat("client.crt"); os.IsNotExist(err) {

		privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
		publicKey := &privateKey.PublicKey

		a := x509.MarshalPKCS1PublicKey(publicKey)
		var b io.Writer
		pem.Encode(b, &pem.Block{Type: "CERTIFICATE", Bytes: a })

		response, err := resty.R().
			SetHeader("Content-Type", "application/json").
			SetBody(b).
			SetHeader("cn", signRequest.CommonName).
			SetHeader("Authorization", signRequest.Authorization).
			Post(signRequest.CertificateAuthorityUrl + "/api/v1/sign")

		if err != nil {
			log.Fatal("Error calling CA /api/v1/sign for signing certificate, error: ", err.Error())
		}

		var signedCert ClientCertificate
		json.Unmarshal(response.Body(), &signedCert)

		//Public key
		certOut, err := os.Create("client.crt")
		pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: signedCert.Certificate})

		certOut.Close()

		// Private key
		keyOut, err := os.OpenFile("client.key", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
		keyOut.Close()
	}
	return loadSignedClientCert()

}

func RetrieveCaCertificate(request SignRequest) []byte {
	if _, err := os.Stat("ca.crt"); os.IsNotExist(err) {

		resty.SetTLSClientConfig(&tls.Config{ InsecureSkipVerify: true })  // No CA certificate yet to verify connection
		response, err := resty.R().
			SetHeader("Content-Type", "application/json").
			Get(request.CertificateAuthorityUrl + "/api/v1/cert")

		if err != nil {
			log.Printf("Error calling CA at /api/v1/cert for CA certificate, error: %s", err.Error())
		}

		var caCert ClientCertificate

		json.Unmarshal(response.Body(), &caCert)

		//Public key
		certOut, err := os.Create("ca.crt")
		pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: caCert.Certificate })

		certOut.Close()
	}
	return loadCACert()
}

func loadSignedClientCert() tls.Certificate {
	catls, err := tls.LoadX509KeyPair("client.crt", "client.key")
	if err != nil {
		panic(err)
	}
	return catls
}

func loadCACert() []byte {
	caCert, err := ioutil.ReadFile("ca.crt")
	if err != nil {
		log.Fatal(err)
	}
	return caCert
}

type ClientCertificate struct {
	Certificate []byte `json:"certificate"`
}

type SignRequest struct {
	CommonName              string
	CertificateAuthorityUrl string
	Authorization           string
}
