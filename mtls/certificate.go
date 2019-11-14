package mtls

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"gopkg.in/resty.v1"
	"io/ioutil"
	"log"
	"os"
)

func RetrieveMutualAuthCertificate(signRequest SignRequest, certName string, certKey string) (*tls.Certificate,error) {
	if _, err := os.Stat(certName); os.IsNotExist(err) {
		var signedCert ClientCertificate

		certPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			log.Printf("Unable to generate RSA key: %s", err.Error())
			return nil,err
		}

		response, err := resty.R().
			SetBody(x509.MarshalPKCS1PublicKey(&certPrivKey.PublicKey)).
			SetHeader("Content-Type", "application/json").
			SetHeader("cn", signRequest.CommonName).
			SetHeader("Authorization", signRequest.Authorization).
			Post(signRequest.CertificateAuthorityUrl + "/api/v1/sign")

		if err != nil {
			log.Fatal("Error calling CA /api/v1/sign for signing certificate, error: ", err.Error())
			return nil,err
		}


		json.Unmarshal(response.Body(), &signedCert)

		//Public key
		certOut, err := os.Create(certName)
		if err != nil {
			log.Printf("Unable to create client cert file: %s", err.Error())
			return nil,err
		}

		err = pem.Encode(certOut, &pem.Block{
			Type:    "CERTIFICATE",
			Bytes:   signedCert.Certificate,
			Headers: nil,
		})

		if err != nil {
			log.Printf("Unable to create client cert: %s", err.Error())
			return nil,err
		}

		err = certOut.Close()
		if err != nil {
			log.Printf("Unable to close cert file: %s", err.Error())
			return nil,err
		}

		keyOut, err := os.OpenFile(certKey, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			log.Printf("Unable to open %s: %s", certKey, err.Error())
			return nil,err
		}

		err = pem.Encode(keyOut, &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey),
		})

		if err != nil {
			log.Printf("Unable to PEM encode %s cert: %s", certKey, err.Error())
			return nil,err
		}
		err = keyOut.Close()
		if err != nil {
			log.Printf("Unable to close %s: %s", certKey, err.Error())
			return nil,err
		}
	}
	tlsCertificate,err := loadSignedClientCert(certName, certKey)
	return &tlsCertificate,err

}

func RetrieveCaCertificate(request SignRequest) []byte {
	if _, err := os.Stat("ca.crt"); os.IsNotExist(err) {
		log.Printf("Creating a new CA for this environment")
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

func loadSignedClientCert(certName string, certKey string) (tls.Certificate, error) {
	catls, err := tls.LoadX509KeyPair(certName, certKey)
	if err != nil {
		return catls,err
	}
	return catls,nil
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
