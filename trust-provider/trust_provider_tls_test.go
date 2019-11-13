package trustprovider

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"github.com/Vivvo/go-sdk/utils"
	"gopkg.in/resty.v1"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

type ClientCertificate struct {
	Certificate []byte `json:"certificate"`
}

func SignClientCertificateRequest(commonName string, publicKey []byte) (*ClientCertificate, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}

	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1658),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		//IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")}, //Enable this for the E2E tests
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	pub, err := x509.ParsePKIXPublicKey(publicKey)
	if err != nil {
		log.Fatalf("Error parsing PKIX Public Key: %s", err.Error())
		return nil, err
	}

	signedCert, err := x509.CreateCertificate(rand.Reader, cert, cert, pub, privateKey)
	if err != nil {
		log.Fatalf("Error signing the certificate, Error: %s", err.Error())
	}
	clientCertificate := ClientCertificate{
		Certificate: signedCert,
	}

	log.Printf("Created and returned a certificate for %s", commonName)
	return &clientCertificate, err
}

var mockCaServer = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	if r.URL.Path == "/api/v1/sign" {
		b, _ := ioutil.ReadAll(r.Body)
		certificate, err := SignClientCertificateRequest(r.Header.Get("cn"), b)
		if err != nil {
			log.Printf("Error signing certifacte: %s", err.Error())
		}
		utils.WriteJSON(certificate, http.StatusOK, rw)
	} else {
		log.Fatalf("invalid endpoint called")
	}
}))

var setupComplete = false

func waitForTrustProvider() (*resty.Response, error) {
	var resp *resty.Response
	var err error

	for {
		resp, err = resty.R().
			Get("https://127.0.0.1:3000/api/v1/version")

		if err != nil && strings.Contains(err.Error(), "connection refused"){
			continue
		}
		break
	}
	return resp, err
}

func TestListenAndServerTlsReturnsErrorOnUnsignedRequest(t *testing.T) {
	go setup()

	t.Logf("calling out to trust provider")
	_, err := waitForTrustProvider()

	if err == nil {
		t.Fatalf("retrieved version for unsigned request")
	}
}

func TestListenAndServerTlsReturnsSuccessfully(t *testing.T) {
	go setup()

	t.Logf("calling out to trust provider")
	resp, err := waitForTrustProvider()

	if err != nil {
		t.Fatalf("failed to get version: %s", err.Error())
	}

	if resp.StatusCode() != http.StatusOK {
		t.Fatalf("failed to get version: [%d]", resp.StatusCode())
	}
}

func setup() {
	cleanup()
	_ = os.Setenv("VIVVO_CA_BASEURL", mockCaServer.URL)
	http.DefaultServeMux = new(http.ServeMux)

	onboardingFunc := func(s map[string]string, n map[string]float64, b map[string]bool, i map[string]interface{}) (interface{}, error, string) {
		return nil, errors.New("error"), ""
	}

	onboarding := Onboarding{
		Parameters:     []Parameter{},
		OnboardingFunc: onboardingFunc,
	}

	tp := New(onboarding, nil, nil, nil, nil, nil)
	err := tp.ListenAndServeTLS("127.0.0.1")
	if err != nil {
		log.Fatalf("Error initializing trust provider: %s", err.Error())
	}
}

func cleanup () {
	os.Remove(CertKey)
	os.Remove(CertName)
}