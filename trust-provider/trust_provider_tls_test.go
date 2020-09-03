package trustprovider

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"github.com/Vivvo/go-sdk/mtls"
	"github.com/Vivvo/go-sdk/utils"
	"gopkg.in/resty.v1"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
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

func waitForTrustProvider(boundByCertificate bool) (*resty.Response, error) {
	var resp *resty.Response
	var err error

	startTime := time.Now()
	for {
		var restyClient *resty.Request
		if boundByCertificate {
			restyClient = utils.Resty(context.Background()).R()
		} else {
			restyClient = resty.R()
		}

		port := os.Getenv(ConfigTrustProviderPort)
		resp, err = restyClient.
			Get(fmt.Sprintf("https://localhost.vivvocloud.com:%s/api/v1/version", port))

		if time.Now().Sub(startTime) > 10*time.Second {
			break
		}

		if err != nil {
			if strings.Contains(err.Error(), "connection refused") {
				continue
			}
			if strings.Contains(err.Error(), "bad certificate") {
				break
			}
			if strings.Contains(err.Error(), "x509: certificate is valid for") {
				break
			}
		}
		time.Sleep(1 * time.Second)
	}
	return resp, err
}

func TestListenAndServerTlsReturnsErrorOnUnsignedRequest(t *testing.T) {
	setupEnvironment(3000, "localhost.vivvocloud.com")
	setup()

	t.Logf("calling out to trust provider")
	_, err := waitForTrustProvider(false)

	if err == nil {
		t.Fatalf("retrieved version for unsigned request")
	}
}

func TestListenAndServerTlsReturnsSuccessfully(t *testing.T) {
	setupEnvironment(3001, "localhost.vivvocloud.com")
	setup()

	t.Logf("calling out to trust provider")
	resp, err := waitForTrustProvider(true)

	t.Log(resp)
	if err != nil {
		t.Fatalf("failed to get version: %s", err.Error())
	}

	if resp.StatusCode() != http.StatusOK {
		t.Fatalf("failed to get version: [%d]", resp.StatusCode())
	}
}

func TestListenAndServerTlsFailsWithCommonName(t *testing.T) {
	setupEnvironment(3002, "localhosts.vivvocloud.com")
	setup()

	t.Logf("calling out to trust provider")
	_, err := waitForTrustProvider(true)
	if err == nil {
		t.Fatalf("retrieved version for request with bad certificate commonname")
	}
}

func setupEnvironment(port int, commonName string) {
	_ = os.Setenv(ConfigTrustProviderPort, strconv.Itoa(port))
	_ = os.Setenv("VIVVO_CA_BASEURL", "https://vivvo-ca.c1.svc.cluster.local")
	_ = os.Setenv("VIVVO_CA_AUTHORIZATION_TOKEN", "abc123")
	_ = os.Setenv("VIVVO_CA_COMMONNAME", commonName)
	_ = os.Setenv("CONSUL_HTTP_ADDR", "consul.service.consul")
}

func setup() {
	cleanup()

	consul, err := utils.NewConsulService()
	if err != nil {
		panic(err)
	}
	signRequest := mtls.SignRequest{Authorization: "", CertificateAuthorityUrl: "", CommonName: ""}
	utils.InitRestyTLS(consul, signRequest)

	http.DefaultServeMux = new(http.ServeMux)

	// start trust provider server first because it's certificate is needed to sign the clients cert
	onboardingFunc := func(s map[string]string, n map[string]float64, b map[string]bool, i map[string]interface{}) (interface{}, error, string) {
		return nil, errors.New("error"), ""
	}

	onboarding := Onboarding{
		Parameters:     []Parameter{},
		OnboardingFunc: onboardingFunc,
	}

	go func() {
		tp := New(onboarding, nil, nil, nil, nil, nil)
		err = tp.ListenAndServeTLS("localhost.vivvocloud.com")
		if err != nil {
			log.Fatalf("Error initializing trust provider: %s", err.Error())
		}
	}()

	var attempts = 0
	// sleep until trust provider generates it's test keys
	for {
		if _, err := os.Stat("tp.key"); os.IsNotExist(err) {
			time.Sleep(1 * time.Second)
			attempts++
			continue
		} else {
			break
		}
	}
}

func cleanup() {
	os.Remove(CertKey)
	os.Remove(CertName)
	os.Remove("ca.crt")
	os.Remove("client.crt")
	os.Remove("client.key")
}
