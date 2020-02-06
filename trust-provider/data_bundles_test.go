package trustprovider

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"github.com/Vivvo/go-sdk/models"
	"github.com/Vivvo/go-sdk/utils"
	"github.com/google/uuid"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type MockDataBundle struct {
	LegalName string `json:"legalName"`
	BankAccountNumber string `json:"bankAccountNumber"`
}

func setupMockIdentityServer() string {
	c, _ := utils.NewConsulTLSService()
	utils.InitResty(c)
	mockIdentityServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "publicKeys") {
			pubKeys := []models.PublicKeyDto{
				{ PolicyId: policyIdOne, PublicKey: rsaPublicKeyOne },
				{ PolicyId: policyIdTwo, PublicKey: rsaPublicKeyTwo },
			}
			utils.WriteJSON(&models.PublicKeysDto{
				PublicKeys: pubKeys,
			}, http.StatusOK, rw)
		}
	}))

	return mockIdentityServer.URL
}

// This test covers almost all of the business logic, the other functions are simply rest calls
func TestDataBundleService_mimicPublishDataBundle(t *testing.T) {
	mockIdentityServerUrl := setupMockIdentityServer()
	d := NewDataBundleService(mockIdentityServerUrl)

	dataBundle := &MockDataBundle{
		LegalName: "Tester guy",
		BankAccountNumber: "123456789",
	}

	pubKeysDto, err := d.GetPublicKeysForDataBundleConsumers(uuid.New(), "TAX_BUNDLE")
	if err != nil {
		t.Fatalf("error getting public keys: %s", err)
	}

	bundles, err := d.EncryptDataBundleWithPublicKeys(dataBundle, pubKeysDto)
	if err != nil {
		t.Fatalf("failed to EncryptDataBundleWithPublicKeys: %s", err)
	}

	for _, v := range bundles.Bundles {
		log.Printf("bundle: %+v", v)
	}

	var dst MockDataBundle
	for _, v := range bundles.Bundles {
		// check that consumer 1 can decrypt their bundle
		if v.PolicyId == policyIdOne {
			err = DecryptPayload(v.AESEncryptedBundle, v.RSAEncryptedAESNonce, v.RSAEncryptedAESKey, rsaPrivateKeyOne, &dst)
			if err != nil {
				panic(err)
			}

			if dst.LegalName != dataBundle.LegalName {
				t.Fatalf("legalname did not match got %s expected %s", dst.LegalName, dataBundle.LegalName)
			}

			if dst.BankAccountNumber != dataBundle.BankAccountNumber {
				t.Fatalf("bankAccountNumber did not match got %s expected %s", dst.BankAccountNumber, dataBundle.BankAccountNumber)
			}
		}

		// check consumer two can decrypt their bundle
		if v.PolicyId == policyIdTwo {
			err = DecryptPayload(v.AESEncryptedBundle, v.RSAEncryptedAESNonce, v.RSAEncryptedAESKey, rsaPrivateKeyTwo, &dst)
			if err != nil {
				panic(err)
			}

			if dst.LegalName != dataBundle.LegalName {
				t.Fatalf("legalname did not match got %s expected %s", dst.LegalName, dataBundle.LegalName)
			}

			if dst.BankAccountNumber != dataBundle.BankAccountNumber {
				t.Fatalf("bankAccountNumber did not match got %s expected %s", dst.BankAccountNumber, dataBundle.BankAccountNumber)
			}
		}
	}

	// ensure bundles are independently encrypted
	//err = d.DecryptDataBundle(bundles.Bundles[0].EncryptedBundle, pkTwo, dst)
	//if err == nil {
	//	t.Fatalf("looks like consumer 2's private key was able to decrypt the bundle meant for consumer 1")
	//}
}

func readPrivateKey(pkPem string) *rsa.PrivateKey {
	block, _ := pem.Decode([]byte(pkPem))
	if block == nil {
		panic("block was nil")
	}

	pk, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	return pk
}

var policyIdOne = uuid.MustParse("aafff2fe-c96e-44e4-b6e2-1836eeb9f53e")
const rsaPrivateKeyOne = `-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----`
const rsaPublicKeyOne = "-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtmQ7Lt/iLnZQg6pEdHEi\nOecEKNnKr9oPOya+ItXr3+4ckBJTr9wFr623RFBjuFt9bSPV6Oxjy+UZ6JLc7PIJ\n6W+1BCBwWThjNlKlXiyStDEz+C2GYqs0GwGOh/iAlSUbjxBKaDPVVa6FeLSW3V0f\nOFrHw6poG3KGnH1Gkw/hN66UN6aIJIh2IrK67PlsXaqzWO+Z15Xcs6l3fZiP0HKi\n5slTO27EYo9PJe4T3BLZw22hcRZCspZLSQQQVSpo9TuErx/Zgv+oRhNJFgZVJHrK\ntLtBrbE9z5EYzb/qIYXcmt+B2XIvWYKJ9jYmnob6e9C3u3RmJ5kLXkjJpCThaNG2\nRKgf7G0Io5WD3ZgzUFCdcLBZMMR8tyWlqrEMj53ugrR4/F/Lcm4+uCX9jfEDBv0o\n2nJw/YaeYffCreh1TVrbwc67oY4Vl6QDx7DLjIc6yI13N2B+bzmoE3a5NZeMECe5\n5q5eTkjeyOzGGhVs5dm0mKYQ5/X4lIG8JQpw7/QmesD7vdx97n/FkLjU+U9d6SZh\nB9mw3WbGceyGL0PS9M9lKvWfcOV19Gf7aLxcUot1U6CvY3QIhyrHJFhxPVDNcc73\nrcxx1QBPUXcS7MyFRTGk47zKgDLdtw3uvkK23pm4ZXtiXBKejCLE7i370NOjo85h\nJrBb8IV36tksog7VbXRewE8CAwEAAQ==\n-----END PUBLIC KEY-----"

var policyIdTwo = uuid.MustParse("b92cf8df-1276-496d-b1c6-2ca99a97d276")
const rsaPrivateKeyTwo = `-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----`
const rsaPublicKeyTwo = `-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAzrDG+UoxV/u7nLEyGl19
DTD8nDRIW0CU54O0mYIDbCoU+IJnXkU9C1NIUmSVLH7VyaqWUQaoGPIrca7jxJzz
fjetw/03QGjWl1xaFT4P3YYTT7Ma1dt9uD4BiUk5VrymGra+pQ6iQMOd2KXzA8n3
r3EJImIniwpmaJREaUSe3S6S25eVcW6lQwpKQMq+j0FBIQrjpNf+33aCwbN7cr68
La6MjoPKVPjdB3ircseEWBe8SN53FoGd0JcMTFN/NISA5OODL+iMG+K9IoFZjjz4
q3VtSGTHESdcwwjHJAbIbAftpfbDT5yyLU5TZ1YrGxZxnp5Y/cY/r6tdZJntjeAq
bqi8LRENlQdksoRUXhg7gu+v5fhlufADRSZjaQbkeJlGyGqxWUmw2g0drPC6zycZ
3pPlcUpwpIJD2m21zGpgSCKnTh4kK2gRs313URxkBwmYNbnDtflBhAtSesCZAoen
rzVvhPfs6Jp6ORINevCC87Ujn1z99XIhrcxZEza8h9RNzAMsULO625W/VurYucA6
uEk8m4REXQ5PP88e8qqoYn8mQw0J9+XSPuMMyRNqrKd28kd8+cWbWZ7WRjmr9WLR
0GIPTlb3Sy+i4wtx+ubaxKdcPsVxI2cDOoVrWiV3/gpuFoAKIMdhO/rtcn8mKJLt
rGB22W2rt67iWGotUUTUwsECAwEAAQ==
-----END PUBLIC KEY-----`