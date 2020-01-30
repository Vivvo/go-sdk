package trustprovider

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"github.com/Vivvo/go-sdk/models"
	"github.com/Vivvo/go-sdk/utils"
	"github.com/google/uuid"
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
	d := DataBundleService{
		IdentityServerUrl: mockIdentityServerUrl,
	}

	dataBundle := &MockDataBundle{
		LegalName: "Tester guy",
		BankAccountNumber: "123456789",
	}

	pubKeysDto, err := d.getPublicKeysForDataBundleConsumers(uuid.New(), "TAX_BUNDLE")
	if err != nil {
		t.Fatalf("error getting public keys: %s", err)
	}

	bundles, err := d.encryptDataBundleWithPublicKeys(dataBundle, pubKeysDto)
	if err != nil {
		t.Fatalf("failed to encryptDataBundleWithPublicKeys: %s", err)
	}

	pkOne := parsePrivateKey(rsaPrivateKeyOne)
	pkTwo := parsePrivateKey(rsaPrivateKeyTwo)

	var dst MockDataBundle
	for _, v := range bundles.Bundles {
		// check that consumer 1 can decrypt their bundle
		if v.PolicyId == policyIdOne {
			err = d.DecryptDataBundle(bundles.Bundles[0], pkOne, &dst)
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
			err = d.DecryptDataBundle(bundles.Bundles[1], pkTwo, &dst)
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
	err = d.DecryptDataBundle(bundles.Bundles[0], pkTwo, dst)
	if err == nil {
		t.Fatalf("looks like consumer 2's private key was able to decrypt the bundle meant for consumer 1")
	}
}

func parsePrivateKey(pkPem string) *rsa.PrivateKey {
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

var policyIdOne = uuid.New()
const rsaPrivateKeyOne = `-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----`
const rsaPublicKeyOne = `-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAp6XV5tFweK+eW6WMVgPj
En6y18wYc3rMzEMpmyPB/5ZF/ASmyK8rqqWqWxqll5hkUNKOvgzSH6zY67FyRmoQ
dQ76ArLWwhKqlP689im3BrI427PSbRxl16fgeUEL9//qHGfLw1D8yaTP8bel92PS
wXPTVCbPuICyvbRzhw/82svMYAKRIjbgPK1tZMsmJmBqY/FZbAcynz6zA7pz9Rp4
Jd0fvGiilExLBQLAssisnANwK8pRq4FUkCnpGSif3ySGY7Cq3Jl4b7j4MYqn8UT5
yUaoiz0oQ5AghNziDKo+vQ+5WyW4oRPC+HT7fBM5+UaxvBlzjLwqHnO6VFarGOTH
K9kfh0uHSM5AAx1EhFjz6nNTTJtGbGGK1zrmbAFwMFfSzgE1p1258yhYZaY/Gx3Z
CMaFbCHUvpDC22WXLNRIw6C5O0zbNuQo4QvHpiTeQUpT5lFzxjXr8MUcQLLJ2WB5
RVH5Tm0m5+klziFNryejQyILb2qq0pnca6gsppNC6aGgS6HOnC5+qnc9uV9KMWb5
Edi0ctFG0luFYDFAKVjYKZ2iwTpUAgPvsEonHfXn6/RMbr7IonwIX1bAibt1VJHh
VQzM8a0JhUeSgFYLvJPApLmaUY6oASaMXihILRsZBgsC8vQECGPybH+lLbiCKPds
Gt/QZIyH1VEey1UM0wS79e0CAwEAAQ==
-----END PUBLIC KEY-----`

var policyIdTwo = uuid.New()
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