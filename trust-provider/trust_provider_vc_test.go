package trustprovider

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"github.com/Vivvo/go-sdk/did"
	"github.com/Vivvo/go-sdk/utils"
	"github.com/Vivvo/go-wallet"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

const privateKeyPem = `-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEA5itUMTAv/2JUifdOtLeNokWb3lvWizgeWTzYyXdJVxqrIn2A
frRIuEyOdVOjFUWv+L4i/qQtthrRfgexeg6U6+CQQVtHqK7l24PAg6efDGOjvvmc
8AAj/n1xaeWnepiGHk0/3UCkdFhjxhS+Hgapysj4qa9J8B2E5bUprzM3MG3GgrT4
i0McpID/UlvySQ6kfTVwD0ulm1ZHm96jsxDjW1GrFmKdwXH/AW9v+zRpxIP00c8A
MZc2RdXZxQqZRDUeK3SwZyV6a+mNxQIiAsLrEJb/5aaBreAge9cMPjy+TAmQ+R0m
BcbZkMskZdTR1K8FNC8RFjdIy/KaQPZQQ+4cowIDAQABAoIBAFr4/zLd1+q5w64w
OESHVAyyNJQjel3WVXBx80FVy4AJA2EDd7kcqq1lXN0UrJ2oyI+pHw3EeGjEms6U
XdpfTw8X2Axs9pq+Xg1wOrQOmXd9HmhKInRdqdxZWm0/nv1+sWvinn5loVp24SCW
bDpT6eJDorz2kmO8Vx2viAU+We7ihLOfHPshOpr13cqbo+X8ZraxuTKGiZPRUSOD
Q+wr4+uTMRoP13saSXpdx2Zx3eTOihKu/G7J30i4wkfYhTVpfKBbYObEMAGyMqs0
FMvW7c9E2oDkxThw11cJg0qtpcQRhqoZ/p6tX0ZztVNVvVwqaGXnK3yD5urTo74v
IvDS+5kCgYEA8tSKSesqg+o5u+knNz8BgGSzAy8QJqTY8MIegCPe6a70izazUjnC
rLQslaXuLFLnXbq8Qi5Trli83OAHdQ5xKSdDbDZZjusOK/OSRSC/N6ZlMuUN+9yp
ZrvCb8CdfuWqjW2Cs4XxhYg64e1/P9IEySj5iDg2jBut8cjOy31WE+0CgYEA8qcA
3HDQSP1R9Y7EYBlvrX+dYJvOEfCPkulSe4ELaStCvXI7FcbcBETUEQN/5Oy9cUuU
xaUJOGvWTBTO/Pme0Pl6rMf+/2YmqFHUbreys/noLKwpkyMxXwP1Zb8quO8rSeqI
e5C5NiYfsbaEggK/D/jo94zhEUzAIYc8r9YkAM8CgYBp7depqUGxrAKle28VBZI1
HTiOIgCsqurMFBJUGdHLJPweoq0VKIdI6Ywtd+XvRfcSBzzKrgTpIGK7A6udH8Cz
kCI0WX02AEn9WFKtfzyLHTY2Pn+cKEVpwGxwbZkG209MRMJoZ/zVIHl3RzBkecyG
qC46gzMgaY6207+KO1HKfQKBgGupeZJVY7Te4LyJKcxRvOFIG/W/a4E+MRXH/Fbb
/Moe7a/MvTZ+UyR5vXYHDXnvKGbaWBoRjbPA9QYwvV41CyhBaRK8cgGzuzc3h3/Q
dbOxEDix8ohcNw2nXfxVA4mmZJiZPRFGN0c1Rx68krJ0sX1OvV8I3NumKCE4Nc72
vma1AoGAO2ajA65nB8HzI6QLbZ49B7vGa/z+M+gx0VVCrsrcie5ZuDhQG2kpD3lW
P/oPcAAehBvdPu8RN+CtAtCFhG6J/tSD64PclJfwN0xrh9yqk3/x36+QqcpjRWFP
mn+3xb9090uN9wVh+butS7CLc0LcM90ET/A7++i6YjBMPTQjKtc=
-----END RSA PRIVATE KEY-----`

const publicKeyPem = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5itUMTAv/2JUifdOtLeN\nokWb3lvWizgeWTzYyXdJVxqrIn2AfrRIuEyOdVOjFUWv+L4i/qQtthrRfgexeg6U\n6+CQQVtHqK7l24PAg6efDGOjvvmc8AAj/n1xaeWnepiGHk0/3UCkdFhjxhS+Hgap\nysj4qa9J8B2E5bUprzM3MG3GgrT4i0McpID/UlvySQ6kfTVwD0ulm1ZHm96jsxDj\nW1GrFmKdwXH/AW9v+zRpxIP00c8AMZc2RdXZxQqZRDUeK3SwZyV6a+mNxQIiAsLr\nEJb/5aaBreAge9cMPjy+TAmQ+R0mBcbZkMskZdTR1K8FNC8RFjdIy/KaQPZQQ+4c\nowIDAQAB\n-----END PUBLIC KEY-----"

type MockResolver struct {
	dids map[string]*did.Document
}

func NewMockResolver() MockResolver {
	r := MockResolver{}
	r.dids = make(map[string]*did.Document, 0)
	return r
}

func (m *MockResolver) Resolve(d string) (*did.Document, error) {
	if m.dids[d] == nil {
		return nil, errors.New("not found")
	}
	return m.dids[d], nil
}

func (m *MockResolver) Register(ddoc *did.Document) error {
	m.dids[ddoc.Id] = ddoc
	return nil
}

var onboardingFuncCalled = false
var saveFuncCalled = false

func TestOnboardingVerifiableClaim(t *testing.T) {

	tests := []struct {
		name               string
		onboardingFunc     func(s map[string]string, n map[string]float64, b map[string]bool) (interface{}, error, string)
		saveFuncCalled     bool
		statusCode         int
		onboardingStatus   bool
		onboardingRequired bool
		token              bool
	}{
		{"Test Successful Onboarding",
			func(s map[string]string, n map[string]float64, b map[string]bool) (interface{}, error, string) {
				onboardingFuncCalled = true
				return MockAccountObj{AccountId: 1}, nil, ""
			},
			true,
			http.StatusCreated,
			true,
			false,
			true,
		},
	}

	for _, tt := range tests {
		os.Remove("w.db")
		os.Remove("wallet.db")

		t.Run(tt.name, func(t *testing.T) {
			onboardingFuncCalled = false
			saveFuncCalled = false
			http.DefaultServeMux = new(http.ServeMux)

			onboarding := Onboarding{
				Parameters:     []Parameter{},
				OnboardingFunc: tt.onboardingFunc,
			}

			mockAccount := MockAccount{}
			mockAccount.SetUpdateFunc(func(account interface{}, token string) error {
				saveFuncCalled = true

				if a, ok := account.(MockAccountObj); ok == true {
					if a.AccountId != 1 {
						t.Errorf("Expected: %d, Actual: %d", 1, a.AccountId)
					}
				} else {
					t.Errorf("Expected an Account object")
				}
				if token == "" {
					t.Errorf("Expected to receive a token")
				}

				return nil
			})

			os.Setenv("DID", "did:vvo:12H6btMP6hPy32VXbwKvGE")
			os.Setenv("PRIVATE_KEY_PEM", privateKeyPem)

			resolver := NewMockResolver()

			tp := New(onboarding, nil, nil, nil, &mockAccount, &resolver)

			executeRequest := func(req *http.Request) *httptest.ResponseRecorder {
				rr := httptest.NewRecorder()
				tp.Router.ServeHTTP(rr, req)

				return rr
			}

			w, _ := newWallet(t)

			ddoc := GenerateDidDocument(w, &resolver)

			vc := buildIAmMeCredential(w, ddoc)
			b, err := json.Marshal(vc)
			if err != nil {
				t.Fatal(err.Error())
			}

			adapterDdocJson, err := tp.wallet.Dids().Read(os.Getenv("DID"))
			if err != nil {
				t.Fatalf(err.Error())
			}

			var adapterDdoc = did.Document{}
			json.Unmarshal([]byte(adapterDdocJson), &adapterDdoc)

			keyExchangeKey := adapterDdoc.PublicKey[1].PublicKeyBase58

			err = w.Messaging().InitDoubleRatchet(ddoc.Id, keyExchangeKey)
			if err != nil {
				t.Fatalf(err.Error())
			}

			rp, err := w.Messaging().RatchetEncrypt(ddoc.Id, string(b))
			if err != nil {
				t.Fatalf(err.Error())
			}

			rpJson, _ := json.Marshal(rp)

			req, _ := http.NewRequest("POST", "/api/register", strings.NewReader(string(rpJson)))
			res := executeRequest(req)
			if res.Code != tt.statusCode {
				t.Errorf("Expected: %d, Actual: %d", tt.statusCode, res.Code)
			}

			b, err = ioutil.ReadAll(res.Body)
			if err != nil {
				t.Errorf("Error reading response body: %s", err.Error())
			}

			var response = trustProviderResponse{}
			err = json.Unmarshal(b, &response)
			if err != nil {
				t.Errorf("Error unmarshalling response body: %s", err.Error())
			}

			str, _ := w.Messaging().RatchetDecrypt(ddoc.Id, response.VerifiableClaim)
			var vcResponse = did.VerifiableClaim{}
			json.Unmarshal([]byte(str), &vcResponse)

			err = vcResponse.Verify([]string{did.VerifiableCredential, did.TokenizedConnectionCredential}, vcResponse.Proof.Nonce, &resolver)
			if err != nil {
				t.Fatal(err.Error())
			}

			if vcResponse.Claim[did.SubjectClaim] != ddoc.Id {
				t.Fatalf("Expected: %s, Actual: %s", "did:vvo:12H6btMP6hPy32VXbwKvGE", vcResponse.Claim[did.SubjectClaim])
			}
		})

		os.Remove("w.db")
		os.Remove("wallet.db")
	}

}

func GenerateDidDocument(w *wallet.Wallet, resolver did.ResolverInterface) (*did.Document) {
	id := utils.ClientIdToDid(uuid.New())

	rsaPubKey, _ := w.Crypto().GenerateRSAKey(wallet.TypeRsaVerificationKey2018, id)
	ed25519PubKey, _ := w.Crypto().GenerateEd25519Key(wallet.TypeEd25519KeyExchange2018, id)

	didDocument := &did.Document{
		Id: id,
		PublicKey: []did.PublicKey{
			{Owner: id, Id: fmt.Sprintf("%s#keys-1", id), PublicKeyPem: rsaPubKey, T: wallet.TypeRsaVerificationKey2018},
			{Owner: id, Id: fmt.Sprintf("%s#keys-2", id), PublicKeyBase58: ed25519PubKey, T: wallet.TypeEd25519KeyExchange2018},
		},
		Authentication: []did.Authentication{{T: wallet.TypeRsaVerificationKey2018, PublicKey: fmt.Sprintf("%s#keys-1", id)}},
		Context:        "https://w3id.org/did/v1",
		Service:        []did.Service{{ServiceEndpoint: "http://example.com", T: "AgentService"}},
	}

	s, _ := json.Marshal(didDocument)

	w.Dids().Create(didDocument.Id, string(s), nil)

	resolver.Register(didDocument)

	return didDocument
}

func newWallet(t *testing.T) (*wallet.Wallet, []byte) {
	masterKey := make([]byte, 32)
	rand.Reader.Read(masterKey)

	w, err := wallet.Create(append(make([]byte, 0), masterKey...), "w.db")
	if err != nil {
		t.Fatalf("Unexpected error: %s", err.Error())
	}

	return w, masterKey
}

func buildIAmMeCredential(w *wallet.Wallet, ddoc *did.Document) did.VerifiableClaim {
	claims := make(map[string]interface{})
	claims[did.SubjectClaim] = ddoc.Id
	claims[did.PublicKeyClaim] = fmt.Sprintf("%s#keys-1", ddoc.Id)

	b, _ := json.Marshal(ddoc)

	claims["ddoc"] = string(b)

	var claim = did.Claim{
		Id:     ddoc.Id,
		Type:   []string{did.VerifiableCredential, did.IAmMeCredential},
		Issuer: ddoc.Id,
		Issued: time.Now().Format("2006-01-02"),
		Claim:  claims,
	}

	vc, _ := claim.WalletSign(w, ddoc.Id, uuid.New().String())
	return vc
}

//func _TestRulesVerifiableCredential(t *testing.T) {
//
//	validToken := uuid.New()
//
//	tests := []struct {
//		Name       string
//		Rules      []Rule
//		Body       string
//		StatusCode int
//		Status     bool
//		Token      uuid.UUID
//		Message    string
//	}{
//		{
//			Name: "alwayspasses",
//			Rules: []Rule{{Claims: []string{did.VerifiableCredential, did.ProofOfAgeCredential}, Name: "alwayspasses", Parameters: []Parameter{{Name: "age", Type: ParameterTypeFloat64, Required: true}}, RuleFunc: func(s map[string]string, n map[string]float64, b map[string]bool, acct interface{}) (bool, error) {
//				return true, nil
//			}}},
//			StatusCode: http.StatusOK,
//			Status:     true,
//			Token:      validToken,
//			Message:    "",
//		},
//	}
//
//	for _, tt := range tests {
//		t.Run(tt.Name, func(t *testing.T) {
//			http.DefaultServeMux = new(http.ServeMux)
//
//			onboarding := Onboarding{
//				Parameters: []Parameter{},
//				OnboardingFunc: func(s map[string]string, n map[string]float64, b map[string]bool) (interface{}, error, string) {
//					return MockAccountObj{AccountId: 1}, nil, ""
//				},
//			}
//
//			mockAccount := MockAccount{}
//			mockAccount.SetUpdateFunc(func(account interface{}, token string) error { return nil })
//			mockAccount.SetReadFunc(func(token string) (interface{}, error) {
//				return MockAccountObj{AccountId: 1234567890, Age: 30}, nil
//			})
//
//			os.Setenv("DID", "did:vvo:12H6btMP6hPy32VXbwKvGE")
//			os.Setenv("PRIVATE_KEY_PEM", privateKeyPem)
//
//			tp := New(onboarding, tt.Rules, &mockAccount, &MockResolver{})
//
//			executeRequest := func(req *http.Request) *httptest.ResponseRecorder {
//				rr := httptest.NewRecorder()
//				tp.Router.ServeHTTP(rr, req)
//				return rr
//			}
//
//			ac := make(map[string]interface{})
//			ac[did.TokenClaim] = uuid.New().String()
//			vc, _ := tp.generateVerifiableClaim(ac, "did:vvo:12H6btMP6hPy32VXbwKvGE", ac[did.TokenClaim].(string), []string{did.VerifiableCredential, did.TokenizedConnectionCredential})
//
//			body := struct {
//				Age             float64             `json:"age"`
//				VerifiableClaim did.VerifiableClaim `json:"verifiableClaim"`
//			}{
//				25,
//				vc,
//			}
//
//			b, _ := json.Marshal(body)
//
//			req, _ := http.NewRequest("POST", fmt.Sprintf("/api/%s/%s", tt.Name, validToken), strings.NewReader(string(b)))
//			res := executeRequest(req)
//
//			b, err := ioutil.ReadAll(res.Body)
//			if err != nil {
//				t.Errorf("Error reading response body: %s", err.Error())
//			}
//
//			var response trustProviderResponse
//			err = json.Unmarshal(b, &response)
//			if err != nil {
//				t.Errorf("Error unmarshalling response body: %s", err.Error())
//			}
//
//			if response.VerifiableClaim == nil {
//				t.Fatal("Expected a verifiable claim in the response body.")
//			}
//
//			err = response.VerifiableClaim.Verify([]string{did.VerifiableCredential, did.ProofOfAgeCredential}, response.VerifiableClaim.Proof.Nonce, &MockResolver{})
//			if err != nil {
//				t.Fatal(err.Error())
//			}
//
//			if response.VerifiableClaim.Claim[did.SubjectClaim] != "did:vvo:12H6btMP6hPy32VXbwKvGE" {
//				t.Fatalf("Expected: %s, Actual: %s", "did:vvo:12H6btMP6hPy32VXbwKvGE", response.VerifiableClaim.Claim[did.SubjectClaim])
//			}
//
//			if response.VerifiableClaim.Claim["age"] != float64(25) {
//				t.Fatalf("Expected: %d, Actual: %s", 25, response.VerifiableClaim.Claim["age"])
//			}
//		})
//	}
//}
