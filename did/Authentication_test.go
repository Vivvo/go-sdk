package did

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
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

const authorizationHeader = `Signature keyId="did:vvo:2y7ViLLfEpouo4XDbLJK6B#keys-1",algorithm="RsaSignatureAuthentication2018",headers="date",signature="tg4GqPyV7lyCJ0vi4M7bOwfWE0QhK45hrffVTFvqfBdKJ6nUpEQYjXiIaTMvSsjm1l2vVM63g8UYnhsT51j0VbyWqQLPxbtt9Wnh28KdKc7Px-l0ChlrsRGTBL0pOBYBqIwrxESvN8WP1UBaokQF4donXgOzIn6xl57L3NGxBz7nnlNHRcXo2IFjE3CK-HPzaXmBqDofKZJs7qbUjvelDF3B1wddHdDV2t8a68-xcI-myQT4kq74scmR10s090tU_ZurSuT5NZFlu7iXPkOYvUVpXXaDjpJ6vTurMBPwPSWWUA4EL39E5d1Fa7ml_X867olpUlfMwr0bRiyHgLtuVQ=="`

var successHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
})

type MockResolver struct {
}

func (m MockResolver) Resolve(d string) (*Document, error) {
	return &Document{Id: "did:vvo:12H6btMP6hPy32VXbwKvGE", PublicKey: []PublicKey{{Id: "did:vvo:12H6btMP6hPy32VXbwKvGE#keys-1", PublicKeyPem: publicKeyPem}}}, nil
}

func TestParseAuthorizationHeader(t *testing.T) {
	authorization, _ := parseAuthorizationHeader(authorizationHeader)

	if authorization.algorithm != "RsaSignatureAuthentication2018" {
		t.Errorf("Expected: %s, Actual: %s", "RsaSignatureAuthentication2018", authorization.algorithm)
	}
	if len(authorization.headers) == 0 {
		t.Errorf("Expected authorizations headers to contain 1 element")
	}
	if authorization.headers[0] != "date" {
		t.Errorf("Expected: %s, Actual: %s", "date", authorization.headers[0])
	}
	if authorization.keyId != "did:vvo:2y7ViLLfEpouo4XDbLJK6B#keys-1" {
		t.Errorf("Expected: %s, Actual: %s", "did:vvo:2y7ViLLfEpouo4XDbLJK6B#keys-1", authorization.algorithm)
	}
	if authorization.did != "did:vvo:2y7ViLLfEpouo4XDbLJK6B" {
		t.Errorf("Expected: %s, Actual: %s", "did:vvo:2y7ViLLfEpouo4XDbLJK6B", authorization.algorithm)
	}
	if authorization.signature != "tg4GqPyV7lyCJ0vi4M7bOwfWE0QhK45hrffVTFvqfBdKJ6nUpEQYjXiIaTMvSsjm1l2vVM63g8UYnhsT51j0VbyWqQLPxbtt9Wnh28KdKc7Px-l0ChlrsRGTBL0pOBYBqIwrxESvN8WP1UBaokQF4donXgOzIn6xl57L3NGxBz7nnlNHRcXo2IFjE3CK-HPzaXmBqDofKZJs7qbUjvelDF3B1wddHdDV2t8a68-xcI-myQT4kq74scmR10s090tU_ZurSuT5NZFlu7iXPkOYvUVpXXaDjpJ6vTurMBPwPSWWUA4EL39E5d1Fa7ml_X867olpUlfMwr0bRiyHgLtuVQ==" {
		t.Errorf("Expected: %s, Actual: %s", "tg4GqPyV7lyCJ0vi4M7bOwfWE0QhK45hrffVTFvqfBdKJ6nUpEQYjXiIaTMvSsjm1l2vVM63g8UYnhsT51j0VbyWqQLPxbtt9Wnh28KdKc7Px-l0ChlrsRGTBL0pOBYBqIwrxESvN8WP1UBaokQF4donXgOzIn6xl57L3NGxBz7nnlNHRcXo2IFjE3CK-HPzaXmBqDofKZJs7qbUjvelDF3B1wddHdDV2t8a68-xcI-myQT4kq74scmR10s090tU_ZurSuT5NZFlu7iXPkOYvUVpXXaDjpJ6vTurMBPwPSWWUA4EL39E5d1Fa7ml_X867olpUlfMwr0bRiyHgLtuVQ==", authorization.signature)
	}
}

func TestNoAuthorizationHeader(t *testing.T) {
	_, err := parseAuthorizationHeader("")
	if err == nil {
		t.Errorf("Expected error: %s", ErrorMissingAuthorizationHeader)
	}
}

func TestMiddleware(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/api/eeze/v1/users/johnnyutah", strings.NewReader(""))
	r.Header.Set("date", time.Now().Format(time.RFC3339))

	privateKey, err := ssh.ParseRawPrivateKey([]byte(privateKeyPem))
	if err != nil {
		t.Fatal(err.Error())
	}

	if pk, ok := privateKey.(*rsa.PrivateKey); !ok {
		t.Fatal("expected *rsa.PrivateKey")
	} else {
		h := sha256.New()
		h.Write([]byte(fmt.Sprintf("date: %s", r.Header.Get("date"))))
		sig, _ := pk.Sign(rand.Reader, h.Sum(nil), &SHA256Hasher{})
		r.Header.Set("Authorization", fmt.Sprintf("Signature keyId=\"did:vvo:12H6btMP6hPy32VXbwKvGE#keys-1\",algorithm=\"RsaSignatureAuthentication2018\",headers=\"date\",signature=\"%s\"", base64.URLEncoding.EncodeToString(sig)))
	}

	w := httptest.NewRecorder()

	AuthenticationMiddleware(MockResolver{}).Middleware(successHandler).ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("Expected: %d, Actual: %d", http.StatusOK, w.Code)
	}
}

func TestMiddlewareWithPostBody(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/api/eeze/v1/users/johnnyutah", strings.NewReader("{ \"status\": \"awesomesauce\"}"))
	r.Header.Set("date", time.Now().Format(time.RFC3339))

	privateKey, err := ssh.ParseRawPrivateKey([]byte(privateKeyPem))
	if err != nil {
		t.Fatal(err.Error())
	}

	if pk, ok := privateKey.(*rsa.PrivateKey); !ok {
		t.Fatal("expected *rsa.PrivateKey")
	} else {
		h := sha256.New()
		h.Write([]byte(fmt.Sprintf("date: %s\n%s", r.Header.Get("date"), "{ \"status\": \"awesomesauce\"}")))

		sig, _ := pk.Sign(rand.Reader, h.Sum(nil), &SHA256Hasher{})
		r.Header.Set("Authorization", fmt.Sprintf("Signature keyId=\"did:vvo:12H6btMP6hPy32VXbwKvGE#keys-1\",algorithm=\"RsaSignatureAuthentication2018\",headers=\"date\",signature=\"%s\"", base64.URLEncoding.EncodeToString(sig)))
	}

	w := httptest.NewRecorder()

	AuthenticationMiddleware(MockResolver{}).Middleware(successHandler).ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("Expected: %d, Actual: %d", http.StatusOK, w.Code)
	}
}

func TestMiddlewareWithPostBodyDoesNotConsumeBody(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/api/eeze/v1/users/johnnyutah", strings.NewReader("{ \"status\": \"awesomesauce\"}"))
	r.Header.Set("date", time.Now().Format(time.RFC3339))

	privateKey, err := ssh.ParseRawPrivateKey([]byte(privateKeyPem))
	if err != nil {
		t.Fatal(err.Error())
	}

	if pk, ok := privateKey.(*rsa.PrivateKey); !ok {
		t.Fatal("expected *rsa.PrivateKey")
	} else {
		h := sha256.New()
		h.Write([]byte(fmt.Sprintf("date: %s\n%s", r.Header.Get("date"), "{ \"status\": \"awesomesauce\"}")))

		sig, _ := pk.Sign(rand.Reader, h.Sum(nil), &SHA256Hasher{})
		r.Header.Set("Authorization", fmt.Sprintf("Signature keyId=\"did:vvo:12H6btMP6hPy32VXbwKvGE#keys-1\",algorithm=\"RsaSignatureAuthentication2018\",headers=\"date\",signature=\"%s\"", base64.URLEncoding.EncodeToString(sig)))
	}

	w := httptest.NewRecorder()

	nextNeedsBody := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := ioutil.ReadAll(r.Body)
		if string(b) != "{ \"status\": \"awesomesauce\"}" {
			t.Errorf("Expected: %s, Actual: %s", "{ \"status\": \"awesomesauce\"}", string(b))
		}
		w.WriteHeader(http.StatusOK)
	})

	AuthenticationMiddleware(MockResolver{}).Middleware(nextNeedsBody).ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("Expected: %d, Actual: %d", http.StatusOK, w.Code)
	}
}

func TestMiddlewareInvalidSignature(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/api/eeze/v1/users/johnnyutah", strings.NewReader(""))
	r.Header.Set("date", time.Now().Format(time.RFC3339))

	privateKey, err := ssh.ParseRawPrivateKey([]byte(privateKeyPem))
	if err != nil {
		t.Fatal(err.Error())
	}

	if pk, ok := privateKey.(*rsa.PrivateKey); !ok {
		t.Fatal("expected *rsa.PrivateKey")
	} else {
		h := sha256.New()
		h.Write([]byte(fmt.Sprintf("date: %s", r.Header.Get("date"))))
		sig, _ := pk.Sign(rand.Reader, h.Sum(nil), &SHA256Hasher{})
		r.Header.Set("Authorization", fmt.Sprintf("Signature keyId=\"did:vvo:12H6btMP6hPy32VXbwKvGE#keys-1\",algorithm=\"RsaSignatureAuthentication2018\",headers=\"date\",signature=\"asdf%s\"", base64.URLEncoding.EncodeToString(sig)))
	}

	w := httptest.NewRecorder()

	AuthenticationMiddleware(MockResolver{}).Middleware(successHandler).ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected: %d, Actual: %d", http.StatusUnauthorized, w.Code)
	}
}
