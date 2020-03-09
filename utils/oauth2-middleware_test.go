package utils

import (
	"crypto/rand"
	"crypto/rsa"
	"github.com/dgrijalva/jwt-go"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOAuth2AuthorizationMiddleware(t *testing.T) {
	pk, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err.Error())
	}

	otherPk, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err.Error())
	}

	clientId := "my-client-id"

	tests := []struct {
		name           string
		audience       string
		expectedScopes []string
		scopes         []string
		signWith       *rsa.PrivateKey
		result         int
	}{
		{"correct audience", clientId, []string{}, []string{}, pk, http.StatusOK},
		{"correct scopes", clientId, []string{"some-scope"}, []string{"some-scope"}, pk, http.StatusOK},
		{"multiple scopes", clientId, []string{"some-scope", "another-scope"}, []string{"some-scope", "another-scope"}, pk, http.StatusOK},
		{"extra scopes", clientId, []string{"some-scope"}, []string{"some-scope", "another-scope"}, pk, http.StatusOK},
		{"incorrect signature", clientId, []string{}, []string{}, otherPk, http.StatusUnauthorized},
		{"incorrect audience", "the-wrong-client-id", []string{}, []string{}, pk, http.StatusUnauthorized},
		{"missing scopes", clientId, []string{"some-scope"}, []string{}, pk, http.StatusUnauthorized},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
				"aud":    tt.audience,
				"scope": tt.scopes,
			})

			signed, err := token.SignedString(tt.signWith)
			if err != nil {
				t.Fatal(err.Error())
			}

			o := OAuth2AuthorizationMiddleware{
				audience:  clientId,
				scopes:    tt.expectedScopes,
				publicKey: pk.Public().(*rsa.PublicKey),
			}

			rr := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "/protected-resource", nil)
			r.Header.Add("Authorization", "Bearer "+signed)

			o.Middleware(nil).ServeHTTP(rr, r)

			if rr.Result().StatusCode != tt.result {
				t.Fatalf("Expected: %d, Actual: %d", tt.result, rr.Result().StatusCode)
			}
		})
	}
}
