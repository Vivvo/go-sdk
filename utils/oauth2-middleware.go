package utils

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"golang.org/x/oauth2/jws"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
)

type OAuth2AuthorizationMiddleware struct {
	audience  string
	scopes    []string
	publicKey *rsa.PublicKey
}

func NewOAuth2AuthorizationMiddleware(audience string, scopes ...string) *OAuth2AuthorizationMiddleware {
	oAuthPublicKey, err := getOAuthPublicKey()
	if err != nil {
		log.Fatalf("Error fetching public key: %s", err.Error())
	}

	return &OAuth2AuthorizationMiddleware{
		audience:  audience,
		scopes:    scopes,
		publicKey: oAuthPublicKey,
	}
}

func toMap(scopes []interface{}) map[string]struct{} {
	scopeMap := make(map[string]struct{})

	for _, s := range scopes {
		if s, ok := s.(string); ok {
			scopeMap[s] = struct{}{}
		}
	}
	return scopeMap
}

func (o *OAuth2AuthorizationMiddleware) Middleware(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		logger := Logger(r.Context())
		defer logger.Sync()

		authorizationHeader, err := getHeader(r, "Authorization")
		if err != nil {
			logger.Infow("Missing authorization header. Could not authenticate request.")
			SetDetailedErrorStatus(http.StatusText(http.StatusBadRequest), "Missing authentication header", "missing authentication header", http.StatusBadRequest, rw)
			return
		}

		authHeaderSplit := strings.Split(authorizationHeader, " ")
		if len(authHeaderSplit) != 2 {
			logger.Infow("Authorization header is invalid. Could not authenticate request")
			SetDetailedErrorStatus(http.StatusText(http.StatusBadRequest), "Bad HTTP authentication header format", "invalid authentication header received, header requires both a token type and token", http.StatusBadRequest, rw)
			return
		}

		tokenType := authHeaderSplit[0]
		if !strings.EqualFold(tokenType, "bearer") {
			SetDetailedErrorStatus(http.StatusText(http.StatusBadRequest), "Bad HTTP authentication header format", "invalid authentication header received, invalid token type", http.StatusBadRequest, rw)
			return
		}

		accessToken := authHeaderSplit[1]
		err = jws.Verify(accessToken, o.publicKey)
		if err != nil {
			logger.Infow("Authorization header is invalid. Could not authenticate request")
			SetDetailedErrorStatus(http.StatusText(http.StatusUnauthorized), "Access token is invalid", err.Error(), http.StatusUnauthorized, rw)
			return
		}

		token, err := jwt.Parse(accessToken, func(token *jwt.Token) (interface{}, error) {
			return o.publicKey, nil
		})
		if err != nil {
			logger.Infow("Token is invalid. Could not authenticate request", "error", err)
			SetDetailedErrorStatus(http.StatusText(http.StatusUnauthorized), "Access token is invalid", "invalid token received, token could not be parsed", http.StatusUnauthorized, rw)
			return
		}

		claims := token.Claims.(jwt.MapClaims)

		err = claims.Valid()
		if err != nil {
			logger.Infow("Token is invalid. Could not authenticate request", "error", err)
			SetDetailedErrorStatus(http.StatusText(http.StatusUnauthorized), "Access token is invalid", err.Error(), http.StatusUnauthorized, rw)
			return
		}

		if claims["aud"] == nil {
			logger.Infow("Token is invalid. Could not authenticate request")
			SetDetailedErrorStatus(http.StatusText(http.StatusUnauthorized), "Access token is invalid", "invalid token received, token is missing claims", http.StatusUnauthorized, rw)
			return
		}

		foundMatchingAudience := false
		if aud, ok := claims["aud"].([]interface{}); ok {
			if len(aud) < 1 {
				logger.Infow("There is no aud attached to the claim.")
				SetDetailedErrorStatus(http.StatusText(http.StatusUnauthorized), "Access token is invalid", "invalid token received, token must have an aud claim", http.StatusUnauthorized, rw)
				return
			}

			for _, a := range aud {
				if a == o.audience {
					foundMatchingAudience = true
					break
				}
			}
		} else if aud, ok := claims["aud"].(string); ok && aud == o.audience {
			foundMatchingAudience = true
		}

		if !foundMatchingAudience {
			logger.Infow("Unable to find the expected audience")
			SetDetailedErrorStatus(http.StatusText(http.StatusUnauthorized), "Access token is invalid", "invalid token received, unexpected audience", http.StatusUnauthorized, rw)
			return
		}

		if o.scopes != nil && len(o.scopes) > 0 {
			missingScopes := make([]string, 0)
			if scopes, ok := claims["scope"].([]interface{}); len(o.scopes) > 0 && ok && len(scopes) > 0 {
				s := toMap(scopes)
				for _, requiredScope := range o.scopes {
					if _, ok := s[requiredScope]; !ok {
						missingScopes = append(missingScopes, requiredScope)
					}
				}
			} else {
				missingScopes = o.scopes
			}

			if len(missingScopes) != 0 {
				msg := fmt.Sprintf("invalid token received, missing required scope(s): [%s]", strings.Join(missingScopes, ", "))
				logger.Infow(msg)
				SetDetailedErrorStatus(http.StatusText(http.StatusUnauthorized), "Access token is invalid", msg, http.StatusUnauthorized, rw)
				return
			}
		}

		if handler != nil {
			handler.ServeHTTP(rw, r)
		}
	})
}

func getHeader(req *http.Request, key string) (string, error) {
	h := req.Header.Get(key)
	if h == "" || len(h) == 0 {
		return "", errors.New(fmt.Sprintf("missing %s", key))
	}

	return h, nil
}

func getOAuthPublicKey() (*rsa.PublicKey, error) {
	logger := Logger(context.Background())
	defer logger.Sync()

	var jwk *struct {
		KTY string `json:"kty"`
		N   string `json:"n"`
		E   string `json:"e"`
		Alg string `json:"alg"`
		Use string `json:"use"`
	}

	client := Resty(context.Background())

	_, err := client.R().
		SetResult(&jwk).
		SetHeader("Accept", "application/json").
		Get(os.Getenv("IDP_JWKS_URL"))

	if err != nil {
		logger.Error("Error making request to vivvo-idp: ", err.Error())
		return nil, err
	}

	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)

	if err != nil {
		logger.Error("Error decoding certs: ", err.Error())
		return nil, err
	}

	var n big.Int
	var e big.Int
	n.SetBytes(nBytes)
	e.SetBytes(eBytes)

	return &rsa.PublicKey{N: &n, E: int(e.Int64())}, nil
}
