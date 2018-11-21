package did

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"github.com/Vivvo/go-sdk/utils"
	"github.com/pkg/errors"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
)

type authorization struct {
	did       string
	keyId     string
	algorithm string
	headers   []string
	signature string
}

const schema = "Signature "

var ErrorNotAuthorized = errors.New("not authorized")
var ErrorMissingAuthorizationHeader = errors.New("missing authorization header")

func AuthenticationMiddleware(resolver ResolverInterface, handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a, err := parseAuthorizationHeader(r.Header.Get("Authorization"))
		if err != nil {
			log.Println(err.Error())
			utils.SetErrorStatus(err, http.StatusUnauthorized, w)
			return
		}

		ddoc, err := resolver.Resolve(a.did)
		if err != nil {
			log.Println(err.Error())
			utils.SetErrorStatus(err, http.StatusUnauthorized, w)
			return
		}

		log.Println(a.keyId)
		pubkey, err := ddoc.GetPublicKeyById(a.keyId)
		if err != nil {
			log.Println(err.Error())
			utils.SetErrorStatus(err, http.StatusUnauthorized, w)
			return
		}

		decodedSig, err := base64.URLEncoding.DecodeString(a.signature)
		if err != nil {
			log.Println(err.Error())
			utils.SetErrorStatus(err, http.StatusUnauthorized, w)
			return
		}

		h := sha256.New()
		var signingString string
		for i, header := range a.headers {
			if i > 0 {
				signingString += "\n"
			}
			signingString += fmt.Sprintf("%s: %s", header, r.Header.Get(header))
		}
		body, err := ioutil.ReadAll(r.Body)
		if len(body) > 0 {
			signingString += fmt.Sprintf("\n%s", body)
		}

		h.Write([]byte(signingString))

		err = rsa.VerifyPKCS1v15(pubkey, crypto.SHA256, h.Sum(nil), decodedSig)
		if err != nil {
			utils.SetErrorStatus(err, http.StatusUnauthorized, w)
			return
		}

		handler.ServeHTTP(w, r)
	})
}

func parseAuthorizationHeader(h string) (*authorization, error) {
	a := authorization{}

	if !strings.HasPrefix(h, schema) {
		return nil, ErrorNotAuthorized
	}

	parts := strings.Split(h[len(schema):], ",")
	for _, part := range parts {
		pair := strings.SplitN(strings.Replace(part, "\"", "", -1), "=", 2)

		switch pair[0] {
		case "keyId":
			a.keyId = pair[1]
			a.did = strings.Split(pair[1], "#")[0]
		case "algorithm":
			a.algorithm = pair[1]
		case "headers":
			a.headers = strings.Split(pair[1], " ")
		case "signature":
			a.signature = pair[1]
		}
	}

	return &a, nil
}
