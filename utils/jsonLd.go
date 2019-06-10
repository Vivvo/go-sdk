package utils

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
)

type SHA256Hasher struct {
}

func (s *SHA256Hasher) HashFunc() crypto.Hash {
	return crypto.SHA256
}

// Converts struct `o` to a lexicographically sorted json object
func Canonicalize(o interface{}) ([]byte, error) {
	var credMap map[string]interface{}
	credJson, err := json.Marshal(o)
	if err != nil {
		return nil, err
	}
	json.Unmarshal(credJson, &credMap)
	sortedCred, err := json.Marshal(credMap)
	if err != nil {
		return nil, err
	}

	return sortedCred, nil
}

func CanonicalizeAndHash(o interface{}) ([]byte, error) {
	canonicalized, err := Canonicalize(o)
	if err != nil {
		return nil, err
	}

	h := sha256.New()
	_, err = h.Write(canonicalized)
	return h.Sum(nil), nil
}

func Sign(o interface{}, proof *Proof, privateKey *rsa.PrivateKey) (*Proof, error) {
	claimHash, err := CanonicalizeAndHash(o)
	if err != nil {
		return nil, err
	}

	proofHash, err := CanonicalizeAndHash(proof)

	h := sha256.New()
	_, err = h.Write(append(claimHash, proofHash...))
	if err != nil {
		return nil, err
	}

	sig, err := privateKey.Sign(rand.Reader, h.Sum(nil), &SHA256Hasher{})
	if err != nil {
		return nil, err
	}

	proof.SignatureValue = base64.URLEncoding.EncodeToString(sig)
	proof.Typ = "RsaSignature2018"

	return proof, nil
}

func SignDomain(url string, clientId string) (string, error) {

	// Generate a secretKey based on a "random" salt and the clientId
	// This ensures every Eeze domain will have a different url signature
	// even if they try to use the same url
	h1 := hmac.New(sha256.New, []byte("aGVsbG8gZnJvbSB2aXZ2byB0aGlzIGlzIGEgbG9uZyByYW5kb20gc3RyaW5nIGxvbA=="))
	h1.Write([]byte(clientId))
	secretKey := h1.Sum(nil)

	// perform an HMAC with	the secretKey and the url
	h := hmac.New(sha256.New, secretKey)
	h.Write([]byte(url))

	return base64.URLEncoding.EncodeToString(h.Sum(nil)), nil
}

func VerifyDomain(url string, clientId string, signature string) (bool, error) {
	sig, err := SignDomain(url, clientId)
	return strings.Compare(sig, signature) == 0, err
}
