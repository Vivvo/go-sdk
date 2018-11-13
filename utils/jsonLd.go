package utils

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
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

func Sign(o interface{}, proof *Proof, privateKey *rsa.PrivateKey) (interface{}, *Proof, error) {
	claimHash, err := CanonicalizeAndHash(o)
	if err != nil {
		return o, nil, err
	}

	proofHash, err := CanonicalizeAndHash(proof)

	h := sha256.New()
	_, err = h.Write(append(claimHash, proofHash...))
	if err != nil {
		return o, nil, err
	}

	sig, err := privateKey.Sign(rand.Reader, h.Sum(nil), &SHA256Hasher{})
	if err != nil {
		return o, nil, err
	}

	proof.SignatureValue = base64.URLEncoding.EncodeToString(sig)
	proof.Typ = "RsaSignature2018"

	return o, proof, nil
}