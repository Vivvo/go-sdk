package utils

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
)

type SHA256Hasher struct {
}

type SHA1Hasher struct {
}

func (s *SHA1Hasher) HashFunc() crypto.Hash {
	return crypto.SHA1
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

	sig, err := privateKey.Sign(rand.Reader, h.Sum(nil), &SHA1Hasher{})
	if err != nil {
		return nil, err
	}

	proof.SignatureValue = base64.URLEncoding.EncodeToString(sig)
	proof.Typ = "RsaSignature2018"

	return proof, nil
}

func SignDomain(obj []byte, privateKey *rsa.PrivateKey) ([]byte, error) {

	h := sha1.New()
	_, err := h.Write([]byte(obj))
	if err != nil {
		return nil, err
	}

	sig, err := privateKey.Sign(rand.Reader, h.Sum(nil), &SHA1Hasher{})
	if err != nil {
		return nil, err
	}

	return sig, nil
}

func VerifyDomain(obj []byte, sig string, publicKey *rsa.PublicKey) error {
	h := sha1.New()
	_, err := h.Write(obj)
	if err != nil {
		return err
	}

	decodedSig, err := base64.URLEncoding.DecodeString(sig)
	if err != nil {
		return err
	}

	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, h.Sum(nil), decodedSig)
	if err != nil {
		return err
	}

	return nil
}
