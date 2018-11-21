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

	proof.SignatureValue = base64.StdEncoding.EncodeToString(sig)
	proof.Typ = "RsaSignature2018"

	return o, proof, nil
}
//
//func Verify(o interface{}, types []string, nonce string, resolver ResolverInterface) error {
//
//	if nonce != "" && strings.Compare(nonce, vc.Proof.Nonce) != 0 {
//		return errors.New("invalid nonce")
//	}
//
//	//FIXME: We must always validate at least one type - otherwise the consumer may not be sure the claim
//	// says what they think it says...
//	if len(types) > 0 {
//		for i, t := range types {
//			if strings.Compare(vc.Type[i], t) != 0 {
//				return errors.New(fmt.Sprintf("missing type %s", t))
//			}
//		}
//	}
//
//	didDocument, err := resolver.Resolve(vc.Issuer)
//	if err != nil {
//		return err
//	}
//
//	// Find the public key that the claim is using
//	pubKey, err := didDocument.GetPublicKeyById(vc.Proof.Creator)
//	if err != nil {
//		return err
//	}
//
//	sig := vc.Proof.SignatureValue
//
//	options := utils.Proof{Created: vc.Proof.Created, Creator: vc.Proof.Creator, Nonce: vc.Proof.Nonce}
//	vc.Proof = nil
//
//	credJson, err := utils.Canonicalize(vc)
//	if err != nil {
//		return err
//	}
//
//	optionsJson, err := utils.Canonicalize(options)
//	if err != nil {
//		return err
//	}
//
//	// Build hash string
//	h := sha256.New()
//	_, err = h.Write(credJson)
//	if err != nil {
//		return err
//	}
//
//	optionsHash := sha256.New()
//	_, err = optionsHash.Write(optionsJson)
//	if err != nil {
//		return err
//	}
//
//	hashString := append(h.Sum(nil), optionsHash.Sum(nil)...)
//	h = sha256.New()
//	_, err = h.Write(hashString)
//	if err != nil {
//		return err
//	}
//
//	decodedSig, err := base64.URLEncoding.DecodeString(sig)
//	if err != nil {
//		return err
//	}
//
//	err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, h.Sum(nil), decodedSig)
//	if err != nil {
//		return err
//	}
//
//	return nil
//}