package did

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"strings"
	"time"
)

const IAmMeCredential = "IAmMeCredential"
const ProofOfAgeCredential = "ProofOfAgeCredential"
const ProofOfLegalNameCredential = "ProofOfLegalNameCredential"
const ProofOfResidencyCredential = "ProofOfResidencyCredential"
const TokenizedConnectionCredential = "TokenizedConnectionCredential"
const VerifiableCredential = "VerifiableCredential"

const EmailAddressClaim = "emailAddress"
const FirstNameClaim = "firstName"
const LastNameClaim = "lastName"
const PublicKeyClaim = "publicKey"
const SubjectClaim = "id"
const TokenClaim = "token"

type Claim struct {
	Id     string                 `json:"id"`
	Type   []string               `json:"type"`
	Issuer string                 `json:"issuer"`
	Issued string                 `json:"issued"`
	Claim  map[string]interface{} `json:"claim"`
}

type VerifiableClaim struct {
	Id     string                 `json:"id"`
	Type   []string               `json:"type"`
	Issuer string                 `json:"issuer"`
	Issued string                 `json:"issued"`
	Claim  map[string]interface{} `json:"claim"`
	Proof  *Proof                 `json:"proof,omitempty"`
}

type Proof struct {
	Typ            string `json:"type,omitempty"`
	Created        string `json:"created,omitempty"`
	Creator        string `json:"creator,omitempty"`
	Nonce          string `json:"nonce,omitempty"`
	SignatureValue string `json:"signatureValue,omitempty"`
}

type SHA256Hasher struct {
}

func (s *SHA256Hasher) HashFunc() crypto.Hash {
	return crypto.SHA256
}

func (vc *Claim) Sign(privateKey *rsa.PrivateKey, nonce string) (VerifiableClaim, error) {
	claim := VerifiableClaim{
		Id:     vc.Id,
		Type:   vc.Type,
		Issuer: vc.Issuer,
		Issued: vc.Issued,
		Claim:  vc.Claim,
	}

	claimHash, err := canonicalizeAndHash(vc)
	if err != nil {
		return VerifiableClaim{}, nil
	}

	var proof = Proof{
		Created: time.Now().Format("2006-01-02T15:04:05-0700"),
		Creator: claim.Issuer,
		Nonce:   nonce,
	}
	proofHash, err := canonicalizeAndHash(proof)

	h := sha256.New()
	_, err = h.Write(append(claimHash, proofHash...))
	if err != nil {
		return VerifiableClaim{}, err
	}

	sig, err := privateKey.Sign(rand.Reader, h.Sum(nil), &SHA256Hasher{})
	if err != nil {
		return VerifiableClaim{}, err
	}

	proof.SignatureValue = base64.URLEncoding.EncodeToString(sig)
	proof.Typ = "RsaSignature2018"

	claim.Proof = &proof
	return claim, nil
}

func (vc *VerifiableClaim) Verify(types []string, nonce string, resolver ResolverInterface) error {

	if nonce != "" && strings.Compare(nonce, vc.Proof.Nonce) != 0 {
		return errors.New("invalid nonce")
	}

	//FIXME: We must always validate at least one type - otherwise the consumer may not be sure the claim
	// says what they think it says...
	if len(types) > 0 {
		for i, t := range types {
			if strings.Compare(vc.Type[i], t) != 0 {
				return errors.New(fmt.Sprintf("missing type %s", t))
			}
		}
	}

	didDocument, err := resolver.Resolve(vc.Issuer)
	if err != nil {
		return err
	}

	// Find the public key that the claim is using
	pubKey, err := didDocument.GetPublicKeyById(vc.Claim[PublicKeyClaim].(string))
	if err != nil {
		return err
	}

	sig := vc.Proof.SignatureValue

	options := Proof{Created: vc.Proof.Created, Creator: vc.Proof.Creator, Nonce: vc.Proof.Nonce}
	vc.Proof = nil

	credJson, err := canonicalizeVerifiableClaim(vc)
	if err != nil {
		return err
	}

	optionsJson, err := canonicalizeVerifiableClaim(options)
	if err != nil {
		return err
	}

	// Build hash string
	h := sha256.New()
	_, err = h.Write(credJson)
	if err != nil {
		return err
	}

	optionsHash := sha256.New()
	_, err = optionsHash.Write(optionsJson)
	if err != nil {
		return err
	}

	hashString := append(h.Sum(nil), optionsHash.Sum(nil)...)
	h = sha256.New()
	_, err = h.Write(hashString)
	if err != nil {
		return err
	}

	decodedSig, err := base64.URLEncoding.DecodeString(sig)
	if err != nil {
		return err
	}

	err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, h.Sum(nil), decodedSig)
	if err != nil {
		return err
	}

	return nil
}

// Converts struct `o` to a lexicographically sorted json object
func canonicalizeVerifiableClaim(o interface{}) ([]byte, error) {
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

func canonicalizeAndHash(o interface{}) ([]byte, error) {
	canonicalized, err := canonicalizeVerifiableClaim(o)
	if err != nil {
		return nil, err
	}

	h := sha256.New()
	_, err = h.Write(canonicalized)
	return h.Sum(nil), nil
}
