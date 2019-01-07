package did

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"github.com/Vivvo/go-sdk/utils"
	"github.com/Vivvo/go-wallet"
	"github.com/pkg/errors"
	"log"
	"strings"
	"time"
)

const AuthenticationChallenge = "AuthenticationChallenge"
const DeviceRegistrationCredential = "DeviceRegistrationCredential"
const IAmMeCredential = "IAmMeCredential"
const ProofOfAgeCredential = "ProofOfAgeCredential"
const ProofOfBusinessOwnershipCredential = "ProofOfBusinessOwnershipCredential"
const ProofOfLegalNameCredential = "ProofOfLegalNameCredential"
const ProofOfResidencyCredential = "ProofOfResidencyCredential"
const TokenizedConnectionCredential = "TokenizedConnectionCredential"
const VerifiableCredential = "VerifiableCredential"

const AuthenticationChallengeClaim = "challenge"
const CallbackClaim = "callback"
const EmailAddressClaim = "emailAddress"
const FirstNameClaim = "firstName"
const LastNameClaim = "lastName"
const LogoClaim = "logo"
const NameClaim = "name"
const PublicKeyClaim = "publicKey"
const RequestedCapabilityClaim = "requestedCapability"
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
	Proof  *utils.Proof           `json:"proof,omitempty"`
}

type ChallengeResponse struct {
	VerifiableClaim  *VerifiableClaim   `json:"challengeResponse"`
	InvokeCapability []InvokeCapability `json:"invokeCapabilities"`
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

	proof := utils.Proof{
		Created: time.Now().Format("2006-01-02T15:04:05-0700"),
		Creator: fmt.Sprintf("%s#keys-1", claim.Issuer),
		Nonce:   nonce,
	}

	p, err := utils.Sign(vc, &proof, privateKey)
	if err != nil {
		log.Panic(err.Error())
		return VerifiableClaim{}, err
	}

	claim.Proof = p
	return claim, nil
}

func (vc *Claim) WalletSign(w *wallet.Wallet, id string, nonce string) (VerifiableClaim, error) {
	claim := VerifiableClaim{
		Id:     vc.Id,
		Type:   vc.Type,
		Issuer: vc.Issuer,
		Issued: vc.Issued,
		Claim:  vc.Claim,
	}

	proof := utils.Proof{
		Created: time.Now().Format("2006-01-02T15:04:05-0700"),
		Creator: fmt.Sprintf("%s#keys-1", claim.Issuer),
		Nonce:   nonce,
	}

	claimHash, err := utils.CanonicalizeAndHash(claim)
	if err != nil {
		return VerifiableClaim{}, err
	}

	proofHash, err := utils.CanonicalizeAndHash(proof)

	sig, err := w.Crypto().RS256Signature(id, append(claimHash, proofHash...))
	if err != nil {
		log.Println(err.Error())
		return VerifiableClaim{}, err
	}

	proof.SignatureValue = sig
	proof.Typ = "RsaSignature2018"

	claim.Proof = &proof
	return claim, nil
}

func (vc *VerifiableClaim)  Verify(types []string, nonce string, resolver ResolverInterface) error {

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
	pubKey, err := didDocument.GetPublicKeyById(vc.Proof.Creator)
	if err != nil {
		return err
	}

	sig := vc.Proof.SignatureValue

	options := utils.Proof{Created: vc.Proof.Created, Creator: vc.Proof.Creator, Nonce: vc.Proof.Nonce}
	vc.Proof = nil

	credJson, err := utils.Canonicalize(vc)
	if err != nil {
		return err
	}

	optionsJson, err := utils.Canonicalize(options)
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
