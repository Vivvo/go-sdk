package did

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"github.com/Vivvo/go-sdk/utils"
	"log"
	"strings"
)

type InvokeCapability struct {
	Id          string       `json:"id"`
	Action      string       `json:"action"`
	InvokeProof *InvokeProof `json:"proof,omitempty"`
}

type InvokeOptions struct {
	Created      string `json:"created"`
	Creator      string `json:"creator"`
	ProofPurpose string `json:"proofPurpose"`
}

type InvokeProof struct {
	Type             string           `json:"type,omitempty"`
	Created          string           `json:"created,omitempty"`
	Creator          string           `json:"creator,omitempty"`
	SignatureValue   string           `json:"signatureValue,omitempty"`
	ProofPurpose     string           `json:"proofPurpose,omitempty"`
	ObjectCapability ObjectCapability `json:"objectCapability,omitempty"`
}

func (i *InvokeCapability) VerifyInvocation(issuer string, resolver ResolverInterface) (map[string][]string, error) {
	ocapInvoker, capabilities, err := VerifyOCaps(i.InvokeProof.ObjectCapability, issuer, resolver)
	if err != nil {
		log.Println("Failed to verify ocaps.")
		return nil, err
	}
	if i.InvokeProof.Creator != ocapInvoker {
		log.Println("Invoker does not match the creator.")
		return nil, errors.New("incorrect invoker")
	}

	// TODO: Check actions invoked are granted by the capability and not excluded by any caveats.
	err = i.verify(resolver)
	if err != nil {
		log.Println("Failed to verify the invocation.")
	}
	return capabilities, err
}

func VerifyOCaps(ocap ObjectCapability, issuer string, resolver ResolverInterface) (string, map[string][]string, error) {
	var capabilities map[string][]string
	if ocap.ParentCapability == nil {
		//FIXME: Need to take in the expected issuer
		if ocap.Proof.Creator != issuer {
			log.Printf("The base ocap was not issued by [%s].", issuer)
			return "", nil, errors.New("unexpected issuer")
		}
		capabilities = ocap.Capabilities
	} else {
		var parentInvoker string
		var err error
		parentInvoker, capabilities, err = VerifyOCaps(*ocap.ParentCapability, issuer, resolver)
		if err != nil {
			return "", nil, err
		}
		if ocap.Proof.Creator != parentInvoker {
			log.Println("Creator does not match the parent invoker.")
			return "", nil, errors.New("incorrect invoker")
		}
	}

	err := ocap.Verify(resolver)
	if err != nil {
		log.Printf("Error verifying ocap: %s", err.Error())
		return "", nil, err
	}

	return ocap.Invoker, capabilities, nil
}

func (c *InvokeCapability) verify(resolver ResolverInterface) error {
	// FIXME: Utility to do this with some validation!
	did := strings.Split(c.InvokeProof.Creator, "#")[0]

	// need to get the resolver to get the person who signed it so we can go to the block chain and get the issuers public key....
	didDocument, err := resolver.Resolve(did)
	if err != nil {
		return err
	}

	// Find the public key that the claim is using
	pubKey, err := didDocument.GetPublicKeyById(c.InvokeProof.Creator)
	if err != nil {
		return err
	}

	sig := c.InvokeProof.SignatureValue

	options := utils.Proof{Created: c.InvokeProof.Created, Creator: c.InvokeProof.Creator, ProofPurpose: c.InvokeProof.ProofPurpose}
	c.InvokeProof = nil

	credJson, err := utils.Canonicalize(c)
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
