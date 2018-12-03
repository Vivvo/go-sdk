package did

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"github.com/Vivvo/go-sdk/utils"
	"log"
	"strings"
	"time"
)

type Capability struct {
	Id               string              `json:"id"`
	Name             string              `json:"name,omitempty"`
	Description      string              `json:"description,omitempty"`
	ParentCapability *ObjectCapability   `json:"parentCapability,omitempty"`
	Invoker          string              `json:"invoker"`
	Caveat           []Caveat            `json:"caveat,omitempty"`
	Creator          string              `json:"creator"`
	Capabilities     map[string][]string `json:"capabilities"` // key is url to entity, values are action urls
}

type ObjectCapability struct {
	Id               string              `json:"id"`
	Name             string              `json:"name,omitempty"`
	Description      string              `json:"description,omitempty"`
	ParentCapability *ObjectCapability   `json:"parentCapability,omitempty"`
	Invoker          string              `json:"invoker"`
	Caveat           []Caveat            `json:"caveat,omitempty"`
	Creator          string              `json:"creator"`
	Capabilities     map[string][]string `json:"capabilities"` // key is url to entity, values are action urls
	Proof      		 *utils.Proof  		 `json:"proof,omitempty"`
}

type Caveat struct {
}

func (c *Capability) Sign(privateKey *rsa.PrivateKey) (ObjectCapability, error) {
	oCap := ObjectCapability{
		Id: c.Id,
		Name: c.Name,
		Description: c.Description,
		ParentCapability: c.ParentCapability,
		Invoker: c.Invoker,
		Caveat: c.Caveat,
		Creator: c.Creator,
		Capabilities: c.Capabilities,
	}

	proof := utils.Proof{
		ProofPurpose: "capabilityDelegation",
		Capability:   c.Id,
		Created:      time.Now().Format("2006-01-02T15:04:05-0700"),
		Creator:      fmt.Sprintf("%s#keys-1", c.Creator),
	}

	p, err := utils.Sign(oCap, &proof, privateKey)
	if err != nil {
		log.Panic(err.Error())
		return ObjectCapability{}, err
	}

	oCap.Proof = p

	return oCap, nil
}

func (o *ObjectCapability) Verify(resolver ResolverInterface) error {

	//TODO: Check a revocation list to make sure the ocap is not revoked!

	// FIXME: Utility to do this with some validation!
	did := strings.Split(o.Creator, "#")[0]

	// need to get the resolver to get the person who signed it so we can go to the block chain and get the issuers public key....
	didDocument, err := resolver.Resolve(did)
	if err != nil {
		return err
	}
	// Find the public key that the claim is using
	pubKey, err := didDocument.GetPublicKeyById(o.Proof.Creator)
	if err != nil {
		log.Println("Failed to get public key.")
		return err
	}

	sig := o.Proof.SignatureValue

	options := utils.Proof{Created: o.Proof.Created, Creator: o.Proof.Creator, ProofPurpose: o.Proof.ProofPurpose, Capability: o.Proof.Capability}
	o.Proof = nil

	credJson, err := utils.Canonicalize(o)
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
		log.Println("Failed to decode signature.")
		return err
	}

	err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, h.Sum(nil), decodedSig)
	if err != nil {
		return err
	}

	return nil
}
