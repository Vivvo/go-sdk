package did

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"github.com/Vivvo/go-sdk/utils"
	"log"
)

type InvokeCapability struct {
	Id string `json:"id"`
	Action string `json:"action"`
	Proof utils.Proof `json:"proof"`
	ObjectCapability ObjectCapability `json:"objectCapability"`
}


func (i *InvokeCapability) Verify(resolver ResolverInterface) error {

	// need to get the resolver to get the person who signed it so we can go to the block chain and get the issuers public key....
	didDocument, err := resolver.Resolve(i.ObjectCapability.Capability.Creator)
	if err != nil {
		log.Printf("Error looking up creator did: %s,", err.Error())
		return err
	}
	log.Printf("%+v", didDocument)

	// Find the public key that the claim is using
	pubKey, err := didDocument.GetPublicKeyById(i.ObjectCapability.Capability.Creator)
	if err != nil {
		log.Printf("Error finding publicKey by did: %s", err.Error())
		return err
	}

	sig := i.Proof.SignatureValue

	options := utils.Proof{Typ: i.Proof.Typ, Created: i.Proof.Created, Creator: i.ObjectCapability.Capability.Creator, SignatureValue: i.Proof.SignatureValue, ProofPurpose: i.Proof.ProofPurpose, Capability: i.Proof.Capability}
	i.ObjectCapability.Proof = nil

	credJson, err := utils.Canonicalize(i)
	if err != nil {
		log.Printf("Error conancalizing i: %s", err.Error())
		return err
	}

	optionsJson, err := utils.Canonicalize(options)
	if err != nil {
		log.Printf("Error conancalizing options: %s", err.Error())
		return err
	}

	// Build hash string
	h := sha256.New()
	_, err = h.Write(credJson)
	if err != nil {
		log.Printf("Error hashing credJson: %s", err.Error())
		return err
	}

	optionsHash := sha256.New()
	_, err = optionsHash.Write(optionsJson)
	if err != nil {
		log.Printf("Error hashing options: %s", err.Error())
		return err
	}

	hashString := append(h.Sum(nil), optionsHash.Sum(nil)...)
	h = sha256.New()
	_, err = h.Write(hashString)
	if err != nil {
		log.Printf("Error appending the two hashes: %s", err.Error())
		return err
	}

	decodedSig, err := base64.URLEncoding.DecodeString(sig)
	if err != nil {
		return err
	}

	err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, h.Sum(nil), decodedSig)
	if err != nil {
		log.Printf("Error verifying signiture: %s", err.Error())
		return err
	}

	return nil
}


//func (i *InvokeCapability) Sign(privateKey *rsa.PrivateKey) (*ObjectCapability, error) {
//	proof := utils.Proof{
//		ProofPurpose: "capabilityDelegation",
//		Capability: i.Id,
//		Created: time.Now().Format("2006-01-02T15:04:05-0700"),
//		Creator: fmt.Sprintf("%s#keys-1", i.Creator),
//	}
//
//	o, p, err := utils.Sign(i, &proof, privateKey)
//	if err != nil {
//		log.Panic(err.Error())
//		return nil, err
//	}
//
//	return &ObjectCapability{
//		Capability: o.(*Capability),
//		Proof: p,
//	}, nil
//}