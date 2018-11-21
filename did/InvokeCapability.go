package did

import (
	"github.com/Vivvo/go-sdk/utils"
)

type InvokeCapability struct {
	Id string `json:"id"`
	Action string `json:"action"`
	Proof utils.Proof `json:"proof"`
	ObjectCapability ObjectCapability `json:"objectCapability"`
}


//func (c *ObjectCapability) Verify(resolver ResolverInterface) error {
//
//	// need to get the resolver to get the person who signed it so we can go to the block chain and get the issuers public key....
//	didDocument, err := resolver.Resolve(c.Capability.Creator)
//	if err != nil {
//		return err
//	}
//
//	// Find the public key that the claim is using
//	pubKey, err := didDocument.GetPublicKeyById(c.Proof.Creator)
//	if err != nil {
//		return err
//	}
//
//	sig := c.Proof.SignatureValue
//
//	options := utils.Proof{Created: c.Proof.Created, Creator: c.Proof.Creator}
//	c.Proof = nil
//
//	credJson, err := utils.Canonicalize(c)
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


//func (c *InvokeCapability) Sign(privateKey *rsa.PrivateKey) (*ObjectCapability, error) {
//	proof := utils.Proof{
//		ProofPurpose: "capabilityDelegation",
//		Capability: c.Id,
//		Created: time.Now().Format("2006-01-02T15:04:05-0700"),
//		Creator: fmt.Sprintf("%s#keys-1", c.Creator),
//	}
//
//	o, p, err := utils.Sign(c, &proof, privateKey)
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