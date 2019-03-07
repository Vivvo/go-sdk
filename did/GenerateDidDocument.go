package did

import (
	"encoding/json"
	"fmt"
	"github.com/Vivvo/go-wallet"
)

type GenerateDidDocument struct {
	Resolver ResolverInterface
}

func (g *GenerateDidDocument) Generate(id string, w *wallet.Wallet, publish bool, serviceEndpoints ...Service) (*Document, error) {
	var doc Document
	doc.Context = "https://w3id.org/did/v1"
	doc.Id = id

	rsaPublicKey, err := w.Crypto().GenerateRSAKey("RsaVerificationKey2018", id)
	if err != nil {
		return nil, err
	}

	ed25519PublicKey, err := w.Crypto().GenerateEd25519Key("Ed25519KeyExchange2018", id)
	if err != nil {
		return nil, err
	}

	pubKey := PublicKey{
		Owner:        id,
		Id:           fmt.Sprintf("%s#keys-1", id),
		T:            "RsaVerificationKey2018",
		PublicKeyPem: rsaPublicKey,
	}

	pubKey2 := PublicKey{
		Owner:           id,
		Id:              fmt.Sprintf("%s#keys-2", id),
		T:               "Ed25519KeyExchange2018",
		PublicKeyBase58: ed25519PublicKey,
	}

	doc.PublicKey = []PublicKey{pubKey, pubKey2}

	auth := Authentication{}
	auth.PublicKey = pubKey.Id
	auth.T = "RsaSignatureAuthentication2018"
	doc.Authentication = []Authentication{auth}

	doc.Service = serviceEndpoints

	docJson, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}

	err = w.Dids().Create(doc.Id, string(docJson), nil)
	if err != nil {
		return nil, err
	}

	if publish {
		err = g.Resolver.Register(&doc)
		if err != nil {
			return nil, err
		}
	}

	return &doc, err
}
