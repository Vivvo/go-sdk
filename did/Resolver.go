package did

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
)

type Service struct {
	T               string `json:"type"`
	ServiceEndpoint string `json:"serviceEndpoint"`
}

type Authentication struct {
	T         string `json:"type"`
	PublicKey string `json:"publicKey"`
}

type PublicKey struct {
	Id              string `json:"id"`
	T               string `json:"type"`
	Owner           string `json:"owner"`
	PublicKeyPem    string `json:"publicKeyPem"`
	PublicKeyBase58 string `json:"publicKeyBase58"`
}

type Document struct {
	Context        string           `json:"@context"`
	Id             string           `json:"id"`
	PublicKey      []PublicKey      `json:"publicKey"`
	Authentication []Authentication `json:"authentication"`
	Service        []Service        `json:"service"`
}

type ResolverInterface interface {
	Resolve(string) (*Document, error)
}

type Resolver struct {
}

func (d *Document) GetPublicKeyById(id string) (*rsa.PublicKey, error) {
	for _, v := range d.PublicKey {
		if strings.Compare(v.Id, id) == 0 {
			block, _ := pem.Decode([]byte(v.PublicKeyPem))
			rsaPubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				return nil, err
			}

			if pubKey, ok := rsaPubKey.(*rsa.PublicKey); ok {
				return pubKey, nil
			} else {
				return nil, errors.New("expected *rsa.PublicKey")
			}
		}
	}
	return nil, errors.New(fmt.Sprintf("public key [%s] not found in did document", id))
}

func (d *Resolver) Resolve(did string) (*Document, error) {
	// Get user DID from blockchain
	response, err := (&http.Client{}).Get(os.Getenv("MOCK_BLOCKCHAIN_URL") + did)
	if err != nil {
		return nil, err
	}

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	var didDocument Document
	err = json.Unmarshal(body, &didDocument)
	if err != nil {
		return nil, err
	}
	return &didDocument, nil
}
