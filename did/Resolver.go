package did

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/go-resty/resty"
	"log"
	"net/http"
	"os"
	"strings"
)

type Service struct {
	Id              string `json:"id"`
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
	Name           string           `json:"name,omitempty"`
	Logo           string           `json:"logo,omitempty"`
}

type ResolverInterface interface {
	Resolve(string) (*Document, error)
	Register(*Document, ...string) error
}

type Resolver struct {
	DidBaseUrl string
}

func (d *Document) GetPublicKeyById(id string) (*rsa.PublicKey, error) {
	for _, v := range d.PublicKey {
		if strings.Compare(v.Id, id) == 0 {
			block, _ := pem.Decode([]byte(v.PublicKeyPem))
			if block == nil {
				log.Printf("[%s]: %s", id, v.PublicKeyPem)
				return nil, errors.New("unable to decode public key pem")
			}
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

	didUrl := d.DidBaseUrl
	if d.DidBaseUrl == "" {
		didUrl = os.Getenv("MOCK_BLOCKCHAIN_URL")
	}

	var didDocument = Document{}

	resp, err := resty.New().R().
		SetResult(&didDocument).
		Get(fmt.Sprintf("%s/api/v1/did/%s", didUrl, did))

	if err != nil {
		return nil, err
	}

	if resp.StatusCode() != http.StatusOK {
		return nil, errors.New(resp.Status())
	}

	return &didDocument, nil
}

func (d *Resolver) Register(ddoc *Document, opts ...string) error {
	log.Println("didBaseUrl: ", d.DidBaseUrl)
	var body = struct {
		Parent      string    `json:"parent,omitempty"`
		PairwiseDid string    `json:"pairwiseDid,omitempty"`
		DidDocument *Document `json:"didDocument"`
	}{DidDocument: ddoc}

	if len(opts) >= 1 {
		body.Parent = opts[0]
	}

	if len(opts) >= 2 {
		body.PairwiseDid = opts[1]
	}

	_, err := resty.New().
		R().
		SetBody(&body).
		Post(fmt.Sprintf("%s/api/v1/did", d.DidBaseUrl))

	if err != nil {
		log.Println(err.Error())
		return err
	}

	return nil
}
