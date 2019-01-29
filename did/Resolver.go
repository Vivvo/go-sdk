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
}

type ResolverInterface interface {
	Resolve(string) (*Document, error)
	Register(*Document) error
}

type MobileResolverInterface interface {
	Resolve(string) (*Document, error)
	RegisterMobile(string, string, *Document) error
}

type Resolver struct {
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

	var didDocument = Document{}

	resp, err := resty.New().R().
		SetResult(&didDocument).
		Get(fmt.Sprintf("%s/api/v1/did/%s", os.Getenv("MOCK_BLOCKCHAIN_URL"), did))

	if err != nil {
		return nil, err
	}

	if resp.StatusCode() != http.StatusOK {
		return nil, errors.New(resp.Status())
	}

	return &didDocument, nil
}

func (d *Resolver) Register(ddoc *Document) error {

	var body = struct {
		DidDocument *Document `json:"didDocument"`
	}{DidDocument: ddoc}

	_, err := resty.New().
		R().
		SetBody(&body).
		Post(fmt.Sprintf("%s/api/v1/did", os.Getenv("MOCK_BLOCKCHAIN_URL")))

	if err != nil {
		log.Println(err.Error())
		return err
	}

	return nil
}

func (d *Resolver) RegisterMobile(parent string, pairwiseDid string, ddoc *Document) error {
	var body = struct {
		Parent      string    `json:"parent,omitempty"`
		PairwiseDid string    `json:"pairwiseDid,omitempty"`
		DidDocument *Document `json:"didDocument"`
	}{Parent: parent, PairwiseDid: pairwiseDid, DidDocument: ddoc}

	_, err := resty.New().
		R().
		SetBody(&body).
		Post(fmt.Sprintf("%s/api/v1/did", os.Getenv("MOCK_BLOCKCHAIN_URL")))

	if err != nil {
		log.Println(err.Error())
		return err
	}

	return nil
}
