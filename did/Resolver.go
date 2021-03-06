package did

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/btcsuite/btcutil/base58"
	"golang.org/x/crypto/ed25519"
	"gopkg.in/resty.v1"
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

func (d *Document) GetKeyByType(typ string) (*PublicKey, error) {
	var key *PublicKey
	for _, v := range d.PublicKey {
		if v.T == typ {
			key = &v
		}
	}

	if key == nil {
		return nil, errors.New(fmt.Sprintf("document %s has no publicKey with type %s", d.Id, typ))
	}

	return key, nil
}

func (d *Document) GetPublicKeyById(id string) (crypto.PublicKey, string, error) {
	for _, v := range d.PublicKey {
		if strings.Compare(v.Id, id) == 0 {
			if strings.Compare(v.T, "RsaVerificationKey2018") == 0 {
				block, _ := pem.Decode([]byte(v.PublicKeyPem))
				if block == nil {
					log.Printf("[%s]: %s", id, v.PublicKeyPem)
					return nil, "", errors.New("unable to decode public key pem")
				}
				rsaPubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
				if err != nil {
					return nil, "", err
				}

				if pubKey, ok := rsaPubKey.(*rsa.PublicKey); ok {
					return pubKey, v.T, nil
				} else {
					return nil, "", errors.New("expected *rsa.PublicKey")
				}
			} else if strings.Compare(v.T, "Ed25519VerificationKey2018") == 0 {
				kbytes := base58.Decode(v.PublicKeyBase58)

				return ed25519.PublicKey(kbytes), v.T, nil
			}
		}
	}
	return nil, "", errors.New(fmt.Sprintf("public key [%s] not found in did document", id))
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
	didUrl := d.DidBaseUrl
	if d.DidBaseUrl == "" {
		didUrl = os.Getenv("MOCK_BLOCKCHAIN_URL")
	}
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

	resp, err := resty.New().
		R().
		SetBody(&body).
		Post(fmt.Sprintf("%s/api/v1/did", didUrl))

	if err != nil {
		log.Println(err.Error())
		return err
	}

	if resp.StatusCode() != http.StatusCreated {
		return errors.New(fmt.Sprintf("Expected: %d, Actual: %d", http.StatusCreated, resp.StatusCode()))
	}
	return nil
}
