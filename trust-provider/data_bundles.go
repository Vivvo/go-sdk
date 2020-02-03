package trustprovider

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/Vivvo/go-sdk/models"
	"github.com/Vivvo/go-sdk/utils"
	"github.com/google/uuid"
	"log"
)

type DataBundleService struct {
	IdentityServerUrl string
}

func (d *DataBundleService) getPublicKeysForDataBundleConsumers(identityId uuid.UUID, dataBundleType string) (*models.PublicKeysDto, error) {
	url := fmt.Sprintf("%s/id1/api/v1/identities/%s/policies/callbacks/%s/publicKeys", d.IdentityServerUrl, identityId, dataBundleType)

	var publicKeysDto models.PublicKeysDto
	resp, err := utils.Resty(context.Background()).R().
		SetResult(&publicKeysDto).
		Get(url)

	if err != nil {
		return nil, fmt.Errorf("failed to request publickeys from identity-server: %w", err)
	}

	if resp.StatusCode() != 200 {
		return nil, fmt.Errorf("unexpected response [%d] from identity-server while retrieving publicKeys: %s", resp.StatusCode(), resp.Body())
	}

	return &publicKeysDto, nil
}

func (d *DataBundleService) encryptDataBundleWithPublicKeys(dataBundle interface{}, publicKeysDto *models.PublicKeysDto) (*models.DataBundlesDto, error) {
	b, err := json.Marshal(dataBundle)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal dataBundle: %w", err)
	}

	dataBundlesDto := &models.DataBundlesDto{
		Bundles: make([]*models.DataBundleDto, 0),
	}
	for _, v := range publicKeysDto.PublicKeys {
		block, _ := pem.Decode([]byte(v.PublicKey))
		if block == nil {
			log.Printf("failed to pem.Decode for policyId %s", v.PolicyId)
			continue
		}
		rsaPubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			log.Printf("failed to ParsePKIXPublicKey for policyId %s", v.PolicyId)
			continue
		}

		pubKey, ok := rsaPubKey.(*rsa.PublicKey)
		if !ok {
			log.Printf("failed rsaPubKey.(*rsa.PublicKey) cast for policyId %s", v.PolicyId)
			continue
		}

		enc, err := rsa.EncryptPKCS1v15(rand.Reader, pubKey, b)
		if err != nil {
			log.Printf("failed to rsa.EncryptPKCS1v15 for policyId %s", v.PolicyId)
			continue
		}

		log.Printf("encrypt - encrypted bundle: %s", enc)
		encodedString := base64.StdEncoding.EncodeToString(enc)
		log.Printf("encrypt - encrypted encoded string: %s", encodedString)
		dataBundlesDto.Bundles = append(dataBundlesDto.Bundles, &models.DataBundleDto{
			PolicyId:        v.PolicyId,
			EncryptedBundle: encodedString,
		})
		log.Printf("decrypt - dataBundlesDto: %+v", dataBundlesDto)
	}

	return dataBundlesDto, nil
}

func (d *DataBundleService) PublishDataBundle(identityId uuid.UUID, dataBundleType string, dataBundle interface{}) error {
	publicKeysDto, err := d.getPublicKeysForDataBundleConsumers(identityId, dataBundleType)
	if err != nil {
		return err
	}

	dataBundlesDto, err := d.encryptDataBundleWithPublicKeys(dataBundle, publicKeysDto)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/id1/api/v1/identities/%s/dataBundle/%s", d.IdentityServerUrl, identityId, dataBundleType)
	resp, err := utils.Resty(context.Background()).R().
		SetBody(dataBundlesDto).
		Post(url)

	if err != nil {
		return fmt.Errorf("PublishDataBundle: failed to make request to identity-server: %w", err)
	}

	if resp.StatusCode() != 200 {
		return fmt.Errorf("unexpected response [%d] from identity-server while retrieving publicKeys: %s", resp.StatusCode(), resp.Body())
	}

	return nil
}

func (d *DataBundleService) DecryptDataBundle(dto *models.DataBundleDto, privateKey *rsa.PrivateKey, destination interface{}) error {
	decodedBundle, err := base64.StdEncoding.DecodeString(dto.EncryptedBundle)
	if err != nil {
		return fmt.Errorf("failed to base64 decode encryptedBundle: %w", err)
	}

	log.Printf("decrypt - decoded bundle: %+v", decodedBundle)

	dec, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, decodedBundle)
	if err != nil {
		return fmt.Errorf("failed to decrypt bundle: %w", err)
	}

	err = json.Unmarshal(dec, destination)
	if err != nil {
		return fmt.Errorf("failed to unmarshal dataBundle into destination interface: %s", err)
	}

	return nil
}