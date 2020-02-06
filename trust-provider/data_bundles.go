package trustprovider

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
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
	"io"
	"log"
)

type DataBundleService struct {
	IdentityServerUrl string
}

type DataBundleServiceInterface interface {
	GetPublicKeysForDataBundleConsumers(identityId uuid.UUID, dataBundleType string) (*models.PublicKeysDto, error)
	EncryptDataBundleWithPublicKeys(dataBundle interface{}, publicKeysDto *models.PublicKeysDto) (*models.DataBundlesDto, error)
	PublishDataBundle(identityId uuid.UUID, dataBundleType string, dataBundle interface{}) error
	DecryptDataBundle(encryptedData string, privateKey *rsa.PrivateKey, destination interface{}) error
}

func NewDataBundleService(identityServiceUrl string) DataBundleServiceInterface {
	return &DataBundleService{IdentityServerUrl: identityServiceUrl}
}

func (d *DataBundleService) GetPublicKeysForDataBundleConsumers(identityId uuid.UUID, dataBundleType string) (*models.PublicKeysDto, error) {
	url := fmt.Sprintf("%s/id1/api/v1/identities/%s/policies/callbacks/%s/publicKeys", d.IdentityServerUrl, identityId, dataBundleType)

	var publicKeysDto models.PublicKeysDto
	resp, err := utils.Resty(context.Background()).R().
		SetResult(&publicKeysDto).
		Get(url)

	if err != nil {
		return nil, fmt.Errorf("failed to request publickeys from identity-server: %s", err.Error())
	}

	if resp.StatusCode() != 200 {
		return nil, fmt.Errorf("unexpected response [%d] from identity-server while retrieving publicKeys: %s", resp.StatusCode(), resp.Body())
	}

	return &publicKeysDto, nil
}

func (d *DataBundleService) EncryptDataBundleWithPublicKeys(dataBundle interface{}, publicKeysDto *models.PublicKeysDto) (*models.DataBundlesDto, error) {
	b, err := json.Marshal(dataBundle)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal dataBundle: %s", err.Error())
	}

	dataBundlesDto := &models.DataBundlesDto{
		Bundles: make([]*models.DataBundleDto, 0),
	}

	// Generate Random Key to AES Encrypt the payloads
	key := make([]byte, 32)
	rand.Read(key)

	for _, v := range publicKeysDto.PublicKeys {
		block, _ := pem.Decode([]byte(v.PublicKey))
		if block == nil {
			log.Printf("failed to pem.Decode for policyId %s", v.PolicyId)
			continue
		}
		rsaPubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			log.Printf("failed to ParsePKIXPublicKey for policyId %s: %s", v.PolicyId, err.Error())
			continue
		}

		pubKey, ok := rsaPubKey.(*rsa.PublicKey)
		if !ok {
			log.Printf("failed rsaPubKey.(*rsa.PublicKey) cast for policyId %s", v.PolicyId)
			continue
		}

		aesEncryptedPayload, nonce, err := EncryptPayloadRandomAES256(b, key)
		if err != nil {
			log.Printf("failed to AES-265 encrypt payload for policyId %s: %s", v.PolicyId, err.Error())
			continue
		}

		rsaEncryptedNonce, err := rsa.EncryptPKCS1v15(rand.Reader, pubKey, nonce)
		if err != nil {
			log.Printf("failed to rsa.EncryptPKCS1v15 nonce for policyId %s: %s", v.PolicyId, err.Error())
			continue
		}

		rsaEncryptedKey, err := rsa.EncryptPKCS1v15(rand.Reader, pubKey, key)
		if err != nil {
			log.Printf("failed to rsa.EncryptPKCS1v15 nonce for policyId %s: %s", v.PolicyId, err.Error())
			continue
		}

		encodedPayload := base64.StdEncoding.EncodeToString(aesEncryptedPayload)
		encodedNonce := base64.StdEncoding.EncodeToString(rsaEncryptedNonce)
		encodedKey := base64.StdEncoding.EncodeToString(rsaEncryptedKey)

		dataBundlesDto.Bundles = append(dataBundlesDto.Bundles, &models.DataBundleDto{
			PolicyId:             v.PolicyId,
			AESEncryptedBundle:   encodedPayload,
			RSAEncryptedAESNonce: encodedNonce,
			RSAEncryptedAESKey:   encodedKey,
		})
	}

	return dataBundlesDto, nil
}

func (d *DataBundleService) PublishDataBundle(identityId uuid.UUID, dataBundleType string, dataBundle interface{}) error {
	publicKeysDto, err := d.GetPublicKeysForDataBundleConsumers(identityId, dataBundleType)
	if err != nil {
		return err
	}

	dataBundlesDto, err := d.EncryptDataBundleWithPublicKeys(dataBundle, publicKeysDto)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/id1/api/v1/identities/%s/dataBundle/%s", d.IdentityServerUrl, identityId, dataBundleType)
	resp, err := utils.Resty(context.Background()).R().
		SetBody(dataBundlesDto).
		Post(url)

	if err != nil {
		return fmt.Errorf("PublishDataBundle: failed to make request to identity-server: %s", err.Error())
	}

	if resp.StatusCode() != 200 {
		return fmt.Errorf("unexpected response [%d] from identity-server while retrieving publicKeys: %s", resp.StatusCode(), resp.Body())
	}

	return nil
}

func (d *DataBundleService) DecryptDataBundle(encryptedData string, privateKey *rsa.PrivateKey, destination interface{}) error {
	decodedBundle, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return fmt.Errorf("failed to base64 decode encryptedBundle: %s", err.Error())
	}

	dec, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, decodedBundle)
	if err != nil {
		return fmt.Errorf("failed to decrypt bundle: %s", err.Error())
	}

	err = json.Unmarshal(dec, destination)
	if err != nil {
		return fmt.Errorf("failed to unmarshal dataBundle into destination interface: %s", err.Error())
	}

	return nil
}

func EncryptPayloadRandomAES256(payload []byte, key []byte) ([]byte, []byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Printf("unable to create aes cipher: %s", err.Error())
		return nil, nil, err
	}

	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		fmt.Printf("unable to generate nonce: %s", err.Error())
		return nil, nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		fmt.Printf("unable to wrap block cipher: %s", err.Error())
		return nil, nil, err
	}

	encryptedPayload := aesgcm.Seal(nil, nonce, payload, nil)

	return encryptedPayload, nonce, nil
}

func decryptPayloadAES(encryptedPayload []byte, nonce []byte, key []byte, res interface{}) error {
	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Printf("unable to use key to generate block cipher: %s", err.Error())
		return err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		fmt.Printf("unable to wrap block cipher: %s", err.Error())
		return err
	}

	data, err := aesgcm.Open(nil, nonce, encryptedPayload, nil)
	if err != nil {
		fmt.Printf("unable to decrypt payload: %s", err.Error())
		return err
	}

	err = json.Unmarshal(data, &res)
	if err != nil {
		fmt.Printf("unable to unmarshal unencrypted payload: %s", err.Error())
		return err
	}

	return nil
}

func DecryptPayload(data models.PublishWrapperDto, privateKey string, res interface{}) error {
	encryptedPayload, err := base64.StdEncoding.DecodeString(data.Data)
	if err != nil {
		fmt.Printf("unable to decode payload: %s", err.Error())
		return err
	}
	encryptedNonce, err := base64.StdEncoding.DecodeString(data.EncryptedNonce)
	if err != nil {
		fmt.Printf("unable to decode nonce: %s", err.Error())
		return err
	}
	encryptedKey, err := base64.StdEncoding.DecodeString(data.EncryptedKey)
	if err != nil {
		fmt.Printf("unable to decode key: %s", err.Error())
		return err
	}

	rsaPrivateKey, err := parsePrivateKey(privateKey)
	if err != nil {
		fmt.Printf("unable to parse private key: %s", err.Error())
		return err
	}

	nonce, err := rsa.DecryptPKCS1v15(rand.Reader, rsaPrivateKey, encryptedNonce)
	if err != nil {
		fmt.Printf("failed to decrypt nonce: %s", err.Error())
		return err
	}

	key, err := rsa.DecryptPKCS1v15(rand.Reader, rsaPrivateKey, encryptedKey)
	if err != nil {
		fmt.Printf("failed to decrypt key: %s", err.Error())
		return err
	}

	err = decryptPayloadAES(encryptedPayload, nonce, key, &res)
	if err != nil {
		fmt.Printf("failed to decrypt payload: %s", err.Error())
		return err
	}

	return nil
}

func parsePrivateKey(pkPem string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pkPem))
	if block == nil {
		log.Printf("failed to pem.Decode privateKey string: block is nil")
		return nil, fmt.Errorf("failed to pem.Decode privateKey string: block is nil")
	}

	pk, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Printf("failed to x509.ParsePKCS1PrivateKey: %s", err.Error())
		return nil, err
	}
	return pk, nil
}
