package models

import "github.com/google/uuid"

type DataBundlesDto struct {
	Bundles []*DataBundleDto `json:"bundles"`
}

type DataBundleDto struct {
	PolicyId             uuid.UUID `json:"policyId,omitempty"`
	UserOverrideConsent  bool      `json:"userOverrideConsent"`
	AESEncryptedBundle   string    `json:"aesEncryptedBundle"`
	RSAEncryptedAESNonce string    `json:"rsaEncryptedAesNonce"`
	RSAEncryptedAESKey   string    `json:"rsaEncryptedAESKey"`
}
