package models

import "github.com/google/uuid"

type DataBundlesDto struct {
	Bundles []*DataBundleDto `json:"bundles"`
}

type DataBundleDto struct {
	PolicyId uuid.UUID `json:"policyId"`
	EncryptedBundle string `json:"encryptedBundle"`
}