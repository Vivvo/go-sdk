package models

import "github.com/google/uuid"

type PublicKeysDto struct {
	PublicKeys []PublicKeyDto `json:"publicKeys"`
}

type PublicKeyDto struct {
	PolicyId  uuid.UUID `json:"policyId,omitempty"`
	PublicKey string    `json:"publicKey"`
}
