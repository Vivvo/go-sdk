package models

type PublishWrapperDto struct {
	EventType      string `json:"eventType"`
	Data           string `json:"data"`
	EncryptedNonce string `json:"encryptedNonce,omitempty"`
	EncryptedKey   string `json:"encryptedKey,omitempty"`
}
