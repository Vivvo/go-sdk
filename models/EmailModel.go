package models

type Email struct {
	IdentityId   string `json:"identityId"`
	EmailAddress string `json:"emailAddress"`
	IsPrimary    bool   `json:"isPrimary"`
}
