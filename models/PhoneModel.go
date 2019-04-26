package models

type Phone struct {
	IdentityId       string `json:"identityId"`
	PhoneType        string `json:"phoneType"`
	CountryCallCode  string `json:"countryCallCode"`
	CountryCode      string `json:"countryCode"`
	PhoneNumber      string `json:"phoneNumber"`
	Extension        string `json:"extension"`
	VerificationCode string `json:"verificationCode"`
	IsPrimary        bool   `json:"isPrimary"`
}
