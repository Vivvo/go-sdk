package models

import "time"

type IdentityDto struct {
	IdentityId string       `json:"identityId,omitempty"`
	Did        string       `json:"did,omitempty"`
	DeviceId   string       `json:"deviceId,omitempty"`
	Username   string       `json:"username,omitempty"`
	Salutation string       `json:"salutation"`
	FirstName  string       `json:"firstName,omitempty"`
	MiddleName string       `json:"middleName,omitempty"`
	LastName   string       `json:"lastName,omitempty"`
	Birthdate  time.Time    `json:"birthdate,omitempty"`
	Emails     []EmailDto   `json:"emails,omitempty"`
	Phones     []PhoneDto   `json:"phones,omitempty"`
	Addresses  []AddressDto `json:"addresses,omitempty"`
}

type PhoneDto struct {
	IdentityId      string `json:"identityId,omitempty"`
	PhoneType       string `json:"phoneType,omitempty"`
	CountryCallCode string `json:"countryCallCode,omitempty"`
	CountryCode     string `json:"countryCode,omitempty"`
	PhoneNumber     string `json:"phoneNumber,omitempty"`
	Extension       string `json:"extension,omitempty"`
	IsPrimary       bool   `json:"isPrimary,omitempty"`
	IsMfa           bool   `json:"isMfa,omitempty"`
	Verified        bool   `json:"verified,omitempty"`
}

type EmailDto struct {
	EmailId      int    `json:"emailId,omitempty"`
	EmailAddress string `json:"emailAddress"`
	IsPrimary    bool   `json:"isPrimary,omitempty"`
	IsVerified   bool   `json:"isVerified,omitempty"`
	IdentityId   string `json:"identityId,omitempty"`
}

type AddressDto struct {
	IdentityId   string `json:"identityId,omitempty"`
	AddressType  string `json:"addressType,omitempty"`
	AddressLine1 string `json:"addressLine1,omitempty"`
	AddressLine2 string `json:"addressLine2,omitempty"`
	City         string `json:"city,omitempty"`
	PostalCode   string `json:"postalCode,omitempty"`
	ProvinceCode string `json:"provinceCode,omitempty"`
	CountryCode  string `json:"countryCode,omitempty"`
	IsPrimary    bool   `json:"isPrimary,omitempty"`
}
