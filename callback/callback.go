package callback

import "github.com/satori/go.uuid"

type PublishEventType string

const (
	PublishEventTypeCreate PublishEventType = "CREATE"
	PublishEventTypeUpdate PublishEventType = "UPDATE"
	PublishEventTypeDelete PublishEventType = "DELETE"
)

type IdentityPublishDto struct {
	IdentityId uuid.UUID `json:"identityId"`
	FirstName  string    `json:"firstName"`
	MiddleName string    `json:"middleName"`
	LastName   string    `json:"lastName"`
}

type IdentityUpdateDto struct {
	EventType PublishEventType   `json:"eventType"`
	Identity  IdentityPublishDto `json:"data"`
}

type AddressType string

const (
	AddressTypeHome     AddressType = "HOME"
	AddressTypeBilling  AddressType = "BILLING"
	AddressTypeBusiness AddressType = "BUSINESS"
	AddressTypeMailing  AddressType = "MAILING"
	AddressTypeOther    AddressType = "OTHER"
)

type AddressPublishDto struct {
	AddressId    int         `json:"addressId"`
	IdentityId   uuid.UUID   `json:"identityId"`
	AddressType  AddressType `json:"addressType"`
	AddressLine1 string      `json:"addressLine1"`
	AddressLine2 string      `json:"addressLine2"`
	City         string      `json:"city"`
	ProvinceCode string      `json:"provinceCode"`
	PostalCode   string      `json:"postalCode"`
	CountryCode  string      `json:"countryCode"`
	IsPrimary    bool        `json:"isPrimary"`
}

type AddressUpdateDto struct {
	EventType PublishEventType  `json:"eventType"`
	Address   AddressPublishDto `json:"data"`
}

type EmailPublishDto struct {
	EmailId      int       `json:"emailId"`
	IdentityId   uuid.UUID `json:"identityId"`
	EmailAddress string    `json:"emailAddress"`
	IsPrimary    bool      `json:"isPrimary"`
	IsVerified   bool      `json:"isVerified"`
}

type EmailUpdateDto struct {
	EventType PublishEventType `json:"eventType"`
	Email     EmailPublishDto  `json:"data"`
}

type PhoneType string

const (
	PhoneTypeHome     PhoneType = "HOME"
	PhoneTypeOther    PhoneType = "OTHER"
	PhoneTypeMobile   PhoneType = "MOBILE"
	PhoneTypeBusiness PhoneType = "BUSINESS"
	PhoneTypeFax      PhoneType = "FAX"
)

type PhonePublishDto struct {
	PhoneId         int       `json:"phoneId"`
	IdentityId      uuid.UUID `json:"identityId"`
	PhoneType       PhoneType `json:"phoneType"`
	CountryCallCode string    `json:"countryCallCode"`
	CountryCode     string    `json:"countryCode"`
	PhoneNumber     string    `json:"phoneNumber"`
	Extension       string    `json:"extension"`
	IsPrimary       bool      `json:"isPrimary"`
	Verified        bool      `json:"verified"`
}

type PhoneUpdateDto struct {
	EventType PublishEventType `json:"eventType"`
	Phone     PhonePublishDto  `json:"data"`
}
