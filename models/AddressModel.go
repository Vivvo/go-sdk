package models

type Address struct {
	IdentityId		 string  	`json:"identityId"`
	AddressType 	 string		`json:"addressType"`
	AddressLine1 	 string 	`json:"addressLine1"`
	AddressLine2 	 string 	`json:"addressLine2"`
	City 			 string		`json:"city"`
	ProvinceCode 	 string 	`json:"provinceCode`
	PostalCode		 string 	`json:"postalCode"`
	CountryCode  	 string 	`json:"countryCode"`
	IsPrimary 		 bool		`json:"isPrimary"`
}