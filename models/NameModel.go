package models

type Name struct {
	FirstName		string		`json:"firstName"`
	MiddleName		string 		`json:"middleName"`
	LastName		string		`json:"lastName"`
	SupportCode		string		`json:"supportCode"`
}