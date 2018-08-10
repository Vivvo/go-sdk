package main

import (
	"github.com/Vivvo/go-sdk/trust-provider"
	"log"
	"github.com/satori/go.uuid"
	"encoding/csv"
	"os"
	"strings"
	"github.com/pkg/errors"
	"time"
)

type DMVAccount struct {
	CustomerNumber   string `json:"customerNumber"`
	ValidationNumber string `json:"validationNumber"`
	FirstName        string `json:"firstName"`
	LastName         string `json:"lastName"`
	BirthDate        string `json:"birthDate"`
	Token            string `json:"token"`
}

type DMVAccountManager struct{}

func (d *DMVAccountManager) Update(account interface{}, token uuid.UUID) error {
	reader, _ := os.Open("./drones.csv")
	r := csv.NewReader(reader)
	records, _ := r.ReadAll()
	reader.Close()

	if a, ok := account.(DMVAccount); ok {
		for _, r := range records[1:] {
			if strings.Compare(r[0], a.MemberNumber) == 0 {
				r[4] = token.String()
			}
		}

		file, _ := os.OpenFile("./drones.csv", os.O_RDWR, 0777)
		writer := csv.NewWriter(file)
		writer.WriteAll(records)
		defer file.Close()
		return nil
	} else {
		return errors.New("invalid account object")
	}
}

func (d *DMVAccountManager) Read(token uuid.UUID) (interface{}, error) {
	reader, _ := os.Open("./drones.csv")
	defer reader.Close()
	r := csv.NewReader(reader)
	records, _ := r.ReadAll()

	for _, r := range records[1:] {
		if strings.Compare(r[4], token.String()) == 0 {
			return DMVAccount{MemberNumber: r[0], Status: r[1], FirstName: r[2], LastName: r[3], Token: r[4]}, nil
		}
	}
	return nil, errors.New("not match found")
}

func onboarding(s map[string]string, n map[string]float64, b map[string]bool) (interface{}, error) {
	reader, _ := os.Open("./drones.csv")
	defer reader.Close()
	r := csv.NewReader(reader)
	records, _ := r.ReadAll()

	for _, r := range records[1:] {
		if strings.Compare(r[0], s["memberNumber"]) == 0 && strings.Compare(r[2], s["firstName"]) == 0 && strings.Compare(r[3], s["lastName"]) == 0 {
			return DMVAccount{MemberNumber: r[0], Status: r[1], FirstName: r[2], LastName: r[3], Token: r[4]}, nil
		}
	}
	return nil, errors.New("no match found")
}

func is19YearsOld(s map[string]string, n map[string]float64, b map[string]bool, acct interface{}) (bool, error) {
	if a, ok := acct.(DMVAccount); ok {
		birthDate, err := time.Parse("2006-01-20", a.BirthDate)
		if err != nil {
			return false, errors.New("unable to parse birth date")
		}
		turns19Date := birthDate.AddDate(19, 0, 0)
		return turns19Date.Before(time.Now()) || turns19Date.Equal(time.Now()), nil
	} else {
		return false, errors.New("not a valid account object")
	}
}

func main() {
	onboarding := trustprovider.Onboarding{
		Parameters: []trustprovider.Parameter{
			{Name: "memberNumber", Required: true, Type: trustprovider.ParameterTypeString},
			{Name: "firstName", Required: true, Type: trustprovider.ParameterTypeString},
			{Name: "lastName", Required: true, Type: trustprovider.ParameterTypeString},
		},
		OnboardingFunc: onboarding,
	}

	rules := []trustprovider.Rule{
		{Name: "is19yearsold", Parameters: []trustprovider.Parameter{}, RuleFunc: is19YearsOld},
	}

	tp := trustprovider.New(onboarding, rules, &DMVAccountManager{})
	log.Fatal(tp.ListenAndServe())
}
