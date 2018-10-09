package trustprovider

import (
	"net/http"
	"github.com/gorilla/mux"
	"github.com/satori/go.uuid"
	"github.com/pkg/errors"
	"log"
	"github.com/Vivvo/go-sdk/utils"
	"fmt"
	"encoding/json"
	"github.com/gorilla/handlers"
	"os"
	"path/filepath"
	"io/ioutil"
)

type Onboarding struct {
	Parameters     []Parameter
	OnboardingFunc func(s map[string]string, n map[string]float64, b map[string]bool) (interface{}, error)
}

type ParameterType int

const (
	ParameterTypeBool    ParameterType = iota
	ParameterTypeFloat64
	ParameterTypeString
)

type Parameter struct {
	Name     string
	Type     ParameterType
	Required bool
}

type Rule struct {
	Name       string
	Parameters []Parameter
	RuleFunc   func(s map[string]string, n map[string]float64, b map[string]bool, acct interface{}) (bool, error)
}

type trustProviderResponse struct {
	Status             bool   `json:"value"`
	Message            string `json:"message,omitempty"`
	OnBoardingRequired bool   `json:"onBoardingRequired"`
	Token              string `json:"token,omitempty"`
	VerifiableClaim    string `json:"verifiableClaim,omitempty"`
}

type devDBRecord struct {
	Account interface{} `json:"account"`
	Token   uuid.UUID   `json:"token"`
}

const dbFilePath = "./db.json"

// Account interface should be implemented and passed in when creating a TrustProvider.
type Account interface {
	// Update an account in the source system to save the token that was generated as part of
	// successfully onboarding.
	Update(account interface{}, token uuid.UUID) error
	// Find an account in the source system by the token that was generated as part of successfully
	// onboarding.
	Read(token uuid.UUID) (interface{}, error)
}

// The TrustProvider will handle basic parameter validation (required, type), call out to your business logic
// functions (e.g.: Onboarding.OnboardingFunc, Rule.RuleFunc) and handle all the response bodies and status
// codes based on what your business logic functions return. This is the quickest and easiest way to implement
// the consistent API that the Citizen One platform expects to integrate with when talking to a Trust Provider.
//
// The port that the http server runs on can be configured by setting an environment variable: TRUST_PROVIDER_PORT.
// If this variable is not set, we will default to port 3000.
//
// The onboarding endpoint will be:
//     /api/register
//
// The rules endpoints will follow this pattern:
//     /api/{Rule.Name}/{token}
type TrustProvider struct {
	onboarding Onboarding
	rules      []Rule
	router     *mux.Router
	account    Account
	port       string
}

func parseParameters(params []Parameter, r *http.Request) (map[string]string, map[string]float64, map[string]bool, error) {
	var body interface{}
	err := utils.ReadBody(&body, r)
	if err != nil {
		return nil, nil, nil, err
	}

	var ve []string

	strs := make(map[string]string, 0)
	nums := make(map[string]float64, 0)
	bools := make(map[string]bool, 0)

	for _, p := range params {
		if p.Required {
			if params, ok := body.(map[string]interface{}); (ok && params[p.Name] == nil) || !ok {
				ve = append(ve, fmt.Sprintf("Parameter %s is Required.", p.Name))
			}
		}

		if params, ok := body.(map[string]interface{}); ok && params[p.Name] != nil {
			switch p.Type {
			case ParameterTypeString:
				if s, ok := params[p.Name].(string); ok {
					strs[p.Name] = s
				} else {
					ve = append(ve, fmt.Sprintf("Parameter %s must be a string.", p.Name))
				}
			case ParameterTypeFloat64:
				if f, ok := params[p.Name].(float64); ok {
					nums[p.Name] = f
				} else {
					ve = append(ve, fmt.Sprintf("Parameter %s must be a number.", p.Name))
				}
			case ParameterTypeBool:
				if b, ok := params[p.Name].(bool); ok {
					bools[p.Name] = b
				} else {
					ve = append(ve, fmt.Sprintf("Parameter %s must be a boolean.", p.Name))
				}
			}
		}
	}

	if len(ve) > 0 {
		e, err := json.Marshal(ve)
		if err == nil {
			err = errors.New(string(e))
		}
		return nil, nil, nil, err
	}

	return strs, nums, bools, nil
}

func (t *TrustProvider) register(w http.ResponseWriter, r *http.Request) {

	s, n, b, err := parseParameters(t.onboarding.Parameters, r)
	if err != nil {
		log.Println(err.Error())
		utils.SetErrorStatus(err, http.StatusBadRequest, w)
		return
	}

	if t.onboarding.OnboardingFunc == nil {
		err := errors.New("TrustProvider.onboarding.OnboardingFunc not implemented!")
		log.Println(err.Error())
		utils.SetErrorStatus(err, http.StatusInternalServerError, w)
		return
	}
	account, err := t.onboarding.OnboardingFunc(s, n, b)
	if err == nil {
		token := uuid.Must(uuid.NewV4())

		err = t.account.Update(account, token)

		if err != nil {
			res := trustProviderResponse{Status: false, OnBoardingRequired: true}
			utils.WriteJSON(res, http.StatusInternalServerError, w)
		} else {
			res := trustProviderResponse{Status: true, OnBoardingRequired: false, Token: token.String()}
			utils.WriteJSON(res, http.StatusCreated, w)
		}
	} else {
		res := trustProviderResponse{Status: false, OnBoardingRequired: true, Message: err.Error()}
		utils.WriteJSON(res, http.StatusOK, w)
	}

}

func (t *TrustProvider) handleRule(rule Rule) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		s, n, b, err := parseParameters(rule.Parameters, r)
		if err != nil {
			log.Println(err.Error())
			utils.SetErrorStatus(err, http.StatusBadRequest, w)
			return
		}

		vars := mux.Vars(r)
		v := vars["token"]
		token, err := uuid.FromString(v)
		if err != nil {
			log.Println(err.Error())
			utils.SetErrorStatus(err, http.StatusBadRequest, w)
			return
		}

		acct, err := t.account.Read(token)
		if err != nil {
			log.Println(err.Error())
			utils.SetErrorStatus(err, http.StatusBadRequest, w)
			return
		}

		status, err := rule.RuleFunc(s, n, b, acct)
		if err != nil {
			log.Println(err.Error())
			utils.SetErrorStatus(err, http.StatusServiceUnavailable, w)
			return
		}

		utils.WriteJSON(trustProviderResponse{Status: status}, http.StatusOK, w)
	})
}

// Create a new TrustProvider. Based on the onboarding, rules and account objects you pass in
// this will bootstrap an http server with onboarding and rules endpoints exposed.
func New(onboarding Onboarding, rules []Rule, account ...Account) TrustProvider {

	var acct Account
	if len(account) == 1 {
		acct = account[0]
	} else {
		acct = &DefaultAccount{}
	}

	t := TrustProvider{onboarding: onboarding, rules: rules, account: acct, router: mux.NewRouter()}

	t.router.HandleFunc("/api/register", t.register).Methods("POST")

	for _, rule := range rules {
		t.router.HandleFunc(fmt.Sprintf("/api/%s/{token}", rule.Name), t.handleRule(rule)).Methods("POST")
	}

	http.Handle("/", handlers.LoggingHandler(os.Stdout, t.router))

	const TrustProviderPortKey = "TRUST_PROVIDER_PORT"
	t.port = os.Getenv(TrustProviderPortKey)
	if t.port == "" {
		t.port = "3000"
	}
	return t
}

func (t *TrustProvider) ListenAndServe() error {
	return http.ListenAndServe(":"+t.port, nil)
}

// DefaultAccount is the default implementation of the Account interface that the TrustProvider will
// use to save tokens associated with accounts and retrieve accounts by those tokens. This implementation
// is NOT suitable for production use.
type DefaultAccount struct{}

// Update implementation stores accounts and tokens in a CSV file.
func (d *DefaultAccount) Update(account interface{}, token uuid.UUID) error {

	err := createDevDB()
	if err != nil {
		log.Printf("Error creating file: %s", err)
		return err
	}

	path, err := filepath.Abs(dbFilePath)
	file, err := os.OpenFile(path, os.O_RDWR|os.O_APPEND, 0644)
	if err != nil {
		log.Printf("Error opening file: %s", err)
		return err
	}

	defer file.Close()

	var records []devDBRecord

	if account == nil {
		return errors.New("you must provide an account object")
	}

	if token.String() == "" {
		return errors.New("you must provide a token")
	}

	fileContents, _ := ioutil.ReadAll(file)
	// empty file before we write the whole array again
	file.Truncate(0)

	json.Unmarshal(fileContents, &records)

	record := devDBRecord{
		Account: account,
		Token:   token,
	}

	records = append(records, record)
	r, err := json.Marshal(records)
	_, err = file.Write(r)
	if err != nil {
		log.Fatalf("Error writing to file: %s", err)
	}

	log.Println("WARNING: Note you are using the default internal database.  This is for debugging only, please don't use this in production.")

	return err
}

// Read implementation reads an account by the given token from a CSV file. The account object will be retrieved
// as a map[string]interface{} since we know the type of the struct you've stored here. You can convert it back
// to the appropriate struct using something like http://github.com/mitchellh/mapstructure
// (examples: https://godoc.org/github.com/mitchellh/mapstructure#Decode)
func (d *DefaultAccount) Read(token uuid.UUID) (interface{}, error) {

	path, err := filepath.Abs(dbFilePath)
	file, err := os.OpenFile(path, os.O_RDWR|os.O_APPEND, 0644)
	if err != nil {
		return nil, errors.New("error opening file")
	}

	defer file.Close()

	fileContents, _ := ioutil.ReadAll(file)

	var records []devDBRecord

	json.Unmarshal(fileContents, &records)

	for _, record := range records {
		if record.Token == token {
			return record, nil
		}
	}

	return nil, err
}

func createDevDB() error {

	_, err := os.Stat(dbFilePath)

	if os.IsNotExist(err) {
		var file, err = os.Create(dbFilePath)
		if err != nil {
			return err
		}
		defer file.Close()
	}

	return nil
}
