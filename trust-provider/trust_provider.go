package trustprovider

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"github.com/Vivvo/go-sdk/did"
	"github.com/Vivvo/go-sdk/utils"
	"github.com/Vivvo/go-wallet"
	"github.com/google/uuid"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/newrelic/go-agent"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

type Onboarding struct {
	Parameters     []Parameter
	OnboardingFunc func(s map[string]string, n map[string]float64, b map[string]bool) (interface{}, error, string)
}

type ParameterType int

const (
	ParameterTypeBool ParameterType = iota
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
	Claims     []string
}

type trustProviderResponse struct {
	Status             bool                 `json:"value"`
	Message            string               `json:"message,omitempty"`
	OnBoardingRequired bool                 `json:"onBoardingRequired"`
	Token              string               `json:"token,omitempty"`
	VerifiableClaim    *did.VerifiableClaim `json:"verifiableClaim,omitempty"`
}

type DidDocResponse struct {
	DidDocument did.Document `json:"didDocument"`
}

type DefaultDBRecord struct {
	Account interface{} `json:"account"`
	Token   string      `json:"token"`
}

const DefaultCsvFilePath = "./db.json"
const DefaultWalletId = "wallet.db"

// Account interface should be implemented and passed in when creating a TrustProvider.
type Account interface {
	// Update an account in the source system to save the token that was generated as part of
	// successfully onboarding.
	Update(account interface{}, token string) error
	// Find an account in the source system by the token that was generated as part of successfully
	// onboarding.
	Read(token string) (interface{}, error)
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
	did        string
	privateKey *rsa.PrivateKey
	resolver   did.ResolverInterface
}

func (t *TrustProvider) parseParameters(body interface{}, params []Parameter, r *http.Request) (map[string]string, map[string]float64, map[string]bool, error) {
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

func (t *TrustProvider) registerWithDid(w http.ResponseWriter, r *http.Request) {
	logger := utils.Logger(r.Context())

	var body interface{}
	err := utils.ReadBody(&body, r)
	if err != nil {
		logger.Errorf("Problem unmarshalling onboarding request body", "error", err.Error())
		utils.SetErrorStatus(err, http.StatusBadRequest, w)
		return
	}
	fmt.Print(body)

	// Decrpyt the body -> double ratchet...
	// parse out the parameters
	// update account
	// verify the claim
	// send the token back to id1
	// send a push notificaiton back to the phone with encrypted message
}

func (t *TrustProvider) getDidDoc(w http.ResponseWriter, r *http.Request) {
	logger := utils.Logger(r.Context())
	vars := mux.Vars(r)
	id := vars["id"]

	wallet, err := wallet.Open([]byte(os.Getenv("MASTER_KEY")), DefaultWalletId)
	if err != nil {
		logger.Errorf("error opening the wallet:", err.Error())
		utils.WriteJSON(err, http.StatusInternalServerError, w)
	}

	ddoc, err := wallet.SGIDidDoc().Read(id)
	if err != nil {
		logger.Errorf("error retrieving the did document:", err.Error())
	}

	var d did.Document
	json.Unmarshal([]byte(ddoc), &d)
	utils.WriteJSON(d, http.StatusCreated, w)

}

func (t *TrustProvider) register(w http.ResponseWriter, r *http.Request) {

	logger := utils.Logger(r.Context())

	var body interface{}
	err := utils.ReadBody(&body, r)
	if err != nil {
		logger.Errorf("Problem unmarshalling onboarding request body", "error", err.Error())
		utils.SetErrorStatus(err, http.StatusBadRequest, w)
		return
	}

	s, n, b, err := t.parseParameters(body, t.onboarding.Parameters, r)
	if err != nil {
		logger.Errorf("Problem parsing onboarding request parameters", "error", err.Error())
		utils.SetErrorStatus(err, http.StatusBadRequest, w)
		return
	}

	if t.onboarding.OnboardingFunc == nil {
		err := errors.New("TrustProvider.onboarding.OnboardingFunc not implemented!")
		logger.Errorf("TrustProvider.onboarding.OnboardingFunc not implemented!")
		utils.SetErrorStatus(err, http.StatusInternalServerError, w)
		return
	}
	account, err, token := t.onboarding.OnboardingFunc(s, n, b)
	if err == nil {
		if token == "" {
			token = uuid.New().String()
		}

		err = t.account.Update(account, token)

		if err != nil {
			res := trustProviderResponse{Status: false, OnBoardingRequired: true}
			utils.WriteJSON(res, http.StatusInternalServerError, w)
		} else {
			var vc *did.VerifiableClaim
			if t.didIsConfigured() {

				iAmMeCredential, ve := t.parseVerifiableCredential(body, "iAmMeCredential", []string{did.VerifiableCredential, did.IAmMeCredential}, logger)
				if len(ve) > 0 {
					e, err := json.Marshal(ve)
					if err == nil {
						err = errors.New(string(e))
					}
					logger.Errorf("Problem verifying the Verifiable Credential", "error", ve)
					utils.SetErrorStatus(err, http.StatusBadRequest, w)
					return
				}

				if iAmMeCredential != nil {
					subject := iAmMeCredential.Claim[did.SubjectClaim].(string)

					ac := make(map[string]interface{})
					ac[did.TokenClaim] = token

					claim, _ := t.generateVerifiableClaim(ac, subject, token, []string{did.VerifiableCredential, did.TokenizedConnectionCredential})
					if err != nil {
						logger.Errorf("Problem generating a verifiable credential response", "error", err.Error())
						utils.SetErrorStatus(err, http.StatusInternalServerError, w)
						return
					}
					vc = &claim
				}
			}

			res := trustProviderResponse{Status: true, OnBoardingRequired: false, Token: token, VerifiableClaim: vc}
			utils.WriteJSON(res, http.StatusCreated, w)
		}
	} else {
		res := trustProviderResponse{Status: false, OnBoardingRequired: true, Message: err.Error()}
		utils.WriteJSON(res, http.StatusOK, w)
	}

}

func (t *TrustProvider) parseVerifiableCredential(body interface{}, attributeName string, types []string, logger *zap.SugaredLogger) (*did.VerifiableClaim, []string) {
	var iAmMeCredential *did.VerifiableClaim
	var ve []string
	logger.Infow("Checking for Verifiable Credential...")
	if b, ok := body.(map[string]interface{}); ok && b[attributeName] != nil {
		vc, err := json.Marshal(b[attributeName])
		if err != nil {
			ve = append(ve, fmt.Sprintf("Unable to unmarshal Verifiable Credential."))
		} else {
			var cred did.VerifiableClaim
			err = json.Unmarshal(vc, &cred)
			if err != nil {
				ve = append(ve, fmt.Sprintf("Unable to unmarshal Verifiable Credential."))
			} else {
				iAmMeCredential = &cred

				err = cred.Verify(types, cred.Proof.Nonce, t.resolver)
				if err != nil {
					log.Println(err.Error())
					ve = append(ve, fmt.Sprintf("Unable to verify Verifiable Credential."))
				}
			}
		}
	} else {
		logger.Infow("Verifiable Credential not found.")
	}
	return iAmMeCredential, ve
}

func (t *TrustProvider) didIsConfigured() bool {
	return t.did != ""
}

func (t *TrustProvider) generateVerifiableClaim(ac map[string]interface{}, subject string, id string, types []string) (did.VerifiableClaim, error) {

	ac[did.SubjectClaim] = subject
	ac[did.PublicKeyClaim] = fmt.Sprintf("%s#keys-1", t.did)

	var claim = did.Claim{
		id,
		types,
		t.did,
		time.Now().Format("2006-01-02"),
		ac,
	}

	return claim.Sign(t.privateKey, uuid.New().String())
}

func (t *TrustProvider) handleRule(rule Rule) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		logger := utils.Logger(r.Context())

		var body interface{}
		err := utils.ReadBody(&body, r)
		if err != nil {
			logger.Error("error", err.Error())
			utils.SetErrorStatus(err, http.StatusBadRequest, w)
			return
		}

		s, n, b, err := t.parseParameters(body, rule.Parameters, r)
		if err != nil {
			logger.Error("error", err.Error())
			utils.SetErrorStatus(err, http.StatusBadRequest, w)
			return
		}

		vars := mux.Vars(r)
		token := vars["token"]

		acct, err := t.account.Read(token)
		if err != nil {
			logger.Error("error", err.Error())
			utils.SetErrorStatus(err, http.StatusBadRequest, w)
			return
		}

		status, err := rule.RuleFunc(s, n, b, acct)
		if err != nil {
			logger.Error("error", err.Error())
			utils.SetErrorStatus(err, http.StatusServiceUnavailable, w)
			return
		}

		if status {
			var vc *did.VerifiableClaim
			if t.didIsConfigured() {
				connectionClaim, ve := t.parseVerifiableCredential(body, "verifiableClaim", []string{did.VerifiableCredential, did.TokenizedConnectionCredential}, logger)
				if len(ve) > 0 {
					e, err := json.Marshal(ve)
					if err == nil {
						err = errors.New(string(e))
					}

					logger.Errorf("Problem verifying Verifiable Credential", "error", err.Error())

					utils.SetErrorStatus(err, http.StatusBadRequest, w)
					return
				}

				if connectionClaim != nil {
					ac := make(map[string]interface{})
					for k, v := range s {
						ac[k] = v
					}
					for k, v := range n {
						ac[k] = v
					}
					for k, v := range b {
						ac[k] = v
					}

					claim, err := t.generateVerifiableClaim(ac, connectionClaim.Claim[did.SubjectClaim].(string), uuid.New().String(), rule.Claims)
					if err != nil {
						logger.Error("error", err.Error())
						utils.SetErrorStatus(err, http.StatusInternalServerError, w)
						return
					}
					vc = &claim
				}
			}
			utils.WriteJSON(trustProviderResponse{Status: status, VerifiableClaim: vc}, http.StatusOK, w)
		} else {
			utils.WriteJSON(trustProviderResponse{Status: status}, http.StatusOK, w)
		}
	})
}

func applyNewRelic(pattern string, handler http.Handler) (string, http.Handler) {
	newRelicConfig := newrelic.NewConfig(os.Getenv("NEW_RELIC_APP_NAME"), os.Getenv("NEW_RELIC_LICENSE_KEY"))
	app, err := newrelic.NewApplication(newRelicConfig)
	if err != nil {
		log.Println("Unable to create New Relic application:", err.Error())
	}

	if app != nil {
		return newrelic.WrapHandle(app, pattern, handler)
	}
	return pattern, handler
}

// Create a new TrustProvider. Based on the onboarding, rules and account objects you pass in
// this will bootstrap an http server with onboarding and rules endpoints exposed.
func New(onboarding Onboarding, rules []Rule, account Account, resolver did.ResolverInterface) TrustProvider {
	t := TrustProvider{onboarding: onboarding, rules: rules, account: account, router: mux.NewRouter(), resolver: resolver}

	t.did = os.Getenv("DID")
	if t.did != "" {
		privateKeyPem := os.Getenv("PRIVATE_KEY_PEM")
		privateKey, err := ssh.ParseRawPrivateKey([]byte(privateKeyPem))
		if err != nil {
			panic(err.Error())
		}
		if pk, ok := privateKey.(*rsa.PrivateKey); ok {
			t.privateKey = pk
		} else {
			panic("expected RSA private key")
		}
	}

	t.router.HandleFunc("/api/register", t.register).Methods("POST")
	t.router.HandleFunc("/api/did/{id}", t.getDidDoc).Methods("GET")
	t.router.HandleFunc("/api/did/register", t.registerWithDid).Methods("POST")

	for _, rule := range rules {
		t.router.HandleFunc(fmt.Sprintf("/api/%s/{token}", rule.Name), t.handleRule(rule)).Methods("POST")
	}

	http.Handle(applyNewRelic("/", handlers.LoggingHandler(os.Stdout, utils.CorrelationIdMiddleware(t.router))))

	const TrustProviderPortKey = "TRUST_PROVIDER_PORT"
	t.port = os.Getenv(TrustProviderPortKey)
	if t.port == "" {
		t.port = "3000"
	}
	return t
}

func (t *TrustProvider) ListenAndServe() error {
	log.Printf("Listening on port: %s", t.port)
	return http.ListenAndServe(":"+t.port, nil)
}

// DefaultAccount is the default implementation of the Account interface that the TrustProvider will
// use to save tokens associated with accounts and retrieve accounts by those tokens. This implementation
// is NOT suitable for production use.
type DefaultAccount struct{}

// Update implementation stores accounts and tokens in a CSV file.
func (d *DefaultAccount) Update(account interface{}, token string) error {

	err := createDevDB()
	if err != nil {
		log.Printf("Error creating file: %s", err)
		return err
	}

	path, err := filepath.Abs(DefaultCsvFilePath)
	file, err := os.OpenFile(path, os.O_RDWR|os.O_APPEND, 0644)
	if err != nil {
		log.Printf("Error opening file: %s", err)
		return err
	}

	defer file.Close()

	var records []DefaultDBRecord

	if account == nil {
		return errors.New("you must provide an account object")
	}

	if token == "" {
		return errors.New("you must provide a token")
	}

	fileContents, _ := ioutil.ReadAll(file)
	// empty file before we write the whole array again
	file.Truncate(0)

	json.Unmarshal(fileContents, &records)

	record := DefaultDBRecord{
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
func (d *DefaultAccount) Read(token string) (interface{}, error) {

	path, err := filepath.Abs(DefaultCsvFilePath)
	file, err := os.OpenFile(path, os.O_RDWR|os.O_APPEND, 0644)
	if err != nil {
		return nil, errors.New("error opening file")
	}

	defer file.Close()

	fileContents, _ := ioutil.ReadAll(file)

	var records []DefaultDBRecord

	json.Unmarshal(fileContents, &records)

	for _, record := range records {
		if record.Token == token {
			return record, nil
		}
	}

	return nil, err
}

func createDevDB() error {

	_, err := os.Stat(DefaultCsvFilePath)

	if os.IsNotExist(err) {
		var file, err = os.Create(DefaultCsvFilePath)
		if err != nil {
			return err
		}
		defer file.Close()
	}

	return nil
}
