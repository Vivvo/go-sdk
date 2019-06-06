package trustprovider

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Vivvo/go-sdk/did"
	"github.com/Vivvo/go-sdk/utils"
	"github.com/Vivvo/go-wallet"
	"github.com/Vivvo/go-wallet/storage/mariadb"
	"github.com/btcsuite/btcutil/base58"
	"github.com/go-resty/resty"
	"github.com/google/uuid"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/newrelic/go-agent"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

const ErrorOnboardingRequired = "onboarding required"
const ErrorCredentialAlreadySent = "credential already sent"

const ConfigTrustProviderPort = "TRUST_PROVIDER_PORT"
const WalletConfigDID = "DID"
const WalletConfigMasterKey = "MASTER_KEY"
const WalletConfigMariadbDSN = "MARIADB_DSN"

type OnboardingFunc func(s map[string]string, n map[string]float64, b map[string]bool, i map[string]interface{}) (account interface{}, err error, token string)

// Parameters:
//     An array of required/optional parameters that the onboarding function will have access to. Validation will automatically
//     be applied based on how the parameters are configured.
// Claims:
//    The types of the verifiable credential that will be issued when onboarding succeeds.
// OnboardingFunc:
//    This function should execute the required business logic to ensure that the person onboarding is tied to
//    and account in your system. The interface{} that is returned from here should be your implementation of an account.
type Onboarding struct {
	Parameters           []Parameter
	Claims               []string
	OnboardingFunc       OnboardingFunc
	VerifiableCredential bool
}

type ParameterType int

const (
	ParameterTypeBool ParameterType = iota
	ParameterTypeFloat64
	ParameterTypeString
	ParameterTypeInterface
)

type Parameter struct {
	Name     string
	Type     ParameterType
	Required bool
}

type Rule struct {
	Name                 string
	Parameters           []Parameter
	RuleFunc             func(s map[string]string, n map[string]float64, b map[string]bool, i map[string]interface{}, acct interface{}) (bool, error)
	Claims               []string
	VerifiableCredential bool
}

type Data struct {
	Name     string
	DataFunc func(acct interface{}) (interface{}, error)
}

type GetStatus struct {
	GetStatusFunc	func(acct interface{}) (StatusResponse, error)
}

type StatusResponse struct {
	StatusAction 	[]StatusAction
	StatusLabel		[]StatusLabel
	StatusFile		[]StatusFile
}

type StatusAction struct {
	Label 		string	`json:"label"`
	Action 		string 	`json:"action"`
	Description	string	`json:"description"`
}

type StatusLabel struct {
	Label 		string 	`json:"label"`
	Value 		string 	`json:"value"`
}

type StatusFile struct {
	Title 		string 	`json:"title"`
	Action 		string 	`json:"action"`
	Description	string 	`json:"description"`
	FileType	string	`json:"fileType"`
	FileSize 	string	`json:"fileSize"`
	Date 		string 	`json:"date"`
}
type SubscribedObject struct {
	Name                 string
	Parameters           []Parameter
	SubscribedObjectFunc func(s map[string]string, n map[string]float64, b map[string]bool, i map[string]interface{}) (bool, error)
}

type trustProviderResponse struct {
	Status             bool                   `json:"value"`
	Message            string                 `json:"message,omitempty"`
	OnBoardingRequired bool                   `json:"onBoardingRequired"`
	IgnoreAttempt      bool                   `json:"ignoreAttempt"`
	Token              string                 `json:"token,omitempty"`
	VerifiableClaim    *wallet.RatchetPayload `json:"verifiableClaim,omitempty"`
}

type TrustProviderErrorResponse struct {
	OnboardingStatus   bool
	OnboardingRequired bool
	Message            string
	HttpStatus         int
}

func (t TrustProviderErrorResponse) Error() string {
	return t.Message
}

type ConnectionResponse struct {
	VerifiableClaim did.VerifiableClaim `json:"verifiableClaim"`
}

type DefaultDBRecord struct {
	Account interface{} `json:"account"`
	Token   string      `json:"token"`
}

type MessageDto struct {
	Type    string `json:"type"`
	Payload string `json:"payload"`
}

type Subscriber struct {
	EventType string      `json:"eventType"`
	Data      interface{} `json:"data"`
}

const DefaultCsvFilePath = "./db.json"
const DefaultWalletId = "Wallet.db"

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
	onboarding       Onboarding
	rules            []Rule
	subscribedObject []SubscribedObject
	data 			 []Data
	getStatus		 GetStatus
	Router           *mux.Router
	account          Account
	port             string
	resolver         did.ResolverInterface
	Wallet           *wallet.Wallet
}

// New will create a new TrustProvider. Based on the onboarding, rules and account objects you pass in
// this will bootstrap an http server with onboarding and rules endpoints exposed.
func New(onboarding Onboarding, rules []Rule, subscribedObjects []SubscribedObject, data []Data, getStatus GetStatus, account Account, resolver did.ResolverInterface) TrustProvider {
	os.Setenv("STARTED_ON", time.Now().Format(time.RFC3339))
	t := TrustProvider{onboarding: onboarding, rules: rules, subscribedObject: subscribedObjects, getStatus: getStatus, account: account, Router: mux.NewRouter(), resolver: resolver}

	if getWalletConfigValue(WalletConfigDID) != "" {
		t.initAdapterDid()
	}

	t.Router.HandleFunc("/api/v1/version", utils.GetReleaseInfo).Methods("GET")

	t.Router.HandleFunc("/api/register", t.register).Methods("POST")

	t.Router.HandleFunc("/api/getstatus/{token}", t.handleGetStatus()).Methods("GET")

	for _, s := range subscribedObjects {
		t.Router.HandleFunc(fmt.Sprintf("/api/subscriber/%s", s.Name), t.handleSubscribedObject(s)).Methods("POST")
	}

	for _, r := range rules {
		t.Router.HandleFunc(fmt.Sprintf("/api/%s/{token}", r.Name), t.handleRule(r)).Methods("POST")
	}

	for _, d := range data {
		t.Router.HandleFunc(fmt.Sprintf("/api/%s/{token}", d.Name), t.handleData(d)).Methods("GET")
	}

	t.port = os.Getenv(ConfigTrustProviderPort)
	if t.port == "" {
		t.port = "3000"
	}
	return t
}

func (t *TrustProvider) ListenAndServe() error {
	http.Handle(applyNewRelic("/", handlers.LoggingHandler(os.Stdout, utils.CorrelationIdMiddleware(t.Router))))

	log.Printf("Listening on port: %s", t.port)
	return http.ListenAndServe(":"+t.port, nil)
}

func (t *TrustProvider) register(w http.ResponseWriter, r *http.Request) {

	logger := utils.Logger(r.Context())

	err, onboardingVC, pairwiseDoc, stringVars, numberVars, boolVars, arrayVars := t.parseRequestBody(w, r, t.onboarding.Parameters, t.onboarding.VerifiableCredential)
	if err != nil {
		res := trustProviderResponse{Status: false, OnBoardingRequired: true, Message: err.Error()}
		utils.WriteJSON(res, http.StatusBadRequest, w)
		return
	}

	if t.onboarding.OnboardingFunc == nil {
		err := errors.New("TrustProvider.onboarding.OnboardingFunc not implemented!")
		logger.Errorf("TrustProvider.onboarding.OnboardingFunc not implemented!")
		utils.SetErrorStatus(err, http.StatusInternalServerError, w)
		return
	}

	account, err, token := t.onboarding.OnboardingFunc(stringVars, numberVars, boolVars, arrayVars)
	//log.Print("Account - ", account)
	if err != nil {
		if e, ok := err.(TrustProviderErrorResponse); ok {
			res := trustProviderResponse{
				Status: e.OnboardingStatus,
				OnBoardingRequired: e.OnboardingRequired,
				IgnoreAttempt: e.HttpStatus >= 500,
				Message: err.Error(),
			}
			utils.WriteJSON(res, http.StatusOK, w)
			return
		} else {
			res := trustProviderResponse{Status: false, OnBoardingRequired: true, Message: err.Error()}
			utils.WriteJSON(res, http.StatusOK, w)
			return
		}
	}

	if token == "" {
		token = uuid.New().String()
		log.Printf("[INFO] Created token for user: %s", token)
	}

	err = t.account.Update(account, token)
	if err != nil {
		res := trustProviderResponse{Status: false, OnBoardingRequired: true}
		utils.WriteJSON(res, http.StatusInternalServerError, w)
		return
	}

	if stringVars["did"] != "" {
		pairwiseDoc, err = t.initializeEncryption(stringVars, w, pairwiseDoc)
		if err != nil {
			utils.SendError(err, w)
			return
		}
	}
	var vc *wallet.RatchetPayload
	if (onboardingVC != nil || stringVars["did"] != "") && len(t.onboarding.Claims) > 0 {
		vc, err = t.sendVerifiableCredential(t.onboarding.Claims, stringVars, onboardingVC, account, token, pairwiseDoc, r.Context())
		if err != nil {
			utils.SendError(err, w)
			return
		}
	}

	res := trustProviderResponse{Status: true, OnBoardingRequired: false, Token: token, VerifiableClaim: vc}
	utils.WriteJSON(res, http.StatusCreated, w)

}

func (t *TrustProvider) handleData(data Data) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		logger := utils.Logger(r.Context())

		var body interface{}
		err := utils.ReadBody(&body, r)
		if err != nil {
			logger.Error("error", err.Error())
			utils.SetErrorStatus(err, http.StatusBadRequest, w)
			return
		}

		vars := mux.Vars(r)
		token := vars["token"]

		account, err := t.account.Read(token)
		if err != nil {
			logger.Error(" error", err.Error())
			utils.SetErrorStatus(err, http.StatusBadRequest, w)
			return
		}

		resp, err := data.DataFunc(account)
		if err != nil {
			logger.Error("error", err.Error())
			utils.SetErrorStatus(err, http.StatusServiceUnavailable, w)
			return
		}

		// Inside the rule function they can update the account object and we will persist it for them!
		t.account.Update(account, token)

		utils.WriteJSON(resp, http.StatusOK, w)

	})
}

func (t *TrustProvider) handleRule(rule Rule) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		logger := utils.Logger(r.Context())

		err, onboardingVC, pairwiseDoc, stringVars, numberVars, boolVars, arrayVars := t.parseRequestBody(w, r, rule.Parameters, rule.VerifiableCredential)
		if err != nil {
			utils.WriteJSON(trustProviderResponse{Status: false, OnBoardingRequired: true}, http.StatusBadRequest, w)
			return
		}

		vars := mux.Vars(r)
		token := vars["token"]

		account, err := t.account.Read(token)
		if err != nil {
			logger.Error("error", err.Error())
			utils.SetErrorStatus(err, http.StatusBadRequest, w)
			return
		}

		status, err := rule.RuleFunc(stringVars, numberVars, boolVars, arrayVars, account)
		if err != nil {
			if err.Error() == ErrorOnboardingRequired {
				utils.WriteJSON(trustProviderResponse{Status: false, OnBoardingRequired: true}, http.StatusOK, w)
				return
			}
			if err.Error() == ErrorCredentialAlreadySent {
				utils.WriteJSON(trustProviderResponse{Status: status}, http.StatusOK, w)
				return
			}
			logger.Error("error: ", err.Error())
			utils.SetErrorStatus(err, http.StatusServiceUnavailable, w)
			return
		}

		// Inside the rule function they can update the account object and we will persist it for them!
		t.account.Update(account, token)

		if stringVars["did"] != "" {
			pairwiseDoc, err = t.initializeEncryption(stringVars, w, pairwiseDoc)
			if err != nil {
				utils.SendError(err, w)
				return
			}
		}
		if status && stringVars["did"] != "" && len(rule.Claims) > 0 {
			_, err = t.sendVerifiableCredential(rule.Claims, stringVars, onboardingVC, account, token, pairwiseDoc, r.Context())
			if err != nil {
				utils.SendError(err, w)
				return
			}
		}

		utils.WriteJSON(trustProviderResponse{Status: status}, http.StatusOK, w)
	})
}

func (t *TrustProvider) handleSubscribedObject(subscribedObject SubscribedObject) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		logger := utils.Logger(r.Context())
		body, err := ioutil.ReadAll(r.Body)

		log.Printf("Body = \n\n%s", body)

		var subscriber Subscriber
		err = json.Unmarshal(body, &subscriber)
		if err != nil {
			logger.Error("error", err.Error())
			utils.SetErrorStatus(err, http.StatusBadRequest, w)
			return
		}

		stringVars, numberVars, boolVars, arrayVars, err := t.parseParameters(subscriber.Data, subscribedObject.Parameters, r)
		if err != nil {
			logger.Error("error", err.Error())
			utils.SetErrorStatus(err, http.StatusBadRequest, w)
			return
		}

		// FIXME: How does the subscribe work without knowing the account???
		status, err := subscribedObject.SubscribedObjectFunc(stringVars, numberVars, boolVars, arrayVars)
		if err != nil {
			logger.Error("error", err.Error())
			utils.SetErrorStatus(err, http.StatusServiceUnavailable, w)
			return
		}

		utils.WriteJSON(trustProviderResponse{Status: status}, http.StatusOK, w)

	})
}

func (t *TrustProvider) parseParameters(body interface{}, params []Parameter, r *http.Request) (map[string]string, map[string]float64, map[string]bool, map[string]interface{}, error) {
	var ve []string

	strs := make(map[string]string, 0)
	nums := make(map[string]float64, 0)
	bools := make(map[string]bool, 0)
	inters := make(map[string]interface{}, 0)

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
			case ParameterTypeInterface:
				if i, ok := params[p.Name].(interface{}); ok {
					inters[p.Name] = i
				} else {
					ve = append(ve, fmt.Sprintf("Parameter %s must be an array.", p.Name))
				}
			}
		}
	}

	if len(ve) > 0 {
		e, err := json.Marshal(ve)
		if err == nil {
			err = errors.New(string(e))
		}
		return nil, nil, nil, nil, err
	}

	return strs, nums, bools, inters, nil
}

func (t *TrustProvider) createPairwiseDid(w *wallet.Wallet, resolver did.ResolverInterface) (*did.Document, error) {
	u, _ := uuid.New().MarshalBinary()
	pairwiseDid := "did:vvo:" + base58.Encode(u)

	genD := &did.GenerateDidDocument{Resolver: resolver}
	document, err := genD.Generate(pairwiseDid, w, true)
	if err != nil {
		return nil, err
	}

	return document, nil
}

func (t *TrustProvider) decryptAndParseVerifiableCredential(w http.ResponseWriter, r *http.Request) (body map[string]interface{}, pairwiseDdoc *did.Document, onboardingVC *did.VerifiableClaim, err error) {
	logger := utils.Logger(r.Context())

	messaging := t.Wallet.Messaging()

	var ratchetPayload = wallet.RatchetPayload{}
	err = utils.ReadBody(&ratchetPayload, r)

	if err != nil {
		logger.Errorf("Problem unmarshalling onboarding request ratchetPayload", "error", err.Error())
		utils.SetErrorStatus(err, http.StatusBadRequest, w)
		return
	}

	ourDid := getWalletConfigValue(WalletConfigDID)
	pairwiseDdoc, err = t.createPairwiseDid(t.Wallet, t.resolver)
	if err != nil {
		utils.SendError(err, w)
		return
	}

	err = messaging.InitDoubleRatchetWithWellKnownPublicKey(ourDid, pairwiseDdoc.Id, ratchetPayload.InitializationKey)
	if err != nil {
		utils.SendError(err, w)
		return
	}

	payload, err := messaging.RatchetDecrypt(pairwiseDdoc.Id, &ratchetPayload)
	if err != nil {
		utils.SendError(err, w)
		return
	}

	err = json.Unmarshal([]byte(payload), &body)
	if err != nil {
		utils.SendError(err, w)
		return
	}

	var ve []string
	onboardingVC, ve = t.parseVerifiableCredential(body, logger)
	if len(ve) > 0 {
		e, err := json.Marshal(ve)
		if err == nil {
			err = errors.New(string(e))
		}
		logger.Errorf("Problem verifying the Verifiable Credential", "error", ve)
		utils.SetErrorStatus(err, http.StatusBadRequest, w)
		return body, pairwiseDdoc, onboardingVC, err
	}

	body = onboardingVC.Claim
	return
}

func (t *TrustProvider) parseRequestBody(w http.ResponseWriter, r *http.Request, parameters []Parameter, requireVC bool) (error, *did.VerifiableClaim, *did.Document, map[string]string, map[string]float64, map[string]bool, map[string]interface{}) {
	var body map[string]interface{}

	logger := utils.Logger(r.Context())

	err := utils.ReadBody(&body, r)
	if err != nil {
		logger.Errorf("Problem unmarshalling onboarding request body", "error", err.Error())
		return err, nil, nil, nil, nil, nil, nil
	}
	var onboardingVC *did.VerifiableClaim
	var pairwiseDoc *did.Document
	if t.isDoubleRatchetEncrypted(body) {
		body, pairwiseDoc, onboardingVC, err = t.decryptAndParseVerifiableCredential(w, r)
		if err != nil {
			logger.Errorf("Problem decrypting and parsing onboarding request ratchetPayload", "error", err.Error())
			return err, nil, nil, nil, nil, nil, nil
		}
	} else if requireVC {
		err := errors.New("must present a verifiable credential")
		logger.Errorf(err.Error())
		return err, nil, nil, nil, nil, nil, nil
	}
	stringVars, numberVars, boolVars, arrayVars, err := t.parseParameters(body, parameters, r)
	if err != nil {
		logger.Errorf("Problem parsing onboarding request parameters", "error", err.Error())
		return err, nil, nil, nil, nil, nil, nil
	}
	return err, onboardingVC, pairwiseDoc, stringVars, numberVars, boolVars, arrayVars
}

func (t *TrustProvider) sendVerifiableCredential(claims []string, stringVars map[string]string, onboardingVC *did.VerifiableClaim, account interface{}, token string, pairwiseDoc *did.Document, ctx context.Context) (*wallet.RatchetPayload, error) {
	logger := utils.Logger(ctx)

	var encryptedVerifiableCredential *wallet.RatchetPayload

	var subject string
	if stringVars["did"] != "" {
		subject = stringVars["did"]
	} else {
		subject = onboardingVC.Claim[did.SubjectClaim].(string)
	}
	c := make(map[string]interface{})
	acctJson, _ := json.Marshal(account)
	json.Unmarshal(acctJson, &c)
	claim, err := t.generateVerifiableClaim(c, subject, token, append([]string{did.VerifiableCredential}, claims...))
	if err != nil {
		logger.Errorf("Problem generating a verifiable credential response", "error", err.Error())
		return nil, err
	}
	claimJson, _ := json.Marshal(claim)
	message := MessageDto{Type: "credential", Payload: string(claimJson)}
	m, _ := json.Marshal(message)
	rp, err := t.Wallet.Messaging().RatchetEncrypt(pairwiseDoc.Id, string(m))
	if err != nil {
		return nil, err
	}
	rp.Sender = getWalletConfigValue(WalletConfigDID)
	encryptedVerifiableCredential = rp
	t.pushNotification(subject, encryptedVerifiableCredential)
	return encryptedVerifiableCredential, nil
}

func (t *TrustProvider) initializeEncryption(s map[string]string, w http.ResponseWriter, pairwiseDoc *did.Document) (*did.Document, error) {
	messaging := t.Wallet.Messaging()
	contactDoc, err := t.resolver.Resolve(s["did"])
	if err != nil {
		res := trustProviderResponse{Status: false, OnBoardingRequired: true}
		utils.WriteJSON(res, http.StatusBadRequest, w)
	}
	pairwiseDoc, err = t.createPairwiseDid(t.Wallet, t.resolver)
	if err != nil {
		return nil, err
	}
	var contactPubkey string
	for _, k := range contactDoc.PublicKey {
		if k.T == wallet.TypeEd25519KeyExchange2018 {
			contactPubkey = k.PublicKeyBase58
		}
	}
	if contactPubkey == "" {
		return nil, errors.New("no ed25519 exchange key found")
	}
	err = messaging.InitDoubleRatchet(pairwiseDoc.Id, contactPubkey)
	if err != nil {
		return nil, err
	}
	return pairwiseDoc, nil
}

func (t *TrustProvider) isDoubleRatchetEncrypted(b map[string]interface{}) bool {
	return b["sender"] != nil && b["dhs"] != nil && b["pn"] != nil && b["ns"] != nil && b["payload"] != nil && b["initializationKey"] != nil
}

func (t *TrustProvider) pushNotification(subject string, vc *wallet.RatchetPayload) error {
	ddoc, err := t.resolver.Resolve(subject)
	if err != nil {
		log.Println(err.Error())
		return err
	}

	for _, s := range ddoc.Service {
		if s.T == "AgentService" {
			log.Printf("Sending verifiable credential to messaging endpoint: %s", s.ServiceEndpoint)
			_, err = resty.New().
				R().
				SetBody(vc).
				Post(s.ServiceEndpoint)
		}
	}

	return err
}

func (t *TrustProvider) parseVerifiableCredential(body interface{}, logger *zap.SugaredLogger) (*did.VerifiableClaim, []string) {
	var vc *did.VerifiableClaim
	var ve []string
	logger.Infow("Checking for Verifiable Credential...")
	vcJson, err := json.Marshal(body)
	if err != nil {
		ve = append(ve, fmt.Sprintf("Unable to unmarshal Verifiable Credential."))
		return nil, ve
	}
	var cred did.VerifiableClaim
	err = json.Unmarshal(vcJson, &cred)
	if err != nil {
		ve = append(ve, fmt.Sprintf("Unable to unmarshal Verifiable Credential."))
		return nil, ve
	}

	vc = &cred

	// If this is an IAmMeCredential and includes their did document, then this must be a pairwise did that was not
	// registered with the Eeze service. Toss that bad boy in our Wallet!
	if containsType(cred.Type, did.IAmMeCredential) {
		t.Wallet.Dids().Create(cred.Claim[did.SubjectClaim].(string), cred.Claim["ddoc"].(string), nil)
	}

	err = cred.Verify([]string{did.VerifiableCredential}, cred.Proof.Nonce, t.resolver)
	if err != nil {
		log.Println(err.Error())
		ve = append(ve, fmt.Sprintf("Unable to verify Verifiable Credential."))
		return nil, ve
	}

	if !containsType(cred.Type, did.IAmMeCredential) {
		//TODO:  only accept verifiable credentials from issuers we TrustProvider!
	}

	return vc, ve
}

func (t *TrustProvider) generateVerifiableClaim(c map[string]interface{}, subject string, token string, types []string) (did.VerifiableClaim, error) {
	id := getWalletConfigValue(WalletConfigDID)

	c[did.SubjectClaim] = subject
	c[did.PublicKeyClaim] = fmt.Sprintf("%s#keys-1", token)

	var claim = did.Claim{
		Id:     uuid.New().String(),
		Type:   types,
		Issuer: id,
		Issued: time.Now().Format("2006-01-02"),
		Claim:  c,
	}

	return claim.WalletSign(t.Wallet, id, uuid.New().String())
}

func (t *TrustProvider) handleGetStatus() http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		logger := utils.Logger(r.Context())

		vars := mux.Vars(r)
		token := vars["token"]

		acct, err := t.account.Read(token)
		if err != nil {
			logger.Error("error", err.Error())
			utils.SetErrorStatus(err, http.StatusBadRequest, w)
			return
		}

		statusResponse, err := t.getStatus.GetStatusFunc(acct)
		if err != nil {
			utils.SetErrorStatus(err, http.StatusServiceUnavailable, w)
		} else {
			utils.WriteJSON(statusResponse, http.StatusOK, w)
		}
	})
}

func (t *TrustProvider) initAdapterDid() error {
	id := getWalletConfigValue(WalletConfigDID)
	if id == "" {
		log.Fatalf("Missing environment variable DID")
	}
	w, err := walletFactory(t)
	if err != nil {
		log.Fatalf("Wallet error: %s", err.Error())
	}

	t.Wallet = w
	wr := WalletResolver{resolver: t.resolver, wallet: t.Wallet, generateDDoc: did.GenerateDidDocument{Resolver: t.resolver}}
	t.resolver = &wr

	_, err = t.resolver.Resolve(id)
	if err == nil {
		log.Println("DID already published")

		if getWalletConfigValue("PRIVATE_KEY") != "" {
			log.Println("Adding private key to Wallet from env variable.")
			pk := strings.Replace(getWalletConfigValue("PRIVATE_KEY"), "\\n", "\n", -1)
			err = t.Wallet.Add(wallet.TypeRsaVerificationKey2018, getWalletConfigValue(WalletConfigDID), pk, nil)
			if err != nil {
				log.Println(err.Error())
			}
		}

		return nil
	}

	_, err = wr.generateDDoc.Generate(id, w, true)
	if err != nil {
		log.Println(err.Error())
	}

	log.Println("Adapter DID document created.")

	return nil

}

func walletFactory(t *TrustProvider) (*wallet.Wallet, error) {
	if dsn := getWalletConfigValue(WalletConfigMariadbDSN); dsn != "" {
		return mariadbWalletFactory(t, dsn)
	} else {
		return sqliteWalletFactory(t)
	}
}

func sqliteWalletFactory(t *TrustProvider) (*wallet.Wallet, error) {
	masterKey := getWalletConfigValue(WalletConfigMasterKey)
	id := getWalletConfigValue(WalletConfigDID)

	var w *wallet.Wallet

	if _, err := os.Stat(DefaultWalletId); os.IsNotExist(err) {
		w, err = wallet.Create([]byte(masterKey), DefaultWalletId)
		if err != nil {
			fmt.Println("error opening Wallet: ", err.Error())
			return nil, err
		}
	} else {
		if w, err = wallet.Open([]byte(masterKey), DefaultWalletId); err == nil {

			t.Wallet = w
			wr := WalletResolver{resolver: t.resolver, wallet: t.Wallet, generateDDoc: did.GenerateDidDocument{Resolver: t.resolver}}
			t.resolver = &wr

			d, _ := w.Dids().Read(id)
			if err != nil {
				fmt.Println("error opening Wallet:", err.Error())
				return nil, err
			}
			if len(d) > 0 {
				fmt.Println("Adapter DID doc already exist")
				return nil, nil
			}
		} else {
			log.Fatalf("Unable to open the Wallet!")
		}
	}
	return w, nil
}

func mariadbWalletFactory(t *TrustProvider, dsn string) (*wallet.Wallet, error) {
	masterKey := getWalletConfigValue(WalletConfigMasterKey)

	var w *wallet.Wallet
	var err error

	ws, err := mariadb.Init(dsn)
	if err != nil {
		return nil, err
	}

	if w, err = wallet.OpenFromStorage(append([]byte{}, []byte(masterKey)...), ws); err == wallet.ErrNotInitialized {
		log.Println("Initializing Wallet!")
		return wallet.CreateFromStorage(append([]byte{}, []byte(masterKey)...), ws)
	} else if err != nil {
		log.Printf("Error opening the Wallet! Check your connection details [%s]", dsn)
		return nil, err
	} else {
		return w, nil
	}
}

func getWalletConfigValue(name string) string {
	prefix := "WALLET_"
	if c := os.Getenv(prefix + name); c != "" {
		return c
	} else {
		return os.Getenv(name)
	}
}

func applyNewRelic(pattern string, handler http.Handler) (string, http.Handler) {
	if os.Getenv("NEW_RELIC_APP_NAME") == "" || os.Getenv("NEW_RELIC_LICENSE_KEY") == "" {
		log.Println("New Relic not configured...")
		return pattern, handler
	}

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

func containsType(types []string, t string) bool {
	for _, i := range types {
		if i == t {
			return true
		}
	}
	return false
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

type WalletResolver struct {
	resolver     did.ResolverInterface
	wallet       *wallet.Wallet
	generateDDoc did.GenerateDidDocument
}

func (wr *WalletResolver) Resolve(id string) (*did.Document, error) {
	j, err := wr.wallet.Dids().Read(id)
	if err != nil || j == "" {
		return wr.resolver.Resolve(id)
	}

	var ddoc = did.Document{}
	err = json.Unmarshal([]byte(j), &ddoc)

	return &ddoc, err
}

func (wr *WalletResolver) Register(ddoc *did.Document, opts ...string) error {
	return wr.resolver.Register(ddoc)
}

func (wr *WalletResolver) GenerateDDoc(id string, w *wallet.Wallet) (*did.Document, error) {
	doc, err := wr.generateDDoc.Generate(id, w, true)
	if err != nil {
		println(err.Error())
		return nil, err
	}

	return doc, nil
}
