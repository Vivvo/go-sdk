package trustprovider

import (
	"encoding/json"
	"fmt"
	"github.com/Vivvo/go-sdk/did"
	"github.com/Vivvo/go-sdk/utils"
	"github.com/Vivvo/go-wallet"
	"github.com/btcsuite/btcutil/base58"
	"github.com/go-resty/resty"
	"github.com/google/uuid"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/newrelic/go-agent"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// Parameters:
//     An array of required/optional parameters that the onboarding function will have access to. Validation will automatically
//     be applied based on how the parameters are configured.
// Claims:
//    The types of the verifiable credential that will be issued when onboarding succeeds.
// OnboardingFunc:
//    This function should execute the required business logic to ensure that the person onboarding is tied to
//    and account in your system. The interface{} that is returned from here should be your implementation of an account.
type Onboarding struct {
	Parameters     []Parameter
	Claims         []string
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

type Data struct {
	Name     string
	DataFunc func(acct interface{}) (interface{}, error)
}

type SubscribedObject struct {
	Name                 string
	Parameters           []Parameter
	SubscribedObjectFunc func(s map[string]string, n map[string]float64, b map[string]bool, acct interface{}) (bool, error)
}

type trustProviderResponse struct {
	Status             bool                   `json:"value"`
	Message            string                 `json:"message,omitempty"`
	OnBoardingRequired bool                   `json:"onBoardingRequired"`
	Token              string                 `json:"token,omitempty"`
	VerifiableClaim    *wallet.RatchetPayload `json:"verifiableClaim,omitempty"`
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
	onboarding       Onboarding
	rules            []Rule
	subscribedObject []SubscribedObject
	Router           *mux.Router
	account          Account
	port             string
	resolver         did.ResolverInterface
	wallet           *wallet.Wallet
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

//TODO: Clean up, Move to the did folder maybe?
func (t *TrustProvider) createPairwiseDid(w *wallet.Wallet) (*did.Document, error) {
	u, _ := uuid.New().MarshalBinary()
	pairwiseDid := "did:vvo:" + base58.Encode(u)

	document, err := t.generateDidDocument(pairwiseDid, w)
	if err != nil {
		return nil, err
	}

	return document, nil
}

func (t *TrustProvider) generateDidDocument(id string, w *wallet.Wallet) (*did.Document, error) {
	doc := did.Document{}
	doc.Context = "https://w3id.org/did/v1"
	doc.Id = id

	rsaPublicKey, err := w.Crypto().GenerateRSAKey("RsaVerificationKey2018", id)
	if err != nil {
		return nil, err
	}

	ed25519PublicKey, err := w.Crypto().GenerateEd25519Key("Ed25519KeyExchange2018", id)
	if err != nil {
		return nil, err
	}

	pubKey := did.PublicKey{
		Owner:        id,
		Id:           fmt.Sprintf("%s#keys-1", id),
		T:            "RsaVerificationKey2018",
		PublicKeyPem: rsaPublicKey,
	}

	pubKey2 := did.PublicKey{
		Owner:           id,
		Id:              fmt.Sprintf("%s#keys-2", id),
		T:               "Ed25519KeyExchange2018",
		PublicKeyBase58: ed25519PublicKey,
	}

	doc.PublicKey = []did.PublicKey{pubKey, pubKey2}

	auth := did.Authentication{}
	auth.PublicKey = pubKey.Id
	auth.T = "RsaSignatureAuthentication2018"
	doc.Authentication = []did.Authentication{auth}

	docJson, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}

	err = w.Dids().Create(doc.Id, string(docJson), nil)
	if err != nil {
		return nil, err
	}

	return &doc, err
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

	var onboardingVC *did.VerifiableClaim
	var pairwiseDoc *did.Document

	if b, ok := body.(map[string]interface{}); ok {
		if b["sender"] != nil && b["dhs"] != nil && b["pn"] != nil && b["ns"] != nil && b["payload"] != nil && b["initializationKey"] != nil {
			// Must be an encrypted payload!
			logger := utils.Logger(r.Context())

			messaging := t.wallet.Messaging()

			var ratchetPayload = wallet.RatchetPayload{}
			err = utils.ReadBody(&ratchetPayload, r)

			if err != nil {
				logger.Errorf("Problem unmarshalling onboarding request ratchetPayload", "error", err.Error())
				utils.SetErrorStatus(err, http.StatusBadRequest, w)
				return
			}

			ourDid := os.Getenv("DID")
			pairwiseDoc, err = t.createPairwiseDid(t.wallet)
			if err != nil {
				utils.SendError(err, w)
				return
			}

			err = messaging.InitDoubleRatchetWithWellKnownPublicKey(ourDid, pairwiseDoc.Id, ratchetPayload.InitializationKey)
			if err != nil {
				utils.SendError(err, w)
				return
			}

			payload, err := messaging.RatchetDecrypt(pairwiseDoc.Id, &ratchetPayload)
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
				return
			}

			body = onboardingVC.Claim
		}
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
	if err != nil {
		res := trustProviderResponse{Status: false, OnBoardingRequired: true, Message: err.Error()}
		utils.WriteJSON(res, http.StatusOK, w)
		return
	}

	if token == "" {
		token = uuid.New().String()
	}

	err = t.account.Update(account, token)

	if err != nil {
		res := trustProviderResponse{Status: false, OnBoardingRequired: true}
		utils.WriteJSON(res, http.StatusInternalServerError, w)
		return
	}

	if s["did"] != "" {
		// Initialize the double ratchet encryption...

		messaging := t.wallet.Messaging()

		contactDoc, err := t.resolver.Resolve(s["did"])
		if err != nil {
			res := trustProviderResponse{Status: false, OnBoardingRequired: true}
			utils.WriteJSON(res, http.StatusBadRequest, w)
		}

		pairwiseDoc, err = t.createPairwiseDid(t.wallet)
		if err != nil {
			utils.SendError(err, w)
			return
		}

		var contactPubkey string
		for _, k := range contactDoc.PublicKey {
			if k.T == wallet.TypeEd25519KeyExchange2018 {
				contactPubkey = k.PublicKeyBase58
			}
		}

		if contactPubkey == "" {
			utils.SendError(errors.New("no ed25519 exchange key found"), w)
			return
		}

		err = messaging.InitDoubleRatchet(pairwiseDoc.Id, contactPubkey)
		if err != nil {
			utils.SendError(err, w)
			return
		}
	}

	var vc *wallet.RatchetPayload
	if (onboardingVC != nil || s["did"] != "") && len(t.onboarding.Claims) > 0 {
		var subject string
		if s["did"] != "" {
			subject = s["did"]
		} else {
			subject = onboardingVC.Claim[did.SubjectClaim].(string)
		}

		c := make(map[string]interface{})
		acctJson, _ := json.Marshal(account)
		json.Unmarshal(acctJson, &c)

		claim, _ := t.generateVerifiableClaim(c, subject, token, append([]string{did.VerifiableCredential}, t.onboarding.Claims...))
		if err != nil {
			logger.Errorf("Problem generating a verifiable credential response", "error", err.Error())
			utils.SetErrorStatus(err, http.StatusInternalServerError, w)
			return
		}

		claimJson, _ := json.Marshal(claim)

		message := MessageDto{Type: "credential", Payload: string(claimJson)}

		m, _ := json.Marshal(message)

		rp, err := t.wallet.Messaging().RatchetEncrypt(pairwiseDoc.Id, string(m))
		if err != nil {
			utils.SendError(err, w)
			return
		}

		rp.Sender = os.Getenv("DID")

		vc = rp

		t.pushNotification(subject, vc)
	}

	res := trustProviderResponse{Status: true, OnBoardingRequired: false, Token: token, VerifiableClaim: vc}
	utils.WriteJSON(res, http.StatusCreated, w)

}

func (t *TrustProvider) pushNotification(subject string, vc *wallet.RatchetPayload) error {
	d, err := t.wallet.Dids().Read(subject)
	if err != nil {
		log.Println("error reading contacts ddoc from wallet", err.Error())
		return err
	}

	var ddoc did.Document
	err = json.Unmarshal([]byte(d), &ddoc)
	if err != nil {
		log.Println("error unmarshalling", err.Error())
		return err
	}

	for _, s := range ddoc.Service {
		if s.T == "AgentService" {
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
	// registered with the Eeze service. Toss that bad boy in our wallet!
	if containsType(cred.Type, did.IAmMeCredential) {
		t.wallet.Dids().Create(cred.Claim[did.SubjectClaim].(string), cred.Claim["ddoc"].(string), nil)
	}

	err = cred.Verify([]string{did.VerifiableCredential}, cred.Proof.Nonce, t.resolver)
	if err != nil {
		log.Println(err.Error())
		ve = append(ve, fmt.Sprintf("Unable to verify Verifiable Credential."))
		return nil, ve
	}

	if !containsType(cred.Type, did.IAmMeCredential) {
		//TODO:  only accept verifiable credentials from issuers we trust!
	}

	return vc, ve
}

func containsType(types []string, t string) bool {
	for _, i := range types {
		if i == t {
			return true
		}
	}
	return false
}

func (t *TrustProvider) generateVerifiableClaim(c map[string]interface{}, subject string, token string, types []string) (did.VerifiableClaim, error) {
	id := os.Getenv("DID")

	c[did.SubjectClaim] = subject
	c[did.PublicKeyClaim] = fmt.Sprintf("%s#keys-1", token)

	var claim = did.Claim{
		Id:     uuid.New().String(),
		Type:   types,
		Issuer: id,
		Issued: time.Now().Format("2006-01-02"),
		Claim:  c,
	}

	return claim.WalletSign(t.wallet, id, uuid.New().String())
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

		acct, err := t.account.Read(token)
		if err != nil {
			logger.Error("error", err.Error())
			utils.SetErrorStatus(err, http.StatusBadRequest, w)
			return
		}

		resp, err := data.DataFunc(acct)
		if err != nil {
			logger.Error("error", err.Error())
			utils.SetErrorStatus(err, http.StatusServiceUnavailable, w)
			return
		}

		utils.WriteJSON(resp, http.StatusOK, w)

	})
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
			//var vc *did.VerifiableClaim
			//connectionClaim, ve := t.parseVerifiableCredential(body, []string{did.VerifiableCredential, did.TokenizedConnectionCredential}, logger)
			//if len(ve) > 0 {
			//	e, err := json.Marshal(ve)
			//	if err == nil {
			//		err = errors.New(string(e))
			//	}
			//
			//	logger.Errorf("Problem verifying Verifiable Credential", "error", err.Error())
			//
			//	utils.SetErrorStatus(err, http.StatusBadRequest, w)
			//	return
			//}
			//
			//if connectionClaim != nil {
			//	ac := make(map[string]interface{})
			//	for k, v := range s {
			//		ac[k] = v
			//	}
			//	for k, v := range n {
			//		ac[k] = v
			//	}
			//	for k, v := range b {
			//		ac[k] = v
			//	}
			//
			//	claim, err := t.generateVerifiableClaim(ac, connectionClaim.Claim[did.SubjectClaim].(string), uuid.New().String(), rule.Claims)
			//	if err != nil {
			//		logger.Error("error", err.Error())
			//		utils.SetErrorStatus(err, http.StatusInternalServerError, w)
			//		return
			//	}
			//	vc = &claim
			//}
			//utils.WriteJSON(trustProviderResponse{Status: status, VerifiableClaim: vc}, http.StatusOK, w)
			utils.WriteJSON(trustProviderResponse{Status: status}, http.StatusOK, w)
		} else {
			utils.WriteJSON(trustProviderResponse{Status: status}, http.StatusOK, w)
		}
	})
}

func (t *TrustProvider) handleSubscribedObject(subscribedObject SubscribedObject) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		logger := utils.Logger(r.Context())

		var body interface{}
		err := utils.ReadBody(&body, r)
		if err != nil {
			logger.Error("error", err.Error())
			utils.SetErrorStatus(err, http.StatusBadRequest, w)
			return
		}
		s, n, b, err := t.parseParameters(body, subscribedObject.Parameters, r)
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

		status, err := subscribedObject.SubscribedObjectFunc(s, n, b, acct)
		if err != nil {
			logger.Error("error", err.Error())
			utils.SetErrorStatus(err, http.StatusServiceUnavailable, w)
			return
		}

		utils.WriteJSON(trustProviderResponse{Status: status}, http.StatusOK, w)

	})
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

type WalletResolver struct {
	resolver did.ResolverInterface
	wallet   *wallet.Wallet
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

func (wr *WalletResolver) Register(ddoc *did.Document) error {
	return wr.resolver.Register(ddoc)
}

// Create a new TrustProvider. Based on the onboarding, rules and account objects you pass in
// this will bootstrap an http server with onboarding and rules endpoints exposed.
func New(onboarding Onboarding, rules []Rule, subscribedObjects []SubscribedObject, data []Data, account Account, resolver did.ResolverInterface) TrustProvider {
	t := TrustProvider{onboarding: onboarding, rules: rules, subscribedObject: subscribedObjects, account: account, Router: mux.NewRouter(), resolver: resolver}

	if os.Getenv("DID") != "" {
		t.initAdapterDid()
	}

	t.Router.HandleFunc("/api/register", t.register).Methods("POST")

	for _, s := range subscribedObjects {
		t.Router.HandleFunc(fmt.Sprintf("/api/subscriber/%s/{token}", s.Name), t.handleSubscribedObject(s)).Methods("POST")
	}

	for _, r := range rules {
		t.Router.HandleFunc(fmt.Sprintf("/api/%s/{token}", r.Name), t.handleRule(r)).Methods("POST")
	}

	for _, d := range data {
		t.Router.HandleFunc(fmt.Sprintf("/api/%s/{token}", d.Name), t.handleData(d)).Methods("GET")
	}

	const TrustProviderPortKey = "TRUST_PROVIDER_PORT"
	t.port = os.Getenv(TrustProviderPortKey)
	if t.port == "" {
		t.port = "3000"
	}
	return t
}

func (t *TrustProvider) initAdapterDid() (error) {
	id := os.Getenv("DID")
	if id == "" {
		log.Fatalf("Missing environment variable DID")
	}
	masterKey := os.Getenv("MASTER_KEY")

	_, err := t.resolver.Resolve(id)
	if err == nil {
		log.Println("DID already published")
		return nil
	}

	var w *wallet.Wallet
	if _, err := os.Stat(DefaultWalletId); os.IsNotExist(err) {
		w, err = wallet.Create([]byte(masterKey), DefaultWalletId)
		if err != nil {
			fmt.Println("error opening wallet: ", err.Error())
			return err
		}
	} else {
		if w, err = wallet.Open([]byte(masterKey), DefaultWalletId); err == nil {
			t.wallet = w
			wr := WalletResolver{resolver: t.resolver, wallet: t.wallet}
			t.resolver = &wr

			d, _ := w.Dids().Read(id)
			if err != nil {
				fmt.Println("error opening wallet:", err.Error())
				return err
			}
			if len(d) > 0 {
				fmt.Println("Adapter DID doc already exist")
				return nil
			}
		} else {
			log.Fatalf("Unable to open the wallet!")
		}
	}

	t.wallet = w
	wr := WalletResolver{resolver: t.resolver, wallet: t.wallet}
	t.resolver = &wr

	rsaPublicKey, err := t.wallet.Crypto().GenerateRSAKey("RsaVerificationKey2018", id)
	if err != nil {
		return err
	}

	ed25519PublicKey, err := t.wallet.Crypto().GenerateEd25519Key("Ed25519KeyExchange2018", id)
	if err != nil {
		return err
	}

	doc := &did.Document{
		Id:             id,
		PublicKey:      []did.PublicKey{{Owner: id, Id: fmt.Sprintf("%s#keys-1", id), PublicKeyPem: rsaPublicKey, T: "RsaVerificationKey2018"}, {Owner: id, Id: fmt.Sprintf("%s#keys-2", id), T: "Ed25519KeyExchange2018", PublicKeyBase58: ed25519PublicKey}},
		Authentication: []did.Authentication{{T: "RsaVerificationKey2018", PublicKey: fmt.Sprintf("%s#keys-1", id)}},
		Context:        "https://w3id.org/did/v1",
	}

	docJson, err := json.Marshal(doc)
	if err != nil {
		return errors.New("error marshalling ddoc")
	}

	err = w.Dids().Create(id, string(docJson), nil)
	if err != nil {
		fmt.Println("error storing the did doc:", err.Error())
	}

	err = t.resolver.Register(doc)
	if err != nil {
		fmt.Println("error registering the did doc:", err.Error())
	}

	log.Println("Adapter DID document created.")

	return nil

}

func (t *TrustProvider) ListenAndServe() error {
	http.Handle(applyNewRelic("/", handlers.LoggingHandler(os.Stdout, utils.CorrelationIdMiddleware(t.Router))))

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
			return record.Account, nil
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
