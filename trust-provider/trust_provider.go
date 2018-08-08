package trustprovider

import (
	"net/http"
	"github.com/gorilla/mux"
	"github.com/gorilla/handlers"
	"os"
	"github.com/satori/go.uuid"
	"github.com/pkg/errors"
	"log"
	"github.com/Vivvo/go-sdk/utils"
	"fmt"
	"encoding/json"
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
	name     string
	typ      ParameterType
	required bool
}

type Rule struct {
	Name       string
	Parameters []Parameter
	RuleFunc   func(s map[string]string, n map[string]float64, b map[string]bool, acct interface{}) (bool, error)
}

type trustProviderResponse struct {
	Status             bool   `json:"value"`
	Message            string `json:"message"`
	OnBoardingRequired bool   `json:"onBoardingRequired"`
	Token              string `json:"token, omitempty"`
}

type TrustProvider struct {
	onboarding Onboarding
	rules      []Rule
	router     *mux.Router
	saveToken  SaveToken
}

type SaveToken func(account interface{}, token string) error

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
		if p.required {
			if params, ok := body.(map[string]interface{}); (ok && params[p.name] == nil) || !ok {
				ve = append(ve, fmt.Sprintf("Parameter %s is required.", p.name))
			}
		}

		if params, ok := body.(map[string]interface{}); ok && params[p.name] != nil {
			switch p.typ {
			case ParameterTypeString:
				if s, ok := params[p.name].(string); ok {
					strs[p.name] = s
				} else {
					ve = append(ve, fmt.Sprintf("Parameter %s must be a string.", p.name))
				}
			case ParameterTypeFloat64:
				if f, ok := params[p.name].(float64); ok {
					nums[p.name] = f
				} else {
					ve = append(ve, fmt.Sprintf("Parameter %s must be a number.", p.name))
				}
			case ParameterTypeBool:
				if b, ok := params[p.name].(bool); ok {
					bools[p.name] = b
				} else {
					ve = append(ve, fmt.Sprintf("Parameter %s must be a boolean.", p.name))
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
		token := uuid.Must(uuid.NewV4()).String()

		if t.saveToken == nil {
			err = defaultSaveToken(account, token)
		} else {
			err = t.saveToken(account, token)
		}

		if err != nil {
			res := trustProviderResponse{Status: false, OnBoardingRequired: true}
			utils.WriteJSON(res, http.StatusInternalServerError, w)
		} else {
			res := trustProviderResponse{Status: true, OnBoardingRequired: false, Token: token}
			utils.WriteJSON(res, http.StatusCreated, w)
		}
	} else {
		res := trustProviderResponse{Status: false, OnBoardingRequired: true}
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

		status, err := rule.RuleFunc(s, n, b, nil)
		if err != nil {
			log.Println(err.Error())
			utils.SetErrorStatus(err, http.StatusServiceUnavailable, w)
			return
		}

		utils.WriteJSON(trustProviderResponse{Status: status}, http.StatusOK, w)
	})
}

func New(onboarding Onboarding, rules []Rule, saveToken SaveToken) (TrustProvider, error) {
	t := TrustProvider{onboarding: onboarding, rules: rules, saveToken: saveToken}
	t.router = mux.NewRouter()

	t.router.HandleFunc("/api/register", t.register).Methods("POST")

	for _, rule := range rules {
		t.router.HandleFunc(fmt.Sprintf("/api/%s/{token}", rule.Name), t.handleRule(rule)).Methods("POST")
	}

	http.Handle("/", handlers.LoggingHandler(os.Stdout, t.router))

	//TODO: Get port from configuration
	go http.ListenAndServe(":3000", nil)

	return t, nil
}

func defaultSaveToken(account interface{}, token string) error {

	err := appendFile(account, token)
	if err != nil {
		return err
	}

	return err
}
