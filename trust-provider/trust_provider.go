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
	ParameterTypeBool ParameterType = iota
	ParameterTypeFloat64
	ParameterTypeString
)

type Parameter struct {
	name     string
	typ      ParameterType
	required bool
}

type Rule struct {
	Name           string
	Params         interface{}
	ParamsOptional interface{}
	RuleFunc       func() (bool, error)
}

type onboardingResponse struct {
	Status             bool   `json:"value"`
	Message            string `json:"message"`
	OnBoardingRequired bool   `json:"onBoardingRequired"`
	Token              string `json:"token, omitempty"`
}

type TrustProvider struct {
	onboarding Onboarding
	rules      []Rule
	router     *mux.Router
	saveFunc   SaveToken
}

type SaveToken func(account interface{}, token string) error

func (t *TrustProvider) register(w http.ResponseWriter, r *http.Request) {
	var body interface{}
	err := utils.ReadBody(&body, r)
	if err != nil {
		log.Println(err.Error())
		utils.SetErrorStatus(err, http.StatusBadRequest, w)
		return
	}

	var ve []string

	strs := make(map[string]string, 0)
	nums := make(map[string]float64, 0)
	bools := make(map[string]bool, 0)

	for _, p := range t.onboarding.Parameters {
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
	account, err := t.onboarding.OnboardingFunc(strs, nums, bools)
	if err == nil {
		token := uuid.Must(uuid.NewV4()).String()

		if t.saveFunc == nil {
			err = defaultSaveToken(account, token)
		} else {
			err = t.saveFunc(account, token)
		}

		if err != nil {
			res := onboardingResponse{Status: false, OnBoardingRequired: true}
			utils.WriteJSON(res, http.StatusInternalServerError, w)
		} else {
			res := onboardingResponse{Status: true, OnBoardingRequired: false, Token: token}
			utils.WriteJSON(res, http.StatusCreated, w)
		}
	} else {
		res := onboardingResponse{Status: false, OnBoardingRequired: true}
		utils.WriteJSON(res, http.StatusOK, w)
	}

}

func New(onboarding Onboarding, rules []Rule, saveFunc SaveToken) (TrustProvider, error) {
	t := TrustProvider{onboarding: onboarding, rules: rules, saveFunc: saveFunc}
	t.router = mux.NewRouter()

	t.router.HandleFunc("/api/register", t.register).Methods("POST")

	http.Handle("/", handlers.LoggingHandler(os.Stdout, t.router))

	//TODO: Get port from configuration
	go http.ListenAndServe(":3000", nil)

	return t, nil
}

func defaultSaveToken(account interface{}, token string) error {
	return utils.Save(account, token)
}
