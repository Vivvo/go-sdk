package trust_provider

import (
	"net/http"
	"github.com/gorilla/mux"
	"github.com/gorilla/handlers"
	"os"
	"github.com/satori/go.uuid"
	"github.com/pkg/errors"
	"log"
)

type TrustProvider struct {
	onboarding Onboarding
	rules      []Rule
	router     *mux.Router
	saveToken  SaveToken
}

type SaveToken func(account interface{}, token string) error

func (t *TrustProvider) register(w http.ResponseWriter, r *http.Request) {
	// Parse parameters
	// Do validation on params

	if t.onboarding.OnboardingFunc == nil {
		err := errors.New("TrustProvider.onboarding.OnboardingFunc not implemented!")
		log.Println(err.Error())
		setErrorStatus(err, http.StatusInternalServerError, w)
		return
	}
	account, err := t.onboarding.OnboardingFunc(nil, nil)
	if err == nil {
		token := uuid.Must(uuid.NewV4()).String()

		if t.saveToken == nil {
			err = defaultSaveToken(account, token)
		} else {
			err = t.saveToken(account, token)
		}

		if err != nil {
			res := onboardingResponse{Status: false, OnBoardingRequired: true}
			writeJSON(res, http.StatusInternalServerError, w)
		} else {
			res := onboardingResponse{Status: true, OnBoardingRequired: false, Token: token}
			writeJSON(res, http.StatusCreated, w)
		}
	} else {
		res := onboardingResponse{Status: false, OnBoardingRequired: true}
		writeJSON(res, http.StatusOK, w)
	}

}

func NewTrustProvider(onboarding Onboarding, rules []Rule, saveToken SaveToken) (TrustProvider, error) {
	t := TrustProvider{onboarding: onboarding, rules: rules, saveToken: saveToken}
	t.router = mux.NewRouter()

	t.router.HandleFunc("/api/register", t.register).Methods("POST")

	http.Handle("/", handlers.LoggingHandler(os.Stdout, t.router))

	//TODO: Get port from configuration
	go http.ListenAndServe(":3000", nil)

	return t, nil
}

func defaultSaveToken(account interface{}, token string) error {

	err := createDevDBIfNotExists()
	if err != nil {
		return err
	}

	err = appendFile(account, token)
	if err != nil {
		return err
	}

	return err
}
