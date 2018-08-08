package trustprovider

import (
	"testing"
	"net/http"
	"net/http/httptest"
	"encoding/json"
	"io/ioutil"
	"github.com/pkg/errors"
	"github.com/Vivvo/vivvo-sdk/utils"
)

type MockOnboardingParams struct {
	Validation   string `json:"validation"`
	Verification string `json:"verification"`
	LastName     string `json:"lastName"`
}

type MockOnboardingParamsOptional struct {
	FirstName  string `json:"firstName"`
	MiddleName string `json:"middleName"`
}

type Account struct {
	AccountId int
}

func TestOnboarding(t *testing.T) {
	var onboardingFuncCalled = false
	var saveFuncCalled = false

	tests := []struct {
		name               string
		onboardingFunc     func(params interface{}, paramsOptional interface{}) (interface{}, error)
		saveFuncCalled     bool
		statusCode         int
		onboardingStatus   bool
		onboardingRequired bool
		token              bool
	}{
		{"Test Successful Onboarding",
			func(params interface{}, paramsOptional interface{}) (interface{}, error) {
				onboardingFuncCalled = true
				return Account{AccountId: 1}, nil
			},
			true,
			http.StatusCreated,
			true,
			false,
			true,
		},
		{"Test Failed Onboarding",
			func(params interface{}, paramsOptional interface{}) (interface{}, error) {
				onboardingFuncCalled = true
				return nil, errors.New("Error!!")
			},
			false,
			http.StatusOK,
			false,
			true,
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			onboardingFuncCalled = false
			saveFuncCalled = false
			http.DefaultServeMux = new(http.ServeMux)

			onboarding := Onboarding{
				OnboardingParams:         MockOnboardingParams{},
				OnboardingParamsOptional: MockOnboardingParamsOptional{},
				OnboardingFunc:           tt.onboardingFunc,
			}

			saveFunc := func(account interface{}, token string) error {
				saveFuncCalled = true

				if a, ok := account.(Account); ok == true {
					if a.AccountId != 1 {
						t.Errorf("Expected: %d, Actual: %d", 1, a.AccountId)
					}
				} else {
					t.Errorf("Expected an Account object")
				}
				if token == "" {
					t.Errorf("Expected to receive a token")
				}

				return nil
			}

			tp, _ := New(onboarding, nil, saveFunc)

			executeRequest := func(req *http.Request) *httptest.ResponseRecorder {
				rr := httptest.NewRecorder()
				tp.router.ServeHTTP(rr, req)

				return rr
			}

			req, _ := http.NewRequest("POST", "/api/register", nil)
			res := executeRequest(req)
			if res.Code != tt.statusCode {
				t.Errorf("Expected: %d, Actual: %d", tt.statusCode, res.Code)
			}

			b, err := ioutil.ReadAll(res.Body)
			if err != nil {
				t.Errorf("Error reading response body: %s", err.Error())
			}

			var response onboardingResponse
			err = json.Unmarshal(b, &response)
			if err != nil {
				t.Errorf("Error unmarshalling response body: %s", err.Error())
			}

			if response.Status != tt.onboardingStatus {
				t.Errorf("Expected: %v, Actual: %v", tt.onboardingStatus, response.Status)
			}

			if response.OnBoardingRequired != tt.onboardingRequired {
				t.Errorf("Expected: %v, Actual: %v", tt.onboardingRequired, response.OnBoardingRequired)
			}

			if tt.token && response.Token == "" {
				t.Errorf("Expected to receive a token")
			} else if !tt.token && response.Token != "" {
				t.Errorf("Expected NOT to receive a token")
			}

			if !onboardingFuncCalled {
				t.Errorf("Expected OnboardingFunc to have been called")
			}

			if saveFuncCalled != tt.saveFuncCalled {
				t.Errorf("Expected: %v, Actual: %v", tt.saveFuncCalled, saveFuncCalled)
			}
		})
	}

}

func TestOnboardingFuncNotConfigured(t *testing.T) {
	http.DefaultServeMux = new(http.ServeMux)

	onboarding := Onboarding{
		OnboardingParams:         MockOnboardingParams{},
		OnboardingParamsOptional: MockOnboardingParamsOptional{},
		OnboardingFunc:           nil,
	}

	tp, _ := New(onboarding, nil, nil)

	executeRequest := func(req *http.Request) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		tp.router.ServeHTTP(rr, req)

		return rr
	}

	req, _ := http.NewRequest("POST", "/api/register", nil)
	res := executeRequest(req)
	if res.Code != http.StatusInternalServerError {
		t.Errorf("Expected: %d, Actual: %d", http.StatusInternalServerError, res.Code)
	}

	b, err := ioutil.ReadAll(res.Body)
	if err != nil {
		t.Errorf("Error reading response body: %s", err.Error())
	}

	var response utils.ErrorDto
	err = json.Unmarshal(b, &response)
	if err != nil {
		t.Errorf("Error unmarshalling response body: %s", err.Error())
	}

	if response.StatusCode != http.StatusInternalServerError {
		t.Errorf("Expected: %v, Actual: %v", http.StatusInternalServerError, response.StatusCode)
	}

	if response.Message != "TrustProvider.onboarding.OnboardingFunc not implemented!" {
		t.Errorf("Expected: %v, Actual: %v", "TrustProvider.onboarding.OnboardingFunc not implemented!", response.Message)
	}
}

func TestSaveFuncNotConfigured(t *testing.T) {
	http.DefaultServeMux = new(http.ServeMux)

	onboarding := Onboarding{
		OnboardingParams:         MockOnboardingParams{},
		OnboardingParamsOptional: MockOnboardingParamsOptional{},
		OnboardingFunc: func(params interface{}, paramsOptional interface{}) (interface{}, error) {
			return Account{AccountId: 1}, nil
		},
	}

	tp, _ := New(onboarding, nil, nil)

	executeRequest := func(req *http.Request) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		tp.router.ServeHTTP(rr, req)
		return rr
	}

	req, _ := http.NewRequest("POST", "/api/register", nil)
	res := executeRequest(req)
	if res.Code != http.StatusInternalServerError {
		t.Errorf("Expected: %d, Actual: %d", http.StatusInternalServerError, res.Code)
	}

	b, err := ioutil.ReadAll(res.Body)
	if err != nil {
		t.Errorf("Error reading response body: %s", err.Error())
	}

	var response utils.ErrorDto
	err = json.Unmarshal(b, &response)
	if err != nil {
		t.Errorf("Error unmarshalling response body: %s", err.Error())
	}

	if response.StatusCode != http.StatusInternalServerError {
		t.Errorf("Expected: %v, Actual: %v", http.StatusInternalServerError, response.StatusCode)
	}

	if response.Message != "TrustProvider.onboarding.OnboardingFunc not implemented!" {
		t.Errorf("Expected: %v, Actual: %v", "TrustProvider.onboarding.OnboardingFunc not implemented!", response.Message)
	}
}
