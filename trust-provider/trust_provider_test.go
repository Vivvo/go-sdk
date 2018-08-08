package trustprovider

import (
	"testing"
	"net/http"
	"net/http/httptest"
	"encoding/json"
	"io/ioutil"
	"github.com/pkg/errors"
	"github.com/Vivvo/go-sdk/utils"
	"strings"
)

type Account struct {
	AccountId int
}

func TestOnboarding(t *testing.T) {
	var onboardingFuncCalled = false
	var saveFuncCalled = false

	tests := []struct {
		name               string
		onboardingFunc     func(s map[string]string, n map[string]float64, b map[string]bool) (interface{}, error)
		saveFuncCalled     bool
		statusCode         int
		onboardingStatus   bool
		onboardingRequired bool
		token              bool
	}{
		{"Test Successful Onboarding",
			func(s map[string]string, n map[string]float64, b map[string]bool) (interface{}, error) {
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
			func(s map[string]string, n map[string]float64, b map[string]bool) (interface{}, error) {
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
				Parameters:     []Parameter{},
				OnboardingFunc: tt.onboardingFunc,
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

			req, _ := http.NewRequest("POST", "/api/register", strings.NewReader(""))
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
		Parameters:     []Parameter{},
		OnboardingFunc: nil,
	}

	tp, _ := New(onboarding, nil, nil)

	executeRequest := func(req *http.Request) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		tp.router.ServeHTTP(rr, req)

		return rr
	}

	req, _ := http.NewRequest("POST", "/api/register", strings.NewReader(""))
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
		Parameters: []Parameter{},
		OnboardingFunc: func(s map[string]string, n map[string]float64, b map[string]bool) (interface{}, error) {
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

	if res.Code != http.StatusCreated {
		t.Errorf("Expected: %d, Actual: %d", http.StatusCreated, res.Code)

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

	}
}

func TestParameters(t *testing.T) {

	tests := []struct {
		name       string
		parameters []Parameter
		body       string
		statusCode int
	}{
		{"Missing required", []Parameter{{name: "customerNumber", typ: ParameterTypeFloat64, required: true}}, "", http.StatusBadRequest},
		{"Missing non-required", []Parameter{{name: "customerNumber", typ: ParameterTypeFloat64, required: false}}, "", http.StatusCreated},
		{"Should be num", []Parameter{{name: "customerNumber", typ: ParameterTypeFloat64, required: false}}, "{\"customerNumber\": \"blahblah\"}", http.StatusBadRequest},
		{"Should be num", []Parameter{{name: "customerNumber", typ: ParameterTypeFloat64, required: false}}, "{\"customerNumber\": 1234565}", http.StatusCreated},
		{"Should be string", []Parameter{{name: "customerNumber", typ: ParameterTypeString, required: false}}, "{\"customerNumber\": 12345}", http.StatusBadRequest},
		{"Should be string", []Parameter{{name: "customerNumber", typ: ParameterTypeString, required: false}}, "{\"customerNumber\":  \"blah\"}", http.StatusCreated},
		{"Should be bool", []Parameter{{name: "customerNumber", typ: ParameterTypeBool, required: false}}, "{\"customerNumber\": \"blahblah\"}", http.StatusBadRequest},
		{"Should be bool", []Parameter{{name: "customerNumber", typ: ParameterTypeBool, required: false}}, "{\"customerNumber\": true}", http.StatusCreated},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			http.DefaultServeMux = new(http.ServeMux)

			onboarding := Onboarding{
				Parameters: tt.parameters,
				OnboardingFunc: func(s map[string]string, n map[string]float64, b map[string]bool) (interface{}, error) {
					return Account{AccountId: 1}, nil
				},
			}

			tp, _ := New(onboarding, nil, func(account interface{}, token string) error { return nil })

			executeRequest := func(req *http.Request) *httptest.ResponseRecorder {
				rr := httptest.NewRecorder()
				tp.router.ServeHTTP(rr, req)
				return rr
			}

			req, _ := http.NewRequest("POST", "/api/register", strings.NewReader(tt.body))
			res := executeRequest(req)
			if res.Code != tt.statusCode {
				t.Errorf("Expected: %d, Actual: %d", http.StatusBadRequest, tt.statusCode)
			}
		})
	}
}

func TestOnboardingCalledWithParams(t *testing.T) {
	http.DefaultServeMux = new(http.ServeMux)

	onboarding := Onboarding{
		Parameters: []Parameter{
			{name: "customerNumber", typ: ParameterTypeFloat64, required: true},
			{name: "validationNumber", typ: ParameterTypeFloat64, required: true},
			{name: "firstName", typ: ParameterTypeString, required: true},
			{name: "middleName", typ: ParameterTypeString, required: false},
			{name: "lastName", typ: ParameterTypeString, required: true},
			{name: "biometrics", typ: ParameterTypeBool, required: true},
		},
		OnboardingFunc: func(s map[string]string, n map[string]float64, b map[string]bool) (interface{}, error) {

			if s["firstName"] != "Johnny" {
				t.Errorf("Expected: %s, Actual: %s", "Johnny", s["firstName"])
			}
			if s["middleName"] != "" {
				t.Errorf("Expected: %s, Actual: %s", "", s["middleName"])
			}
			if s["lastName"] != "Utah" {
				t.Errorf("Expected: %s, Actual: %s", "Utah", s["lastName"])
			}
			if n["customerNumber"] != 123456789 {
				t.Errorf("Expected: %v, Actual: %v", 123456789, n["customerNumber"])
			}
			if n["validationNumber"] != 987654321 {
				t.Errorf("Expected: %v, Actual: %v", 987654321, n["validationNumber"])
			}
			if b["biometrics"] != true {
				t.Errorf("Expected: %v, Actual: %v", true, b["biometrics"])
			}

			return Account{AccountId: 1}, nil
		},
	}

	tp, _ := New(onboarding, nil, func(account interface{}, token string) error { return nil })

	executeRequest := func(req *http.Request) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		tp.router.ServeHTTP(rr, req)
		return rr
	}

	body := "{\"customerNumber\": 123456789, \"validationNumber\": 987654321, \"firstName\": \"Johnny\", \"lastName\": \"Utah\", \"biometrics\": true}"

	req, _ := http.NewRequest("POST", "/api/register", strings.NewReader(body))
	executeRequest(req)
}
