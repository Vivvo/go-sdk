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
	"github.com/satori/go.uuid"
	"fmt"
	"github.com/apex/log"
)

type MockAccountObj struct {
	AccountId int
	Age       float64
}

type MockAccount struct {
	update func(account interface{}, token uuid.UUID) error
	read   func(token uuid.UUID) (interface{}, error)
}

func (d *MockAccount) SetUpdateFunc(update func(account interface{}, token uuid.UUID) error) {
	d.update = update
}

func (d *MockAccount) Update(account interface{}, token uuid.UUID) error {
	return d.update(account, token)
}

func (d *MockAccount) SetReadFunc(read func(token uuid.UUID) (interface{}, error)) {
	d.read = read
}

func (d *MockAccount) Read(token uuid.UUID) (interface{}, error) {
	return d.read(token)
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
				return MockAccountObj{AccountId: 1}, nil
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

			mockAccount := MockAccount{}
			mockAccount.SetUpdateFunc(func(account interface{}, token uuid.UUID) error {
				saveFuncCalled = true

				if a, ok := account.(MockAccountObj); ok == true {
					if a.AccountId != 1 {
						t.Errorf("Expected: %d, Actual: %d", 1, a.AccountId)
					}
				} else {
					t.Errorf("Expected an Account object")
				}
				if token.String() == "" {
					t.Errorf("Expected to receive a token")
				}

				return nil
			})

			tp := New(onboarding, nil, &mockAccount)

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

			var response trustProviderResponse
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
				log.Error(response.Token)
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

	tp := New(onboarding, nil, nil)

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

func _TestSaveFuncNotConfigured(t *testing.T) {
	http.DefaultServeMux = new(http.ServeMux)

	onboarding := Onboarding{
		Parameters: []Parameter{},
		OnboardingFunc: func(s map[string]string, n map[string]float64, b map[string]bool) (interface{}, error) {
			return MockAccountObj{AccountId: 1}, nil
		},
	}

	tp := New(onboarding, nil, nil)

	executeRequest := func(req *http.Request) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		tp.router.ServeHTTP(rr, req)

		return rr
	}

	req, _ := http.NewRequest("POST", "/api/register", strings.NewReader(""))
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

func TestSaveFuncConfigured(t *testing.T) {
	http.DefaultServeMux = new(http.ServeMux)

	onboarding := Onboarding{
		Parameters: []Parameter{},
		OnboardingFunc: func(s map[string]string, n map[string]float64, b map[string]bool) (interface{}, error) {
			return MockAccountObj{AccountId: 100}, nil
		},
	}

	var saveFuncCalled = false

	mockAccount := MockAccount{}
	mockAccount.SetUpdateFunc(func(account interface{}, token uuid.UUID) error {
		saveFuncCalled = true
		return nil
	})

	tp := New(onboarding, nil, &mockAccount)

	executeRequest := func(req *http.Request) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		tp.router.ServeHTTP(rr, req)

		return rr
	}

	req, _ := http.NewRequest("POST", "/api/register", strings.NewReader(""))
	_ = executeRequest(req)

	if !saveFuncCalled {
		t.Errorf("Expected OnboardingFunc to have been called")
	}
}

func TestParameters(t *testing.T) {

	tests := []struct {
		name       string
		parameters []Parameter
		body       string
		statusCode int
	}{
		{"Missing Required", []Parameter{{Name: "customerNumber", Type: ParameterTypeFloat64, Required: true}}, "", http.StatusBadRequest},
		{"Missing non-Required", []Parameter{{Name: "customerNumber", Type: ParameterTypeFloat64, Required: false}}, "", http.StatusCreated},
		{"Should be num", []Parameter{{Name: "customerNumber", Type: ParameterTypeFloat64, Required: false}}, "{\"customerNumber\": \"blahblah\"}", http.StatusBadRequest},
		{"Should be num", []Parameter{{Name: "customerNumber", Type: ParameterTypeFloat64, Required: false}}, "{\"customerNumber\": 1234565}", http.StatusCreated},
		{"Should be string", []Parameter{{Name: "customerNumber", Type: ParameterTypeString, Required: false}}, "{\"customerNumber\": 12345}", http.StatusBadRequest},
		{"Should be string", []Parameter{{Name: "customerNumber", Type: ParameterTypeString, Required: false}}, "{\"customerNumber\":  \"blah\"}", http.StatusCreated},
		{"Should be bool", []Parameter{{Name: "customerNumber", Type: ParameterTypeBool, Required: false}}, "{\"customerNumber\": \"blahblah\"}", http.StatusBadRequest},
		{"Should be bool", []Parameter{{Name: "customerNumber", Type: ParameterTypeBool, Required: false}}, "{\"customerNumber\": true}", http.StatusCreated},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			http.DefaultServeMux = new(http.ServeMux)

			onboarding := Onboarding{
				Parameters: tt.parameters,
				OnboardingFunc: func(s map[string]string, n map[string]float64, b map[string]bool) (interface{}, error) {
					return MockAccountObj{AccountId: 1}, nil
				},
			}

			mockAccount := MockAccount{}
			mockAccount.SetUpdateFunc(func(account interface{}, token uuid.UUID) error { return nil })

			tp := New(onboarding, nil, &mockAccount)

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
			{Name: "customerNumber", Type: ParameterTypeFloat64, Required: true},
			{Name: "validationNumber", Type: ParameterTypeFloat64, Required: true},
			{Name: "firstName", Type: ParameterTypeString, Required: true},
			{Name: "middleName", Type: ParameterTypeString, Required: false},
			{Name: "lastName", Type: ParameterTypeString, Required: true},
			{Name: "biometrics", Type: ParameterTypeBool, Required: true},
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

			return MockAccountObj{AccountId: 1}, nil
		},
	}

	mockAccount := MockAccount{}
	mockAccount.SetUpdateFunc(func(account interface{}, token uuid.UUID) error { return nil })

	tp := New(onboarding, nil, &mockAccount)

	executeRequest := func(req *http.Request) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		tp.router.ServeHTTP(rr, req)
		return rr
	}

	body := "{\"customerNumber\": 123456789, \"validationNumber\": 987654321, \"firstName\": \"Johnny\", \"lastName\": \"Utah\", \"biometrics\": true}"

	req, _ := http.NewRequest("POST", "/api/register", strings.NewReader(body))
	executeRequest(req)
}

func TestRules(t *testing.T) {

	validToken := uuid.Must(uuid.NewV4())

	tests := []struct {
		Name       string
		Rules      []Rule
		Body       string
		StatusCode int
		Status     bool
		Token      uuid.UUID
		Message    string
	}{
		{
			Name:       "alwayspasses",
			Rules:      []Rule{{Name: "alwayspasses", Parameters: []Parameter{}, RuleFunc: func(s map[string]string, n map[string]float64, b map[string]bool, acct interface{}) (bool, error) { return true, nil }}},
			Body:       "",
			StatusCode: http.StatusOK,
			Status:     true,
			Token:      validToken,
			Message:    "",
		},
		{
			Name:       "alwaysfails",
			Rules:      []Rule{{Name: "alwaysfails", Parameters: []Parameter{}, RuleFunc: func(s map[string]string, n map[string]float64, b map[string]bool, acct interface{}) (bool, error) { return false, nil }}},
			Body:       "",
			StatusCode: http.StatusOK,
			Status:     false,
			Token:      validToken,
			Message:    "",
		},
		{
			Name:       "throwsanerror",
			Rules:      []Rule{{Name: "throwsanerror", Parameters: []Parameter{}, RuleFunc: func(s map[string]string, n map[string]float64, b map[string]bool, acct interface{}) (bool, error) { return false, errors.New("WHAT HAVE YOU DONE?") }}},
			Body:       "",
			StatusCode: http.StatusServiceUnavailable,
			Status:     false,
			Token:      validToken,
			Message:    "WHAT HAVE YOU DONE?",
		},
		{
			Name: "passeswithcorrectparam",
			Rules: []Rule{{Name: "passeswithcorrectparam", Parameters: []Parameter{{Name: "age", Required: true, Type: ParameterTypeFloat64}},
				RuleFunc: func(s map[string]string, n map[string]float64, b map[string]bool, acct interface{}) (bool, error) {
					return n["age"] < 24, nil
				}}},
			Body:       "{\"age\": 19}",
			StatusCode: http.StatusOK,
			Status:     true,
			Token:      validToken,
			Message:    "",
		},
		{
			Name: "failswithincorrectparam",
			Rules: []Rule{{Name: "failswithincorrectparam", Parameters: []Parameter{{Name: "age", Required: true, Type: ParameterTypeFloat64}},
				RuleFunc: func(s map[string]string, n map[string]float64, b map[string]bool, acct interface{}) (bool, error) {
					return n["age"] > 24, nil
				}}},
			Body:       "{\"age\": 19}",
			StatusCode: http.StatusOK,
			Status:     false,
			Token:      validToken,
			Message:    "",
		},
		{
			Name: "needsaccountobject",
			Rules: []Rule{{Name: "needsaccountobject", Parameters: []Parameter{{Name: "age", Required: true, Type: ParameterTypeFloat64}},
				RuleFunc: func(s map[string]string, n map[string]float64, b map[string]bool, acct interface{}) (bool, error) {
					if a, ok := acct.(MockAccountObj); ok {
						return n["age"] <= a.Age, nil

					} else {
						return false, errors.New("invalid token")
					}
				}}},
			Body:       "{\"age\": 19}",
			StatusCode: http.StatusOK,
			Status:     true,
			Token:      validToken,
			Message:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			http.DefaultServeMux = new(http.ServeMux)

			onboarding := Onboarding{
				Parameters: []Parameter{},
				OnboardingFunc: func(s map[string]string, n map[string]float64, b map[string]bool) (interface{}, error) {
					return MockAccountObj{AccountId: 1}, nil
				},
			}

			mockAccount := MockAccount{}
			mockAccount.SetUpdateFunc(func(account interface{}, token uuid.UUID) error { return nil })
			mockAccount.SetReadFunc(func(token uuid.UUID) (interface{}, error) {
				return MockAccountObj{AccountId: 1234567890, Age: 30}, nil
			})

			tp := New(onboarding, tt.Rules, &mockAccount)

			executeRequest := func(req *http.Request) *httptest.ResponseRecorder {
				rr := httptest.NewRecorder()
				tp.router.ServeHTTP(rr, req)
				return rr
			}

			req, _ := http.NewRequest("POST", fmt.Sprintf("/api/%s/%s", tt.Name, validToken), strings.NewReader(tt.Body))
			res := executeRequest(req)

			check(t, tt.StatusCode, res.Code)

			b, err := ioutil.ReadAll(res.Body)
			if err != nil {
				t.Errorf("Error reading response body: %s", err.Error())
			}

			var response trustProviderResponse
			err = json.Unmarshal(b, &response)
			if err != nil {
				t.Errorf("Error unmarshalling response body: %s", err.Error())
			}

			check(t, tt.Status, response.Status)
			check(t, tt.Message, response.Message)
		})
	}
}

func check(t *testing.T, expected interface{}, actual interface{}) {
	if expected != actual {
		t.Errorf("Expected: %v, Actual: %v", expected, actual)
	}
}
