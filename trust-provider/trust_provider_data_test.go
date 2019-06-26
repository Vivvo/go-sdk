package trustprovider

import (
	"fmt"
	"github.com/mitchellh/mapstructure"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type MockAcct struct {
	Name string `json:"name"`
}

type MockAccountManager struct {
}

func (m *MockAccountManager) Update(account interface{}, token string) error {
	return nil
}

func (m *MockAccountManager) Read(token string) (interface{}, error) {
	return MockAcct{"Bohdi"}, nil
}

func TestDataEndpoint(t *testing.T) {
	tests := []struct {
		Name     string
		Endpoint string
		Status   int
		Body     string
	}{
		{"Test Data Endpoint", "TestDataEndpoint", http.StatusOK, "{\"message\":\"Hello, Bohdi!\"}"},
		{"Test Data Endpoint With Slashes", "test/data/endpoint", http.StatusOK, "{\"message\":\"Hello, Bohdi!\"}"},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			data := []Data{
				{Name: tt.Endpoint, DataFunc: func(acct interface{}) (interface{}, error) {
					var account MockAcct

					mapstructure.Decode(acct, &account)

					return struct {
						Message string `json:"message"`
					}{Message: fmt.Sprintf("Hello, %s!", account.Name)}, nil
				}},
			}

			tp := New(Onboarding{}, nil, nil, data, GetStatus{}, &MockAccountManager{}, &MockResolver{})

			s := httptest.NewServer(tp.Router)
			defer s.Close()

			resp, err := s.Client().Get(fmt.Sprintf("%s/api/%s/1b6bcde9-b315-4278-a8ff-010a7fff987d", s.URL, tt.Endpoint))
			if err != nil {
				t.Fatalf(err.Error())
			}
			if resp.StatusCode != tt.Status {
				t.Fatalf("Expected: %d, Actual: %d", tt.Status, resp.StatusCode)
			}

			b, _ := ioutil.ReadAll(resp.Body)
			if strings.Compare(string(b), tt.Body) != 0 {
				t.Fatalf("Expected: %s, Actual: %s", tt.Body, string(b))
			}
			s.Close()
		})
	}

}
