package utils

import (
	"github.com/hashicorp/consul/api"
	"math/rand"
	"strings"
	"testing"
	"time"
)

type MockConsulHealth struct {
	response []*api.ServiceEntry
}

func (m *MockConsulHealth) Service(service, tag string, passingOnly bool, q *api.QueryOptions) ([]*api.ServiceEntry, *api.QueryMeta, error) {
	return m.response, nil, nil
}

func TestServiceDiscovery(t *testing.T) {
	tests := []struct {
		service         string
		mockResponse    []*api.ServiceEntry
		expectedService string
	}{
		{"test-service", []*api.ServiceEntry{{Service: &api.AgentService{Address: "localhost", Port: 9105}}}, "localhost:9105"},
		{"test-service", []*api.ServiceEntry{}, "test-service"},
		{"test-service", []*api.ServiceEntry{{Service: &api.AgentService{Address: "taggedHost", Port: 9105, Tags: []string{"vivvo"}}}, {Service: &api.AgentService{Address: "localhost", Port: 9105}}}, "localhost:9105"},
		{"test-service", []*api.ServiceEntry{{Service: &api.AgentService{Address: "taggedHost", Port: 9105, Tags: []string{"vivvo"}}}}, "taggedHost:9105"},
	}

	service := ConsulService{}

	s := rand.NewSource(time.Now().Unix())
	service.rng = rand.New(s)

	for _, test := range tests {
		t.Run(test.service, func(t *testing.T) {
			service.health = &MockConsulHealth{response: test.mockResponse}

			address := service.GetService(test.service)

			if strings.Compare(address, test.expectedService) != 0 {
				t.Fatalf("Expected: %s, Actual: %s", test.expectedService, address)
			}
		})
	}
}
