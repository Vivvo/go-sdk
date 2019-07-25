package go_sdk_testing

type MockConsulService struct {
}

func (m *MockConsulService) GetService(service string, _tag ...string) string {
	return service
}
