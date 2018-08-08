package trustprovider

type Onboarding struct {
	OnboardingParams         interface{}
	OnboardingParamsOptional interface{}
	OnboardingFunc           func(params interface{}, paramsOptional interface{}) (interface{}, error)
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