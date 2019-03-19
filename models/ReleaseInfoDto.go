package models

type ReleaseInfoDto struct {
	VersionNumber string `json:"VERSION_NUMBER"`
	AppName       string `json:"APP_NAME"`
	GitShaSort    string `json:"GIT_SHA_SHORT"`
	TenantName    string `json:"TENANT_NAME"`
	StaredOn      string  `json:"STARTED_ON"`
}
