package models

// ReleaseInfoDto holds our application release information
type ReleaseInfoDto struct {
	VersionNumber string `json:"version_number"`
	AppName       string `json:"app_name"`
	GitShaSort    string `json:"git_sha_short"`
	TenantName    string `json:"tenant_name"`
	StartedOn     string `json:"started_on"`
}
