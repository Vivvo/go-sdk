package utils

import (
	"net/http"
	"os"

	"github.com/Vivvo/go-sdk/models"
)

// GetReleaseInfo pulls the release info from environment variables writes it to json
func GetReleaseInfo(w http.ResponseWriter, r *http.Request) {
	logger := Logger(r.Context())
	defer logger.Sync()
	var releaseInformation = models.ReleaseInfoDto{
		VersionNumber: os.Getenv("VERSION_NUMBER"),
		AppName:       os.Getenv("APP_NAME"),
		GitShaSort:    os.Getenv("GIT_SHA_SHORT"),
		TenantName:    os.Getenv("TENANT_NAME"),
		StartedOn:     os.Getenv("STARTED_ON"),
	}
	WriteJSON(releaseInformation, http.StatusCreated, w)
}
