package utils

import (
	"github.com/Vivvo/go-sdk/models"
	"github.com/Vivvo/vivvo-idp/utils"
	"net/http"
	"os"
	"time"
)

func GetReleaseInfo(w http.ResponseWriter, r *http.Request) {
	logger := Logger(r.Context())
	defer logger.Sync()
	var releaseInformation = models.ReleaseInfoDto{
		VersionNumber: os.Getenv("VERSION_NUMBER"),
		AppName:       os.Getenv("APP_NAME"),
		GitShaSort:    os.Getenv("GIT_SHA_SHORT"),
		TenantName:    os.Getenv("TENANT_NAME"),
		StaredOn:      time.Now(),
	}
	utils.WriteJSON(releaseInformation, http.StatusCreated, w)
}
