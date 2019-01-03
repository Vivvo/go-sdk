package subscribe

import (
	"github.com/Vivvo/go-sdk/models"
	"github.com/Vivvo/go-sdk/utils"
	"github.com/gorilla/mux"
	"log"
	"net/http"
	"os"
)


type Address struct {
	address models.Address
}
type Name struct {
	name models.Name
}
type Email struct {
	email models.Email
}
type Phone struct {
	phone models.Phone
}

type Subscribe struct {
	address 	Address
	name 		Name
	email 		Email
	phone 		Phone
	router 		*mux.Router
	port 		string

}

func New() Subscribe {
	//t := Subscribe{address: address, name: name, email: email, phone: phone, router: mux.NewRouter()}
	t := Subscribe{router: mux.NewRouter()}

	t.router.HandleFunc("/api/subscribe/address", t.subscribeAddress).Methods("POST")
	t.router.HandleFunc("/api/subscribe/name",   t.subscribeName).Methods("POST")
	t.router.HandleFunc("/api/subscribe/email",   t.subscribeEmail).Methods("POST")
	t.router.HandleFunc("/api/subscribe/phone",   t.subscribePhone).Methods("POST")



	const TrustProviderPortKey = "TRUST_PROVIDER_PORT"
	t.port = os.Getenv(TrustProviderPortKey)
	if t.port == "" {
		t.port = "4000"
	}
	return t
}

func (t *Subscribe) ListenAndServe() error {
	log.Printf("Listening on port: %s", t.port)
	return http.ListenAndServe(":"+t.port, nil)
}

func (t *Subscribe) subscribeAddress(w http.ResponseWriter, r *http.Request) {
	logger := utils.Logger(r.Context())
	vars := mux.Vars(r)
	schemaType := vars["schema"]

	var body interface{}
	err := utils.ReadBody(&body, r)
	if err != nil {
		logger.Errorf("Problem unmarshalling schema request body", "error", err.Error())
		utils.SetErrorStatus(err, http.StatusBadRequest, w)
		return
	}
	utils.WriteJSON(schemaType, http.StatusOK, w)
}

func (t *Subscribe) subscribeName(w http.ResponseWriter, r *http.Request) {
	logger := utils.Logger(r.Context())
	vars := mux.Vars(r)
	schemaType := vars["schema"]

	var body interface{}
	err := utils.ReadBody(&body, r)
	if err != nil {
		logger.Errorf("Problem unmarshalling schema request body", "error", err.Error())
		utils.SetErrorStatus(err, http.StatusBadRequest, w)
		return
	}
	utils.WriteJSON(schemaType, http.StatusOK, w)
}

func (t *Subscribe) subscribeEmail(w http.ResponseWriter, r *http.Request) {
	logger := utils.Logger(r.Context())
	vars := mux.Vars(r)
	schemaType := vars["schema"]

	var body interface{}
	err := utils.ReadBody(&body, r)
	if err != nil {
		logger.Errorf("Problem unmarshalling schema request body", "error", err.Error())
		utils.SetErrorStatus(err, http.StatusBadRequest, w)
		return
	}
	utils.WriteJSON(schemaType, http.StatusOK, w)
}

func (t *Subscribe) subscribePhone(w http.ResponseWriter, r *http.Request) {
	logger := utils.Logger(r.Context())
	vars := mux.Vars(r)
	schemaType := vars["schema"]

	var body interface{}
	err := utils.ReadBody(&body, r)
	if err != nil {
		logger.Errorf("Problem unmarshalling schema request body", "error", err.Error())
		utils.SetErrorStatus(err, http.StatusBadRequest, w)
		return
	}
	utils.WriteJSON(schemaType, http.StatusOK, w)

}
