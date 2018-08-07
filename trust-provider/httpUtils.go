package trust_provider

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"github.com/go-resty/resty"
)

func setErrorStatus(e error, s int, w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	b := errorResponse{
		StatusCode: s,
		Message:    e.Error(),
	}

	writeJSON(b, s, w)
}

func writeJSON(v interface{}, s int, w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")

	b, err := json.Marshal(v)
	if err != nil {
		log.Println(err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
		return
	}
	w.WriteHeader(s)
	w.Write(b)
}

func readBody(v interface{}, r *http.Request) error {
	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return err
	}

	err = json.Unmarshal(b, &v)
	return err
}

func readResponseBody(v interface{}, r *resty.Response) error {
	err := json.Unmarshal(r.Body(), &v)
	return err
}
