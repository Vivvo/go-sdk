package utils

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
)

type ErrorDto struct {
	StatusCode int    `json:"statusCode"`
	Message    string `json:"message"`
}

func SetErrorStatus(e error, s int, w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	b := ErrorDto{
		StatusCode: s,
		Message:    e.Error(),
	}

	WriteJSON(b, s, w)
}

func WriteJSON(v interface{}, s int, w http.ResponseWriter) {
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

func ReadBody(v interface{}, r *http.Request) error {
	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return err
	}

	err = json.Unmarshal(b, &v)
	return err
}
