package did

import (
	"github.com/Vivvo/go-sdk/utils"
	"github.com/pkg/errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestResolver_Register(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		var body = struct {
			Parent      string    `json:"parent,omitempty"`
			PairwiseDid string    `json:"pairwiseDid,omitempty"`
			DidDocument *Document `json:"didDocument"`
		}{}

		err := utils.ReadBody(&body, r)
		if err != nil {
			utils.SetErrorStatus(err, http.StatusBadRequest, rw)
			return
		}
		rw.WriteHeader(http.StatusCreated)
	}))

	r := Resolver{DidBaseUrl: s.URL}

	err := r.Register(&Document{})
	if err != nil {
		t.Fatalf(err.Error())
	}
}

func TestResolver_Register_WithParent(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		var body = struct {
			Parent      string    `json:"parent,omitempty"`
			PairwiseDid string    `json:"pairwiseDid,omitempty"`
			DidDocument *Document `json:"didDocument"`
		}{}

		err := utils.ReadBody(&body, r)
		if err != nil {
			utils.SetErrorStatus(err, http.StatusBadRequest, rw)
			return
		}

		if body.Parent != "imaparent" {
			utils.SetErrorStatus(errors.New("bad parent"), http.StatusBadRequest, rw)
			return
		}
		rw.WriteHeader(http.StatusCreated)
	}))

	r := Resolver{DidBaseUrl: s.URL}

	err := r.Register(&Document{}, "imaparent")
	if err != nil {
		t.Fatalf(err.Error())
	}
}

func TestResolver_Register_WithParentAndPairwise(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		var body = struct {
			Parent      string    `json:"parent,omitempty"`
			PairwiseDid string    `json:"pairwiseDid,omitempty"`
			DidDocument *Document `json:"didDocument"`
		}{}

		err := utils.ReadBody(&body, r)
		if err != nil {
			utils.SetErrorStatus(err, http.StatusBadRequest, rw)
			return
		}

		if body.Parent != "imaparent" {
			utils.SetErrorStatus(errors.New("bad parent"), http.StatusBadRequest, rw)
			return
		}

		if body.PairwiseDid != "totallypairwise" {
			utils.SetErrorStatus(errors.New("bad pairwise"), http.StatusBadRequest, rw)
			return
		}
		rw.WriteHeader(http.StatusCreated)

	}))

	r := Resolver{DidBaseUrl: s.URL}

	err := r.Register(&Document{}, "imaparent", "totallypairwise")
	if err != nil {
		t.Fatalf(err.Error())
	}
}
