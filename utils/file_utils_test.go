package utils

import (
	"testing"
	"os"
)

type Account struct {
	AccountId int
}

//func TestRead(t *testing.T) {
//
//	tests := []struct {
//		name           string
//		token          string
//		expectedRecord interface{}
//	}{
//		{"No record found", "invalidToken", nil},
//	}
//
//	for _, tt := range tests {
//		t.Run(tt.name, func(t *testing.T) {
//			record, err := Read(tt.token)
//
//			if err != nil {
//				t.Errorf("Expected: %s, Actual: %s", "Johnny", s["firstName"])
//			}
//			log.Println(record)
//			log.Println(err)
//		})
//	}
//}

func cleanupTestFile() {
	// delete file
	os.Remove("./db.json")
}

func TestSave(t *testing.T) {

	genericAccount := Account{
		AccountId: 1234567890,
	}

	validToken := "validToken"

	tests := []struct {
		name            string
		account         interface{}
		token           string
		expectedFailure bool
		expectedError   string
	}{
		{"Test Successful Save", genericAccount, validToken, false, ""},
		{"Test Failed Save - missing account", nil, validToken, true, "you must provide an account object"},
		{"Test Failed Save - missing token", genericAccount, "", true, "you must provide a token"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cleanupTestFile()
			err := Save(tt.account, tt.token)

			if tt.expectedFailure && err == nil {
				t.Errorf("Expected an error and didn't recieve one")
			}

			if err != nil && tt.expectedError != err.Error() {
				t.Errorf("Expected: %s, Actual %s", tt.expectedError, err.Error())
			}

			//if !tt.expectedFailure {
			//	record, _ := Read(tt.token)
			//	if record != nil {
			//		t.Errorf("No record found")
			//	}
			//}
		})
	}
}

func TestNoDB(t *testing.T) {
	cleanupTestFile()
	_, err := Read("TOKEN!")

	if err == nil {
		t.Errorf("Expected an error opening the file!")
	} else if err.Error() != "error opening file" {
		t.Errorf("Expected: %s, got: %s", "error opening file", err)
	}

}
