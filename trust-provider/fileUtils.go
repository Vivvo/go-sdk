package trustprovider

import (
	"log"
	"os"
	"path/filepath"
	"encoding/json"
)

func createDevDBIfNotExists() error {
	path, err := filepath.Abs(".")
	if err != nil {
		log.Println(err)
	}

	path = path + "/db.json"

	// Check if file exists
	_, err = os.Stat(path)

	// create file if not exists
	if os.IsNotExist(err) {
		var file, err = os.Create(path)
		if err != nil {
			log.Println(err)
			return err
		}
		defer file.Close()

		_, err = file.WriteString("[\r\n]")
		if err != nil {
			log.Fatalf("failed writing to file: %s", err)
		}
	}

	return err
}

func appendFile(account interface{}, token string) error {

	path, err := filepath.Abs("./db.json")
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Fatalf("failed opening file: %s", err)
		return err
	}

	defer file.Close()

	var record = devDBRecord{
		Account: account,
		Token:   token,
	}

	r, err := json.Marshal(record)

	_, err = file.WriteString(string(r) + ",\r\n]")
	if err != nil {
		log.Fatalf("failed writing to file: %s", err)
	}

	return err

}

type devDBRecord struct {
	Account interface{} `json:"account"`
	Token   string      `json:"token"`
}
