package trustprovider

import (
	"log"
	"os"
	"path/filepath"
	"encoding/json"
	"io/ioutil"
)

type devDBRecord struct {
	Account interface{} `json:"account"`
	Token   string      `json:"token"`
}

const DbFilePath = "./db.json"

func createDevDB() error {

	_, err := os.Stat(DbFilePath)

	if os.IsNotExist(err) {
		var file, err = os.Create(DbFilePath)
		if err != nil {
			return err
		}
		defer file.Close()
	}

	return nil
}

func appendFile(account interface{}, token string) error {

	err := createDevDB()
	if err != nil {
		log.Printf("Error creating file: %s", err)
		return err
	}

	path, err := filepath.Abs(DbFilePath)
	file, err := os.OpenFile(path, os.O_RDWR|os.O_APPEND, 0644)
	if err != nil {
		log.Printf("Error opening file: %s", err)
		return err
	}

	defer file.Close()

	fileContents, _ := ioutil.ReadAll(file)
	// empty file before we write the whole array again
	file.Truncate(0)

	var records []devDBRecord

	json.Unmarshal(fileContents, &records)

	record := devDBRecord{
		Account: account,
		Token:   token,
	}

	records = append(records, record)
	r, err := json.Marshal(records)
	_, err = file.Write(r)
	if err != nil {
		log.Fatalf("Error writing to file: %s", err)
	}

	return err

}
