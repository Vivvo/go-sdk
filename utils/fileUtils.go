package utils

import (
	"log"
	"os"
	"path/filepath"
	"encoding/json"
	"io/ioutil"
	"errors"
)

type devDBRecord struct {
	Account interface{} `json:"account"`
	Token   string      `json:"token"`
}

const dbFilePath = "./db.json"

func createDevDB() error {

	_, err := os.Stat(dbFilePath)

	if os.IsNotExist(err) {
		var file, err = os.Create(dbFilePath)
		if err != nil {
			return err
		}
		defer file.Close()
	}

	return nil
}

func Save(account interface{}, token string) error {

	err := createDevDB()
	if err != nil {
		log.Printf("Error creating file: %s", err)
		return err
	}

	path, err := filepath.Abs(dbFilePath)
	file, err := os.OpenFile(path, os.O_RDWR|os.O_APPEND, 0644)
	if err != nil {
		log.Printf("Error opening file: %s", err)
		return err
	}

	defer file.Close()

	var records []devDBRecord

	if account == nil {
		return errors.New("you must provide an account object")
	}

	if token == "" {
		return errors.New("you must provide a token")
	}

	fileContents, _ := ioutil.ReadAll(file)
	// empty file before we write the whole array again
	file.Truncate(0)

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

	log.Println("WARNING: Note you are using the default internal database.  This is for debugging only, please don't use this in production.")

	return err

}

func Read(token string) (*devDBRecord, error) {

	path, err := filepath.Abs(dbFilePath)
	file, err := os.OpenFile(path, os.O_RDWR|os.O_APPEND, 0644)
	if err != nil {
		return nil, errors.New("error opening file")
	}

	defer file.Close()

	fileContents, _ := ioutil.ReadAll(file)

	var records []devDBRecord

	json.Unmarshal(fileContents, &records)

	for _, record := range records {
		if record.Token == token {
			return &record, nil
		}
	}

	return nil, err
}
