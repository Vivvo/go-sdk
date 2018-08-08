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

func createDevDB() error {
	path, err := filepath.Abs(".")
	if err != nil {
		log.Println(err)
		return err
	}

	path = path + "/db.json"

	_, err = os.Stat(path)

	if os.IsNotExist(err) {
		var file, err = os.Create(path)
		if err != nil {
			log.Println(err)
			return err
		}
		defer file.Close()
	}

	return nil
}

func appendFile(account interface{}, token string) error {

	err := createDevDB()
	if err != nil {
		log.Printf("failed opening file1: %s", err)
		return err
	}

	path, err := filepath.Abs("./db.json")
	file, err := os.OpenFile(path, os.O_APPEND|os.O_RDWR, 0644)
	if err != nil {
		log.Printf("failed opening file2: %s", err)
		return err
	}

	defer file.Close()

	fileContents, _ := ioutil.ReadAll(file)
	// empty file before we write the whole array again
	file.Truncate(0)

	var records []devDBRecord

	json.Unmarshal(fileContents, &records)

	var record = devDBRecord{
		Account: account,
		Token:   token,
	}

	records = append(records, record)
	r, err := json.Marshal(records)

	file.Write(nil)
	_, err = file.Write(r)
	if err != nil {
		log.Fatalf("failed writing to file: %s", err)
	}

	return err

}
