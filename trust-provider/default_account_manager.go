package trustprovider

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
)

// DefaultAccount is the default implementation of the Account interface that the TrustProvider will
// use to save tokens associated with accounts and retrieve accounts by those tokens. This implementation
// is NOT suitable for production use.
type DefaultAccount struct{}

// Update implementation stores accounts and tokens in a CSV file.
func (d *DefaultAccount) Update(account interface{}, token string) error {

	err := createDevDB()
	if err != nil {
		log.Printf("Error creating file: %s", err)
		return err
	}

	path, err := filepath.Abs(DefaultCsvFilePath)
	file, err := os.OpenFile(path, os.O_RDWR|os.O_APPEND, 0644)
	if err != nil {
		log.Printf("Error opening file: %s", err)
		return err
	}

	defer file.Close()

	var records []DefaultDBRecord

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

	record := DefaultDBRecord{
		Account: account,
		Token:   token,
	}

	existingRecord := false
	for i, dbRecord := range records {
		if dbRecord.Token == record.Token {
			records[i] = record
			existingRecord = true
		}
	}

	if !existingRecord {
		records = append(records, record)
	}

	r, err := json.Marshal(records)
	_, err = file.Write(r)
	if err != nil {
		log.Fatalf("Error writing to file: %s", err)
	}

	log.Println("WARNING: Note you are using the default internal database. This is for debugging only, please don't use this in production.")

	return err
}

// Read implementation reads an account by the given token from a CSV file. The account object will be retrieved
// as a map[string]interface{} since we know the type of the struct you've stored here. You can convert it back
// to the appropriate struct using something like http://github.com/mitchellh/mapstructure
// (examples: https://godoc.org/github.com/mitchellh/mapstructure#Decode)
func (d *DefaultAccount) Read(token string) (interface{}, error) {

	path, err := filepath.Abs(DefaultCsvFilePath)
	file, err := os.OpenFile(path, os.O_RDWR|os.O_APPEND, 0644)
	if err != nil {
		return nil, errors.New("error opening file")
	}

	defer file.Close()

	fileContents, _ := ioutil.ReadAll(file)

	var records []DefaultDBRecord

	json.Unmarshal(fileContents, &records)

	for _, record := range records {
		if record.Token == token {
			return record.Account, nil
		}
	}

	return nil, errors.New("not found")
}
