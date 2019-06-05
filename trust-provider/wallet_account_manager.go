package trustprovider

import (
	"encoding/json"
	"log"
)

type WalletAccountManager struct {
	TrustProvider TrustProvider
}

func (wam *WalletAccountManager) Update(account interface{}, token string) error {
	b, err := json.Marshal(account)
	if err != nil {
		log.Printf("Error marshalling account object: %s", err.Error())
		return err
	}

	err = wam.TrustProvider.Wallet.Accounts().Create(token, string(b), nil)
	if err != nil {
		log.Printf("Error inserting account object: %s", err.Error())
		log.Printf("Attempting to update account...")
		err = wam.TrustProvider.Wallet.Accounts().Update(token, string(b))
		if err != nil {
			log.Printf("Error updating account object: %s", err.Error())
			return err
		}
	}
	return nil
}

func (wam *WalletAccountManager) Read(token string) (interface{}, error) {
	s, err := wam.TrustProvider.Wallet.Accounts().Read(token)
	if err != nil {
		log.Printf("Error reading account object: %s", err.Error())
		return nil, err
	}

	var account map[string]interface{}
	err = json.Unmarshal([]byte(s), &account)
	if err != nil {
		log.Printf("Error unmarshalling account object: %s", err.Error())
	}
	return account, err
}
