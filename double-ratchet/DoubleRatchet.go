package doubleratchet

import (
	"encoding/json"
	"github.com/Vivvo/go-sdk/did"
	"github.com/Vivvo/go-sdk/models"
	"github.com/Vivvo/go-sdk/utils"
	"github.com/Vivvo/go-wallet"
	"github.com/google/uuid"
	"log"
)

type Encryption struct {
	wallet   *wallet.Wallet
	resolver did.ResolverInterface
}

/*
	recipientDid - public or pairwise did: we will do the math
*/
func (e *Encryption) Encrypt(recipientDid string, message interface{}) (*wallet.RatchetPayload, error) {
	m := e.wallet.Messaging()

	tags := struct{
		PublicDid string
	}{
		PublicDid: recipientDid,
	}
	tj, err := json.Marshal(tags)

	existing, err := e.wallet.Contacts().Read(recipientDid)
	if err != nil {
		// no existing contact, still need to check if recipientDid a publicDid
		eBytes, err := e.wallet.Contacts().FindByTags(tj)
		if err == nil {
			existing = string(eBytes)
		}
	}

	var pairwise string
	if existing == "" {
		pairwise = utils.ClientIdToDid(uuid.New())
		_, err = did.Generate(pairwise, e.resolver, e.wallet, true)

		ddoc, err := e.resolver.Resolve(recipientDid)
		if err != nil {
			return nil, err
		}

		pubkey, err := ddoc.GetKeyByType(wallet.TypeEd25519KeyExchange2018)
		if err != nil {
			return nil, err
		}
		err = m.InitDoubleRatchet(pairwise, pubkey.PublicKeyBase58)
		if err != nil {
			return nil, err
		}

		contact := models.Contact{Id: pairwise, PairwiseDid: pairwise, PublicDid: recipientDid}
		cj, err := json.Marshal(contact)
		err = e.wallet.Contacts().Create(pairwise, string(cj), tj)
		if err != nil {
			return nil, err
		}
	} else {
		var c models.Contact
		err := json.Unmarshal([]byte(existing), &c)
		if err != nil {
			return nil, err
		}

		pairwise = c.PairwiseDid
	}

	j, err := json.Marshal(message)
	if err != nil {
		return nil, err
	}
	return m.RatchetEncrypt(pairwise, string(j))
}

// TODO: Existing adapters have pubDid in config, need to handle adding to userProfile
func (e *Encryption) Decrypt(encryptedMessage *wallet.RatchetPayload, obj interface{}) error {
	m := e.wallet.Messaging()

	pairwise := utils.ClientIdToDid(uuid.New())
	_, err := did.Generate(pairwise, e.resolver, e.wallet, false)

	log.Println(encryptedMessage.Sender)
	ddoc, err := e.resolver.Resolve(encryptedMessage.Sender)
	if err != nil {
		return err
	}

	pubkey, err := ddoc.GetKeyByType(wallet.TypeEd25519KeyExchange2018)
	if err != nil {
		return err
	}

	profiles, _ := e.wallet.UserProfile().ReadAll()
	var ups []models.UserProfile
	_ = json.Unmarshal(profiles, &ups)
	err = m.InitDoubleRatchetWithWellKnownPublicKey(ups[0].PublicDid, pairwise, pubkey.PublicKeyBase58)
	if err != nil {
		return err
	}

	msg, err := m.RatchetDecrypt(pairwise, encryptedMessage)
	if err != nil {
		return err
	}

	err = json.Unmarshal([]byte(msg), obj)

	return nil
}

func IsDoubleRatchetEncrypted(msg interface{}) bool {
	if payload, ok := msg.(map[string]interface{}); ok {
		return payload["sender"] != nil && payload["dhs"] != nil && payload["pn"] != nil && payload["ns"] != nil && payload["payload"] != nil && payload["initializationKey"] != nil
	} else {
		return false
	}
}
