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

	ratchetPartner, err := e.findRatchetPartnerByPublicOrPairwiseDid(recipientDid)
	if err != nil {
		return nil, err
	}

	var pairwise string
	if ratchetPartner == nil {
		log.Println("ENCRYPT WITH NEW PARTNER, RECIPIENT: " + recipientDid)
		var pubkey *did.PublicKey
		pairwise, pubkey, err = e.createNewPairwise(recipientDid)
		if err != nil {
			return nil, err
		}

		err = m.InitDoubleRatchet(pairwise, pubkey.PublicKeyBase58)
		if err != nil {
			return nil, err
		}
	} else {
		log.Println("ENCRYPT WITH EXISTING PARTNER, PAIRWISE: " + ratchetPartner.PairwiseDid)
		pairwise = ratchetPartner.PairwiseDid
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

	ratchetPartner, err := e.findRatchetPartnerByPublicOrPairwiseDid(encryptedMessage.Sender)
	if err != nil {
		return err
	}

	var pairwise string
	if ratchetPartner == nil {
		log.Println("DECRYPT WITH NEW PARTNER, SENDER: " + encryptedMessage.Sender)
		var pubkey *did.PublicKey
		pairwise, pubkey, err = e.createNewPairwise(encryptedMessage.Sender)
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
	} else {
		log.Println("DECRYPT WITH EXISTING PARTNER, SENDER: " + ratchetPartner.PairwiseDid)
		pairwise = ratchetPartner.PairwiseDid
	}

	msg, err := m.RatchetDecrypt(pairwise, encryptedMessage)
	if err != nil {
		return err
	}

	err = json.Unmarshal([]byte(msg), obj)

	return nil
}

func (e *Encryption) createNewPairwise(partnerPublicDid string) (string, *did.PublicKey, error) {
	pairwise := utils.ClientIdToDid(uuid.New())
	_, err := did.Generate(pairwise, e.resolver, e.wallet, true)

	ddoc, err := e.resolver.Resolve(partnerPublicDid)
	if err != nil {
		return "", nil, err
	}

	pubkey, err := ddoc.GetKeyByType(wallet.TypeEd25519KeyExchange2018)
	if err != nil {
		return "", nil, err
	}

	partner := models.RatchetPartner{Id: pairwise, PairwiseDid: pairwise, PublicDid: partnerPublicDid}
	cj, err := json.Marshal(partner)
	err = e.wallet.RatchetPartners().Create(pairwise, string(cj), e.rpTags(partnerPublicDid))
	if err != nil {
		return "", nil, err
	}

	return pairwise, pubkey, err
}

// TODO: This should be done better smh..
// And can userProfile replace ratchetPartner model in wallet?
func (e *Encryption) findRatchetPartnerByPublicOrPairwiseDid(recipientDid string) (*models.RatchetPartner, error) {
	var rp *models.RatchetPartner
	existing, err := e.wallet.RatchetPartners().Read(recipientDid)
	if err != nil {
		// no existing contact, still need to check if recipientDid a publicDid
		eBytes, err := e.wallet.RatchetPartners().FindByTags(e.rpTags(recipientDid))
		if err != nil {
			return nil, err
		}
		if len(eBytes) > 2 {
			var rpList []*models.RatchetPartner
			err = json.Unmarshal(eBytes, &rpList)
			if err == nil && len(rpList) > 0 {
				return rpList[0], nil
			} else {
				return nil, err
			}
		} else {
			return nil, err
		}
	}

	_ = json.Unmarshal([]byte(existing), &rp)
	return rp, nil
}

func (e *Encryption) rpTags(recipientDid string) []byte {
	tags := make(map[string]string, 0)
	tags["publicDid"] = recipientDid
	tj, _ := json.Marshal(tags)
	return tj
}