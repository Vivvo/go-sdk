package doubleratchet

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"github.com/Vivvo/go-sdk/did"
	"github.com/Vivvo/go-sdk/models"
	"github.com/Vivvo/go-sdk/utils"
	"github.com/Vivvo/go-wallet"
	"github.com/google/uuid"
	"log"
	"os"
	"strings"
	"testing"
)

type DoubleRatchetMockResolver struct {
	ddocs map[string]*did.Document
}

func NewDoubleRatchetMockResolver() *DoubleRatchetMockResolver {
	m := DoubleRatchetMockResolver{}
	m.ddocs = make(map[string]*did.Document, 0)
	return &m
}

func (m *DoubleRatchetMockResolver) Resolve(did string) (*did.Document, error) {
	return m.ddocs[did], nil
}
func (m *DoubleRatchetMockResolver) Register(ddoc *did.Document, other ...string) error {
	m.ddocs[ddoc.Id] = ddoc
	return nil
}

var resolver did.ResolverInterface
var aliceWallet *wallet.Wallet
var bobWallet *wallet.Wallet
var bobPublicDid string
var alicePublicDid string

func TestSuite(t *testing.T) {

	tests := []struct {
		name string
		fn   func(t *testing.T)
	}{
		{"testEncryptMessageWithNewPartner", testEncryptMessageWithNewPartner},
		{"testEncryptMessageWithExistingPartner", testEncryptMessageWithExistingPartner},
		{"testEncryptMessageWithExistingPartnerLoop", testEncryptMessageWithExistingPartnerLoop},
	}

	for _, tt := range tests {
		err := setup()
		if err != nil {
			t.Fatalf(err.Error())
		}

		t.Run(tt.name, tt.fn)

		teardown()
	}

}

func testEncryptMessageWithNewPartner(t *testing.T) {

	bobMessaging := Encryption{bobWallet, resolver}
	payload, err := bobMessaging.Encrypt(alicePublicDid, "Hi, Alice!")
	if err != nil {
		t.Error(err.Error())
	}

	log.Println(payload)

	aliceMessaging := Encryption{aliceWallet, resolver}
	var msg string
	err = aliceMessaging.Decrypt(payload, &msg)
	if err != nil {
		t.Error(err.Error())
	}

	if strings.Compare(msg, "Hi, Alice!") != 0 {
		t.Errorf("Expected: %s, Actual: %s", "Hi, Alice!", msg)
	}
}

func testEncryptMessageWithExistingPartner(t *testing.T) {
	testEncryptMessageWithNewPartner(t) // run new partner to cover initdoubleratchet, now they are partners

	bobMessaging := Encryption{bobWallet, resolver}
	payload, err := bobMessaging.Encrypt(alicePublicDid, "Hi, Alice!")
	if err != nil {
		t.Error(err.Error())
	}

	aliceMessaging := Encryption{aliceWallet, resolver}
	var msg string
	err = aliceMessaging.Decrypt(payload, &msg)
	if err != nil {
		t.Error(err.Error())
	}

	if strings.Compare(msg, "Hi, Alice!") != 0 {
		t.Errorf("Expected: %s, Actual: %s", "Hi, Alice!", msg)
	}
}

func testEncryptMessageWithExistingPartnerLoop(t *testing.T) {
	testEncryptMessageWithNewPartner(t) // run new partner to cover initdoubleratchet, now they are partners

	for i := 0; i < 10; i++ {
		t.Run(fmt.Sprintf("testEncryptMessageWithExistingPartner %d", i), testEncryptMessageWithExistingPartner)
	}
}

func setup() error {
	var err error
	os.Setenv("DEBUG", "true")

	resolver = NewDoubleRatchetMockResolver()

	aliceKey := make([]byte, 32)
	rand.Read(aliceKey)
	aliceWallet, err = wallet.Create(aliceKey, "alice.Wallet")
	if err != nil {
		return err
	}

	g := did.GenerateDidDocument{resolver}
	alicePublicDid = utils.ClientIdToDid(uuid.New())
	_, err = g.Generate(alicePublicDid, aliceWallet, true)
	if err != nil {
		return err
	}
	aliceProfile := models.UserProfile{Id: alicePublicDid, PublicDid: alicePublicDid}
	aj, _ := json.Marshal(aliceProfile)
	aliceWallet.UserProfile().Create(alicePublicDid, string(aj), nil)

	bobKey := make([]byte, 32)
	rand.Read(bobKey)
	bobWallet, err = wallet.Create(bobKey, "bob.Wallet")
	if err != nil {
		return err
	}

	bobPublicDid = utils.ClientIdToDid(uuid.New())
	_, err = g.Generate(bobPublicDid, bobWallet, true)
	if err != nil {
		return err
	}

	bobProfile := models.UserProfile{Id: bobPublicDid, PublicDid: bobPublicDid}
	bj, _ := json.Marshal(bobProfile)
	bobWallet.UserProfile().Create(bobPublicDid, string(bj), nil)

	return err
}

func teardown() {
	os.Remove("alice.Wallet")
	os.Remove("bob.Wallet")
}
