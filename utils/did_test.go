package utils

import (
	"fmt"
	"github.com/btcsuite/btcutil/base58"
	"github.com/google/uuid"
	"testing"
)

func TestDidToClientId(t *testing.T) {
	clientId := uuid.New()
	bytes, _ := clientId.MarshalBinary()
	b := base58.Encode(bytes)
	did := fmt.Sprintf("did:vvo:%s", b)

	res, err := DidToClientId(did)

	if err != nil {
		t.Fatalf("Threw an unexpected error: %s", err.Error())
	}

	if res != clientId {
		t.Fatalf("Expected: %s, Actual: %s", clientId, res)
	}

}

func TestClientIdToDid(t *testing.T) {
	clientId, _ := uuid.Parse("0ebb71f7-146b-47b4-a6ed-2ca2eab29b38")

	did := ClientIdToDid(clientId)

	res, err := DidToClientId(did)
	if err != nil {
		t.Fatalf("Unexpected Error: %s", err.Error())
	}

	if res != clientId {
		t.Fatalf("Expected: %s, Actual: %s", clientId, res)
	}
}

func TestStripKeysFromDid(t *testing.T) {
	testArray := []string{"did:vvo:5oZzq6u4ZVNxp8YA3YBkgq"}

	for _, testDid := range testArray {
		res, err := stripKeysFromDid(testDid)
		if err != nil {
			t.Fatalf("Unexpected Error: %s", err.Error())
		}
		println(res)
	}
}
