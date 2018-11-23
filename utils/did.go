package utils

import (
	"github.com/btcsuite/btcutil/base58"
	"github.com/google/uuid"
	"strings"
)

func DidToClientId(did string) (uuid.UUID, error) {
	base58Encoded := strings.Replace(did, "did:vvo:", "", 1)
	clientIdBytes := base58.Decode(base58Encoded)
	return uuid.FromBytes(clientIdBytes)
}

func ClientIdToDid(clientId uuid.UUID) string {
	u, _ := clientId.MarshalBinary()
	return "did:vvo:" + base58.Encode(u)

}
