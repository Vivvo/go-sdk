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


//func stripKeysFromDid(pubKeyDid string) (string, error) {
//	//check if the did has a #keys in it
//	if (strings.Contains(pubKeyDid, "#keys")) || (!strings.Contains(pubKeyDid, "did:vvo:")) {
//		return "", errors.New(fmt.Sprintf("Cannot strip key due to incorrect string format: %s", pubKeyDid))
//	}
//
//	start := strings.Index(pubKeyDid, "did:vvo:")
//	end := strings.Index(pubKeyDid[start:], "#")
//	did := pubKeyDid[start:end]
//	fmt.Println(did)
//
//	return did, nil
//}