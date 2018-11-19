package did

import (
	"crypto/rsa"
	"fmt"
	"github.com/Vivvo/go-sdk/utils"
	"log"
	"time"
)

type Capability struct {
	Id               string              `json:"id"`
	Name             string              `json:"name"`
	Description      string              `json:"description"`
	ParentCapability *Capability         `json:"parentCapability,omitempty"`
	Invoker          string              `json:"invoker"`
	Caveat           []Caveat            `json:"caveat,omitempty"`
	Creator			 string				 `json:"creator"`
	Capabilities     map[string][]string `json:"capabilities"` // key is url to entity, values are action urls
}

type ObjectCapability struct {
	Capability *Capability  `json:"capability"`
	Proof      *utils.Proof `json:"proof"`
}

type Caveat struct {

}

func (c *Capability) Sign(privateKey *rsa.PrivateKey) (*ObjectCapability, error) {
	proof := utils.Proof{
		ProofPurpose: "capabilityDelegation",
		Capability: c.Id,
		Created: time.Now().Format("2006-01-02T15:04:05-0700"),
		Creator: fmt.Sprintf("%s#keys-1", c.Creator),
	}

	o, p, err := utils.Sign(c, &proof, privateKey)
	if err != nil {
		log.Panic(err.Error())
		return nil, err
	}

	return &ObjectCapability{
		Capability: o.(*Capability),
		Proof: p,
	}, nil
}