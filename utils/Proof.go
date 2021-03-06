package utils

type Proof struct {
	Typ            string `json:"type,omitempty"`
	Created        string `json:"created,omitempty"`
	Creator        string `json:"creator,omitempty"`
	Nonce          string `json:"nonce,omitempty"`
	SignatureValue string `json:"signatureValue,omitempty"`
	ProofPurpose   string `json:"proofPurpose,omitempty"`
	Capability     string `json:"capability,omitempty"`
}
