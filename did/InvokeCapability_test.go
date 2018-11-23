package did

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

const invocation = `{
  "id": "2a46807b-bc0d-4818-bbcd-11ba3e6ceb4f",
  "action": "manage",
  "proof": {
    "type": "RsaSignature2018",
    "created": "2018-11-23T20:03:16+0000",
    "creator": "did:vvo:AVgg8xz2s3222UMfJtjCFR#keys-1",
    "signatureValue": "FI68Kt4_dQ5mUzHp87aSON2vaKEpS-GwaQFaNOPblzU-68-UWwr9h4Msg47v4Yfd_eQaUgvKfH3Re1N3f65znVONc61vA_6CRmIoZ7Unc-l8fEeUdLHGFhd65UIY-1mSft-USWTKSmPZpeL4DHsxOdNLLu6_IluExT2XakIUTjgHkl1Ajdspl1dKqUdNUEXhlG6vcHgNx0LSeKV8DFMj3sgAWtEXDroWpwh1EYG9fGzKN81AhodLfNSiet_PTiYFGUGkNVPPSGgC8-FXowlaVD20Azb19piPHKcW7HV9sKogz2l1ud8viyUpD1Ri8JegxnptFs42tnX_oFHFHUH9Uw==",
    "proofPurpose": "capabilityDelegation",
    "objectCapability": {
      "capability": {
        "id": "69b73a8a-8efc-4f0b-bc00-e089eb292cb5",
        "name": "Manage kjhgfd",
        "description": "Manage Eeze domain",
        "invoker": "did:vvo:AVgg8xz2s3222UMfJtjCFR#keys-1",
        "creator": "did:vvo:5oZzq6u4ZVNxp8YA3YBkgq",
        "capabilities": {
          "https://c1dev.vivvo.com/eeze/domains/did:vvo:6jLNypk5da7r52fsihyUra/entities/self": [
            "manage"
          ]
        }
      },
      "proof": {
        "type": "RsaSignature2018",
        "created": "2018-11-23T20:03:16+0000",
        "creator": "did:vvo:5oZzq6u4ZVNxp8YA3YBkgq#keys-1",
        "signatureValue": "Ws9Mu4Cc1vCEwrfSxfyx0UngVWAs25BLcOS85g6xAwFFzsRddMNKECDjZSZ0V0zTP0fJ9t1f-Ru1kSZ3WbbaMynMddMG3lFzL517CYc9Vjf-JinismBSr2q93lTqklD6jJ6AbvbqH_I6VWlfLRoDf5sRUgKapmW6SGHmmg29_6R45uT4xdjfdFG7PCUx8VYJqeLnVeJoIdniv1P6ZrlwEgVve6S12t24sPAgUMnsdND6Zh3L5dkf9Dg4dQ8yjgTTQkO1Ri9-ruhnH1z9CFzBZgDzizXAX7i4XU6FWIByHRfcoRXB4p0QMTGtSSo0XtL77V8Vl9BICXKSKdI-RQoZ3DvV4cRQNItVX80bTpQg4ndVVs5Tc0LkhEK6J2cvBbVAQ2YPN3vnm3cw2lvrvQPPdklyrCdecJsJAEPvjsIoCBXYp821LK4Emxted0kX_7Fr_UGGlCWvMM_xOdCHbWQHwbdmtkMak_4ZXBN5c34l86JupsRg9iukLk1H6_fxl02LH7oaQUIBkWwzTysYf5Xxi-KPwJ6FJPvXs_w-p2COuNOz7mJm536rNdiy2jvn8Vbd1i1Tf31OophlpvYnig8cBYZBNwo-FX9YZrSCxytuS2RCKbUKGygxe4-S3MQyTLjFRnOGaJSxmgARsHOMqnj3cXqplzQq_9GQ6Ln3HsDqGvY=",
        "proofPurpose": "capabilityDelegation",
        "capability": "69b73a8a-8efc-4f0b-bc00-e089eb292cb5"
      }
    }
  }
}`

const didvvo5oZzq6u4ZVNxp8YA3YBkgqkeys1 = "\n-----BEGIN CERTIFICATE-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAy0/rLInvnlcuifTs2a6UX1NxVZeJpj8Jq1Cw61OftikLz7LTPKaNNcOhqXf0Kn3x4SSoO+XLQpCq1FwBE/4FbpdXcxpgPBnW1JxNl54NZzR9H0oyL52S/IyubJeb84i8wPXolQdS66vcbaZgXsKMMk36Y2I7e1KcuubGLGIjYcZSFSg/TQWLIoUvin1b+RyjsADpAOzfv+EbDTZvNNytKQK9CG59oKGxMoL7Uy7flazI4eTvdLCe5JVr9XOoBlQwUz8pRRKynaMMcDswhM1QzUloMLiRuaaOhHaNyjHTeqWrxMjH/mBqjS2vKTsjOVmwjm/kYUX5mzXB25HNrT1aw6Geu+uBEnjI5FHKeKGNJdpjJZTNS2O0LBc0HtZUidy1fLpOY2QULLUpbHOEpOzRVuX/nHX7GrBRwmhE9KVN3WM0z4KqfrhUj9x4MlJZIuxqGL99VBLL7WhOAPaasJ945h/TSgxT7/A4sLVzUSz1OUNYoLPK4eGtnYGUtQ7IkMWPCc1cd2glUsYTBGlMRNUHrmA/ApB0RjEUcK6pkRPfYO7pSaSI+lYBAPitjvsw5famrsbmfQmb7/zGhwhxlNLW1DHgKWiHOPV7JYR86iPVBl3uFcUIDVua8gsGodoQpbusNyAXOqxvIaQGtzwGVHfjdqaPdOOUDiGUF2/gxo69misCAwEAAQ==\n-----END CERTIFICATE-----"

const didvvoAVgg8xz2s3222UMfJtjCFRkeys1 = "-----BEGIN CERTIFICATE-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqYhMb3XqW909z1YXkG5mModEKcfKB+dE\ndWwTboo5SAoKwCFLTTujVGjxP04YJbexeYqYuqiVLAV0MHQK1xbFFLpmjyCgjd4Z9tR3YCdF8kkB\nFiUy9CD5xY0dUWSoekIyrhje2W6O6a+3UnlWKYa2B7MQiKvfjkAmX8zcj0/ZVvxZQDpYNp6/zgt7\n/zUUGuDYz2ykp7MMSDCpI7EReJ0Mycb9dppMDcd1jCUAGGcECnq8KsmculPt2aOQFPwq/0nc4gkO\nC/fJqe91qZZP4zZkpWKFGBgW/1CdCt7pByVii0TXB5fkK9WRkv1+SpvcWxmhjHh4gilm46tzsm/h\ne9sdCQIDAQAB\n\n-----END CERTIFICATE-----"

type MockOcapResolver struct {
}

func (m *MockOcapResolver) Resolve(id string) (*Document, error) {
	if strings.Compare(id, "did:vvo:5oZzq6u4ZVNxp8YA3YBkgq") == 0 {
		return &Document{PublicKey: []PublicKey{{Id: "did:vvo:5oZzq6u4ZVNxp8YA3YBkgq#keys-1", PublicKeyPem: didvvo5oZzq6u4ZVNxp8YA3YBkgqkeys1}},}, nil
	} else if strings.Compare(id, "did:vvo:AVgg8xz2s3222UMfJtjCFR") == 0 {
		return &Document{PublicKey: []PublicKey{{Id: "did:vvo:AVgg8xz2s3222UMfJtjCFR#keys-1", PublicKeyPem: didvvoAVgg8xz2s3222UMfJtjCFRkeys1}},}, nil
	}
	return nil, errors.New("not found")
}
func (m *MockOcapResolver) Register(*Document) error {
	return errors.New("not implemented")
}

func TestObjectCapability_Verify(t *testing.T) {
	invokeCapability := InvokeCapability{}
	json.Unmarshal([]byte(invocation), &invokeCapability)

	_, err := invokeCapability.VerifyInvocation(&MockOcapResolver{})

	if err != nil {
		t.Fatalf("Unexepected Error: %s", err.Error())
	}
}
