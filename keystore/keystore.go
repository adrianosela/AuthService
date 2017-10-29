package keystore

import (
	"crypto/rsa"
	"time"
)

//Keystore represents an interface capable of storing and fetching public Keys
type Keystore interface {
	SavePubKey(string, *rsa.PublicKey, time.Duration) error
	GetPubKeys() (map[string]*rsa.PublicKey, error)
}

//KeyMetadata represents the format in which we will cache and store keys
type KeyMetadata struct {
	KeyPem       []byte    `json:"key_pem"`
	ID           string    `json:"key_id"`
	InvalidAfter time.Time `json:"expires"`
}
