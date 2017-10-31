package keystore

import (
	"crypto/rsa"
	"net/http"
	"time"
)

//Keystore represents an interface capable of storing and fetching public Keys
type Keystore interface {
	SavePubKey(string, *rsa.PublicKey, time.Duration) error
	GetPubKeys() (map[string]*rsa.PublicKey, error)
	SharePubKeyHandler(http.ResponseWriter, *http.Request)
}
