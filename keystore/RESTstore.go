package keystore

import (
	"bytes"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/adrianosela/AuthService/keys"
	"github.com/adrianosela/Keystore/keystoreapi"
	jwt "github.com/dgrijalva/jwt-go"
	jose "github.com/square/go-jose"
)

var (
	//RESTkeystoreURL is our keystore service URL
	RESTkeystoreURL = "http://keystore.adrianosela.com"
)

//RESTKeystore is a client of my own REST keystore found in github.com/adrianosela/Keystore
type RESTKeystore struct {
	sync.RWMutex //inherit read/write lock behavior
	HTTPClient   http.Client
	CachedKeys   map[string]*keystoreAPI.KeyMetadata `json:"keys"`
	SigningKey   *rsa.PrivateKey
	SigningKeyID string
}

//NewRESTKeystore returns the addr of a new keystore object
func NewRESTKeystore() (*RESTKeystore, error) {
	//return a keystore struct
	ks := &RESTKeystore{
		HTTPClient: http.Client{
			Timeout: time.Duration(time.Second * 15), //a sane timeout
		},
		CachedKeys: map[string]*keystoreAPI.KeyMetadata{},
	}
	err := ks.refreshCache()
	if err != nil {
		return nil, fmt.Errorf("Could not refresh the cached keys. %s", err)
	}
	return ks, nil
}

//SavePubKey will cache a given key locally as well as publish it to the RESTKeystore
func (ks *RESTKeystore) SetKeyPair(keyID string, keyPair *rsa.PrivateKey, lifespan time.Duration) error {
	if keyPair == nil {
		return fmt.Errorf("[ERROR] Could not set key: Key was nil, key_id = %s", keyID)
	}
	//grab and defer release of write lock
	ks.Lock()
	defer ks.Unlock()
	ks.SigningKey = keyPair
	ks.SigningKeyID = keyID
	//convert the key to PEM
	pemKey, err := keys.RSAPublicKeyToPEM(&keyPair.PublicKey)
	if err != nil {
		return fmt.Errorf("Could not convert key: %s, to pem. %s", keyID, err)
	}
	//put it in the KeyMetadata struct
	keyMeta := keystoreAPI.KeyMetadata{
		ID:           keyID,
		InvalidAfter: time.Now().Add(lifespan),
		KeyPem:       pemKey,
	}
	//marshall onto JSON bytes
	jsonKeyMeta, err := json.Marshal(keyMeta)
	if err != nil {
		return fmt.Errorf("Could not marshall key: %s. %s", keyID, err)
	}
	//create the http request
	req, err := http.NewRequest("POST", fmt.Sprintf("%s/key", RESTkeystoreURL), bytes.NewBuffer(jsonKeyMeta))
	if err != nil {
		return fmt.Errorf("Could not create POST request to RESTKeystore API for key: %s. %s", keyID, err)
	}
	//send it over the Keystore's HTTPClient
	resp, err := ks.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("Could not send POST request to RESTKeystore API for key: %s. %s", keyID, err)
	}
	//if the POST succeeded, then save to the local cache
	if resp.StatusCode == http.StatusOK {
		ks.CachedKeys[keyID] = &keyMeta
		return nil
	}
	return fmt.Errorf("POST to RESTKeystore was not successful. Status Code = %d", resp.StatusCode)
}

func (ks *RESTKeystore) GetPubKeys() (map[string]*rsa.PublicKey, error) {
	err := ks.refreshCache()
	if err != nil {
		return nil, fmt.Errorf("Could not refresh the cached keys. %s", err)
	}
	//respecting the return type in my keystore interface
	keysMap := make(map[string]*rsa.PublicKey)
	//Grab the read lock
	ks.RLock()
	defer ks.RUnlock()
	//convert every PEM key in the cache to RSA and stick it in the map
	for id, key := range ks.CachedKeys {
		rsakey, err := jwt.ParseRSAPublicKeyFromPEM(key.KeyPem)
		if err != nil {
			return nil, err
		}
		keysMap[id] = rsakey
	}
	return keysMap, nil
}

func (ks *RESTKeystore) refreshCache() error {
	ks.Lock()
	defer ks.Unlock()
	//get all the IDs of all the keys on the store server
	RESTkeystoreIDs, err := ks.getKeyIDs()
	if err != nil {
		return fmt.Errorf("Could not get the list of IDs in store. %s", err)
	}
	//for every key that we know is in store, we check if its cached
	for _, id := range RESTkeystoreIDs {
		//if the key is not found in the cache
		if _, ok := ks.CachedKeys[id]; !ok {
			log.Printf("[INFO] Pulling Key From REST Keystore: %s\n", id)
			keyMeta, err := ks.getKeyMetadata(id)
			if err != nil {
				log.Printf("[ERROR] Could not pull Key From REST Keystore: %s\n. %s", id, err)
				continue //graceful failure means we just forget about that key for now
			}
			ks.CachedKeys[id] = keyMeta
			log.Printf("[INFO] Pulled Key From REST Keystore: %s\n", id)
		}
	}

	//clean up expired Keys
	ks.retireExpired()
	return nil
}

func (ks *RESTKeystore) getKeyMetadata(keyID string) (*keystoreAPI.KeyMetadata, error) {
	//create the http request to get the Key
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/key/%s", RESTkeystoreURL, keyID), nil)
	if err != nil {
		return nil, fmt.Errorf("Could not create GET request to RESTKeystore API. %s", err)
	}

	retries := 0
	err = errors.New("")
	//we will attempt to get the key three times
	for err != nil && retries < 3 {
		resp, err := ks.HTTPClient.Do(req)
		retries++
		if err != nil {
			continue
		}
		//read the response bytes if success
		jsonBytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			continue
		}
		var keyMeta keystoreAPI.KeyMetadata
		err = json.Unmarshal(jsonBytes, &keyMeta)
		if err != nil {
			continue
		}
		return &keyMeta, nil
	}
	return nil, fmt.Errorf("3 Failed attempts at getting key %s from RESTKeystore. %s", keyID, err)
}

func (ks *RESTKeystore) getKeyIDs() ([]string, error) {
	//create request
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/keys", RESTkeystoreURL), nil)
	if err != nil {
		return nil, errors.New("Could not create GET request for keys")
	}
	//send the request
	resp, err := ks.HTTPClient.Do(req)
	if err != nil {
		return nil, errors.New("Could not send GET request for keys")
	}
	defer resp.Body.Close()
	//read the bytes off the body
	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.New("Could not read response for keys")
	}
	//unmarshall onto a type dictated by the keystore API
	var list keystoreAPI.GetKeyListOutput
	err = json.Unmarshal(respBytes, &list)
	if err != nil {
		return nil, err //errors.New("Could not unmashall keystore list response")
	}
	//success
	return list.KeyIDList, nil
}

func (ks *RESTKeystore) retireExpired() {
	//TODO
}

//GetSigningKey returns the signing key along its ID and nil error if success
func (ks *RESTKeystore) GetSigningKey() (*rsa.PrivateKey, string, error) {
	ks.RLock()
	defer ks.RUnlock()
	if ks.SigningKey == nil || ks.SigningKeyID == "" {
		return nil, "", errors.New("No Signing Key Set")
	}
	return ks.SigningKey, ks.SigningKeyID, nil
}

func (ks *RESTKeystore) SharePubKeyHandler(w http.ResponseWriter, r *http.Request) {
	err := ks.refreshCache()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, fmt.Sprintf("[ERROR] : %v", err))
		return
	}

	keyset := jose.JsonWebKeySet{
		Keys: []jose.JsonWebKey{},
	}

	for kid, key := range ks.CachedKeys {
		keyset.Keys = append(keyset.Keys, jose.JsonWebKey{
			Key:       key.KeyPem,
			Algorithm: "RS512",
			Use:       "sig",
			KeyID:     kid,
		})
	}

	keysBytes, err := json.Marshal(keyset)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, fmt.Sprintf("[ERROR] : %v", err))
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, string(keysBytes))
	return
}
