package keystore

import (
	"bytes"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/adrianosela/AuthService/keys"
	jwt "github.com/dgrijalva/jwt-go"
)

var (
	RESTkeystoreURL = os.Getenv("KEYSTORE_URL")
)

//RESTKeystore is a client of my own REST keystore found in github.com/adrianosela/Keystore
type RESTKeystore struct {
	sync.RWMutex //inherit read/write lock behavior
	HTTPClient   http.Client
	CachedKeys   map[string]*KeyMetadata `json:"keys"`
}

func NewRESTKeystore(certFile, keyFile, CAFile string) *RESTKeystore {
	// Load client cert
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatal(err)
	}
	// Load CA cert
	CACert, err := ioutil.ReadFile(CAFile)
	if err != nil {
		log.Fatal(err)
	}
	CACertPool := x509.NewCertPool()
	CACertPool.AppendCertsFromPEM(CACert)
	// Setup HTTPS client
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      CACertPool,
	}
	tlsConfig.BuildNameToCertificate()
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	client := http.Client{
		Transport: transport,
		Timeout:   time.Duration(time.Second * 60),
	}
	//return a keystore struct with the tls client
	return &RESTKeystore{
		HTTPClient: client,
		CachedKeys: map[string]*KeyMetadata{},
	}
}

func (ks *RESTKeystore) SavePubKey(keyID string, pubKey *rsa.PublicKey, lifespan time.Duration) error {
	//convert the key to PEM
	pemKey, err := keys.RSAPublicKeyToPEM(pubKey)
	if err != nil {
		return fmt.Errorf("Could not convert key: %s, to pem. %s", keyID, err)
	}
	//put it in the KeyMetadata struct
	keyMeta := KeyMetadata{
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
	req, err := http.NewRequest("POST", RESTkeystoreURL+"save", bytes.NewBuffer(jsonKeyMeta))
	if err != nil {
		return fmt.Errorf("Could not create POST request to RESTKeystore API for key: %s. %s", keyID, err)
	}
	//grab and set the release of the write lock
	ks.Lock()
	defer ks.Unlock()
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

func (ks *RESTKeystore) GetKeys() (map[string]*rsa.PublicKey, error) {
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

func (ks *RESTKeystore) getKeyMetadata(keyID string) (*KeyMetadata, error) {
	//create the http request to get the Key
	req, err := http.NewRequest("GET", RESTkeystoreURL+"keys/"+keyID, nil)
	if err != nil {
		return nil, fmt.Errorf("Could not create GET request to RESTKeystore API. %s", err)
	}

	var resp *http.Response
	defer resp.Body.Close()
	retries := 0
	err = errors.New("")
	//we will attempt to get the key three times
	for err != nil && retries < 3 {
		resp, err = ks.HTTPClient.Do(req)
		retries++
		if err != nil {
			continue
		}
		//read the response bytes if success
		jsonBytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			continue
		}
		var keyMeta KeyMetadata
		err = json.Unmarshal(jsonBytes, &keyMeta)
		if err != nil {
			continue
		}
		return &keyMeta, nil
	}
	return nil, fmt.Errorf("3 Failed attempts at getting key %s from RESTKeystore. %s", keyID, err)
}

func (ks *RESTKeystore) getKeyIDs() ([]string, error) {
	var kids []string
	return kids, nil
	//TODO
}

func (ks *RESTKeystore) retireExpired() {
	//TODO
}
