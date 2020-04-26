package main

import (
	"crypto/rand"
	"crypto/rsa"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/adrianosela/auth/api"
	"github.com/adrianosela/auth/keys"
	"github.com/adrianosela/auth/keystore"
	"github.com/adrianosela/auth/openid"
	"github.com/adrianosela/auth/store"
	uuid "github.com/satori/go.uuid"
)

func main() {
	ks, err := keystore.NewRESTKeystore()
	if err != nil {
		log.Fatalf("[ERROR] Could not initialize keystore. %s", err)
	}

	apiConfig := &api.Configuration{
		OpenID:   openid.DefaultDiscoveryConfig(os.Getenv("IDP_ISSUER_URL")),
		DB:       store.NewMockDB(),
		Keystore: ks,
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal("[ERROR] Could not generate Keys")
	}
	block, err := keys.RSAPublicKeyToPEM(&key.PublicKey)
	if err != nil {
		log.Fatal("[ERROR] Could not convert key to PEM")
	}
	id := uuid.Must(uuid.NewV4()).String()
	log.Printf("[INFO] Generated New Key-Pair: {\"id\":\"%s\"}\n%s", id, string(block))
	err = apiConfig.Keystore.SetKeyPair(id, key, time.Duration(time.Hour*12))
	if err != nil {
		log.Fatalf("[ERROR] Could not set Key: %v", err)
	}

	router := api.GetRouter(apiConfig)
	log.Println("[INFO] Listening on http://localhost:80")
	err = http.ListenAndServe(":80", router)
	if err != nil {
		log.Fatal("ListenAndServe Error: ", err)
	}
}
