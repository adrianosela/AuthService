package main

import (
	"crypto/rand"
	"crypto/rsa"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/adrianosela/AuthService/api"
	"github.com/adrianosela/AuthService/keys"
	"github.com/adrianosela/AuthService/keystore"
	"github.com/adrianosela/AuthService/openidconnect"
	"github.com/adrianosela/AuthService/store"
	uuid "github.com/satori/go.uuid"
)

func main() {

	idp := &openidconnect.OpenIDProvider{
		IssuerURL: os.Getenv("IDP_ISSUER_URL"),
		KeysURL:   os.Getenv("IDP_ISSUER_URL") + "/auth/keys",
	}

	ks, err := keystore.NewRESTKeystore()
	if err != nil {
		log.Fatalf("[ERROR] Could not initialize keystore. %s", err)
	}

	APIConfig := &api.APIConfiguration{
		IdentityProv: idp,
		DB:           store.NewMockDB(),
		Keystore:     ks,
	}

	//crate some example users
	adrianoID, _ := APIConfig.DB.AddUser("adriano", uuid.NewV4().String(), "adriano@gmail.com")
	miguelID, _ := APIConfig.DB.AddUser("miguel", uuid.NewV4().String(), "miguel@gmail.com")
	felipeID, _ := APIConfig.DB.AddUser("felipe", uuid.NewV4().String(), "felipe@gmail.com")
	adrianID, _ := APIConfig.DB.AddUser("adrian", uuid.NewV4().String(), "adrian@gmail.com")
	antonioID, _ := APIConfig.DB.AddUser("antonio", uuid.NewV4().String(), "antonio@gmail.com")

	APIConfig.DB.AddGroup(&store.Group{
		ID:          uuid.NewV4().String(),
		Name:        "Everyone",
		Description: "Every Test User",
		Members:     []string{adrianoID, miguelID, felipeID, adrianID, antonioID},
		Owners:      []string{adrianoID},
	})
	APIConfig.DB.AddGroup(&store.Group{
		ID:          uuid.NewV4().String(),
		Name:        "Developers",
		Description: "Developer Test Users",
		Members:     []string{adrianoID, miguelID, felipeID},
		Owners:      []string{adrianoID},
	})
	APIConfig.DB.AddGroup(&store.Group{
		ID:          uuid.NewV4().String(),
		Name:        "Infrastructure",
		Description: "Infrastructure Test Users",
		Members:     []string{adrianoID, felipeID},
		Owners:      []string{adrianoID, felipeID},
	})
	APIConfig.DB.AddGroup(&store.Group{
		ID:          uuid.NewV4().String(),
		Name:        "GameServer",
		Description: "GameServer Allow-Join Users",
		Members:     []string{adrianoID, miguelID, adrianID},
		Owners:      []string{adrianoID},
	})

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal("[ERROR] Could not generate Keys")
	}

	block, err := keys.RSAPublicKeyToPEM(&key.PublicKey)
	if err != nil {
		log.Fatal("[ERROR] Could not convert key to PEM")
	}

	id := uuid.NewV4().String()

	log.Printf("[INFO] Generated New Key-Pair: {\"id\":\"%s\"}\n%s", id, string(block))

	err = APIConfig.Keystore.SetKeyPair(id, key, time.Duration(time.Hour*12))
	if err != nil {
		log.Fatalf("[ERROR] Could not set Key: %v", err)
	}

	router := api.GetRouter(APIConfig)
	log.Println("[INFO] Listening on http://localhost:80")
	err = http.ListenAndServe(":80", router)
	if err != nil {
		log.Fatal("ListenAndServe Error: ", err)
	}

}
