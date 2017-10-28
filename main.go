package main

import (
	"crypto/rand"
	"crypto/rsa"
	"log"
	"net/http"

	"github.com/adrianosela/AuthService/api"
	"github.com/adrianosela/AuthService/keys"
	"github.com/adrianosela/AuthService/openidconnect"
	"github.com/adrianosela/AuthService/store"
	uuid "github.com/satori/go.uuid"
)

func main() {

	idp := &openidconnect.OpenIDProvider{
		IssuerURL: "http://localhost:8888",
		KeysURL:   "http://localhost:8888/auth/keys",
	}

	rtrConfig := &api.RouterConfiguration{
		IdentityProv: idp,
		DB:           store.NewMockDB(),
	}

	//crate some example users
	adrianoID, _ := rtrConfig.DB.AddUser("adriano", uuid.NewV4().String(), "adriano@gmail.com")
	miguelID, _ := rtrConfig.DB.AddUser("miguel", uuid.NewV4().String(), "miguel@gmail.com")
	felipeID, _ := rtrConfig.DB.AddUser("felipe", uuid.NewV4().String(), "felipe@gmail.com")
	adrianID, _ := rtrConfig.DB.AddUser("adrian", uuid.NewV4().String(), "adrian@gmail.com")
	antonioID, _ := rtrConfig.DB.AddUser("antonio", uuid.NewV4().String(), "antonio@gmail.com")

	rtrConfig.DB.AddGroup(&store.Group{
		ID:          uuid.NewV4().String(),
		Name:        "Everyone",
		Description: "Every Test User",
		Members:     []string{adrianoID, miguelID, felipeID, adrianID, antonioID},
		Owners:      []string{adrianoID},
	})
	rtrConfig.DB.AddGroup(&store.Group{
		ID:          uuid.NewV4().String(),
		Name:        "Developers",
		Description: "Developer Test Users",
		Members:     []string{adrianoID, miguelID, felipeID},
		Owners:      []string{adrianoID},
	})
	rtrConfig.DB.AddGroup(&store.Group{
		ID:          uuid.NewV4().String(),
		Name:        "Infrastructure",
		Description: "Infrastructure Test Users",
		Members:     []string{adrianoID, felipeID},
		Owners:      []string{adrianoID, felipeID},
	})
	rtrConfig.DB.AddGroup(&store.Group{
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

	err = rtrConfig.DB.SaveKey(id, "TestKey", key)
	if err != nil {
		log.Fatalf("[ERROR] Could not set Key: %v", err)
	}

	router := api.GetRouter(rtrConfig)
	log.Println("[INFO] Listening on http://localhost:8888")
	err = http.ListenAndServe(":8888", router)
	if err != nil {
		log.Fatal("ListenAndServe Error: ", err)
	}

}