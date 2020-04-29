package api

import (
	"github.com/adrianosela/auth/keystore"
	"github.com/adrianosela/auth/openid"
	"github.com/adrianosela/auth/storage"
	"github.com/gorilla/mux"
)

// Configuration includes the datastore, the keystore, and the identity provider
type Configuration struct {
	DB       storage.Datastore
	Keystore keystore.Keystore
	OpenID   *openid.DiscoveryConfig
}

//GetRouter returns a router given an APIConfiguration
func GetRouter(conf *Configuration) *mux.Router {

	router := mux.NewRouter()

	// OpenID Connect Endpoints
	h, _ := conf.OpenID.HTTPHandlerFunc()
	router.Methods("GET").Path(openid.DefaultDiscoveryPath).HandlerFunc(h)
	router.Methods("GET").Path("/auth/keys").HandlerFunc(conf.Keystore.SharePubKeyHandler)

	// Basic Auth Endpoints --> Emitting JWT Tokens
	router.Methods("GET").Path("/auth/login").HandlerFunc(conf.GetTokenHandler)

	// Groups Mgmt Endpoints
	router.Methods("GET").Path("/groups").HandlerFunc(conf.DB.ListGroupsHandler)
	router.Methods("GET").Path("/groups/{group_id}").HandlerFunc(conf.DB.ShowGroupHandler)

	return router
}
