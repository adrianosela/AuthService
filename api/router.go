package api

import (
	"github.com/adrianosela/AuthService/keystore"
	"github.com/adrianosela/AuthService/openidconnect"
	"github.com/adrianosela/AuthService/store"
	"github.com/gorilla/mux"
)

//APIConfiguration includes the datastore, the keystore, and the identity provider
type APIConfiguration struct {
	DB           store.Datastore
	Keystore     keystore.Keystore
	IdentityProv *openidconnect.OpenIDProvider
}

//GetRouter returns a router given an APIConfiguration
func GetRouter(api *APIConfiguration) *mux.Router {

	router := mux.NewRouter()

	// OpenID Connect Endpoints
	router.Methods("GET").Path("/.well-known/webfinder").HandlerFunc(api.IdentityProv.OpenIDConfigDiscovery)
	router.Methods("GET").Path("/auth/keys").HandlerFunc(api.Keystore.SharePubKeyHandler)

	// Basic Auth Endpoints --> Emitting JWT Tokens
	router.Methods("GET").Path("/auth/login").HandlerFunc(api.GetTokenHandler)

	// Groups Mgmt Endpoints
	router.Methods("GET").Path("/groups").HandlerFunc(api.DB.ListGroupsHandler)
	router.Methods("GET").Path("/groups/{group_id}").HandlerFunc(api.DB.ShowGroupHandler)

	return router
}
