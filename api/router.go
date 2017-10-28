package api

import (
	"github.com/adrianosela/AuthService/openidconnect"
	"github.com/adrianosela/AuthService/store"
	"github.com/gorilla/mux"
)

//RouterConfiguration includes the datastore and the identity provider
type RouterConfiguration struct {
	DB           store.Datastore
	IdentityProv *openidconnect.OpenIDProvider
}

//GetRouter returns a router given a router configuration
func GetRouter(rtrConfig *RouterConfiguration) *mux.Router {

	router := mux.NewRouter()

	// OpenID Connect Endpoints
	router.Methods("GET").Path("/.well-known/webfinder").HandlerFunc(rtrConfig.IdentityProv.OpenIDConfigDiscovery)
	router.Methods("GET").Path("/auth/keys").HandlerFunc(rtrConfig.DB.SharePubKeyHandler)

	// Basic Auth Endpoints --> Emitting JWT Tokens
	router.Methods("GET").Path("/auth/login").HandlerFunc(rtrConfig.DB.GetTokenHandler)

	// Groups Mgmt Endpoints
	router.Methods("GET").Path("/groups").HandlerFunc(rtrConfig.DB.ListGroupsHandler)
	router.Methods("GET").Path("/groups/{group_id}").HandlerFunc(rtrConfig.DB.ShowGroupHandler)

	return router
}
