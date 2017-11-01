package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/adrianosela/AuthService/customJWT"
	jwtgo "github.com/dgrijalva/jwt-go"
)

type GetTokenResponse struct {
	Token      string `json:"token"` //Spec recommends returning in the body to avoid header size limitations
	ValidUntil int64  `json:"valid_until"`
}

//GetTokenHandler is an HTTP handler that takes in basic auth, and gives the user a JWT
func (api *APIConfiguration) GetTokenHandler(w http.ResponseWriter, r *http.Request) {
	//for now picking up basic auth but not actually using it
	username, password, ok := r.BasicAuth()
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, fmt.Sprintf("[ERROR]: No basic credentials provided"))
		return
	}

	if !api.DB.PassedBasicAuth(username, password) {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, fmt.Sprintf("[ERROR]: Incorrect username or password"))
		return
	}

	userID, err := api.DB.GetUserID(username)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, fmt.Sprintf("[ERROR]: User passed basic auth but no records found")) //think of something better later
		return
	}

	claims := customJWT.NewCustomClaims(userID, "adrianosela/all", api.IdentityProv.IssuerURL, []string{}, time.Hour*1)

	//fill in group membership info
	claims.Groups = api.DB.GetUserMemberGroups(userID)

	//grab the signing key and id
	signingKey, id, err := api.Keystore.GetSigningKey()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, fmt.Sprintf("[ERROR]: %s", err)) //think of something better later
		return
	}

	jwt := customJWT.NewJWT(claims, jwtgo.SigningMethodRS512)

	jwt.Header["sig_kid"] = id

	stringToken, err := customJWT.SignJWT(jwt, signingKey)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, fmt.Sprintf("[ERROR]: Could not sign key: %v", err)) //for now, later will want to hide
		return
	}

	respBytes, err := json.Marshal(&GetTokenResponse{
		Token:      stringToken,
		ValidUntil: claims.ExpiresAt,
	})

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, fmt.Sprintf("[ERROR]: Could not marshall response: %v", err)) //for now, later will want to hide
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, string(respBytes)) //for now, later will want to hide
	return
}
