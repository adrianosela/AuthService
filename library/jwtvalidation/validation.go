package jwtvalidation

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/adrianosela/auth/cjwt"
	"github.com/adrianosela/auth/openidconnect"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/lestrrat/go-jwx/jwk"
)

//ValidateToken returns the claims within a token as a CustomClaims obect and validates its fields
func ValidateToken(tkString, iss, aud, authProvEndpoint string, grps []string) (*cjwt.CustomClaims, error) {
	var cc cjwt.CustomClaims
	//parse onto a jwt token object. Note the in-line use of the KeyFunc type
	token, err := jwt.ParseWithClaims(tkString, &cc, func(tk *jwt.Token) (interface{}, error) {
		//read the key id off the token header
		kid, ok := tk.Header["sig_kid"].(string)
		if !ok {
			return nil, errors.New("Signing Key ID Not in Token Header")
		}
		//get the .well-known configuration
		req, err := http.NewRequest("GET", authProvEndpoint+"/.well-known/webfinder", nil)
		if err != nil {
			return nil, err
		}
		client := http.Client{
			Timeout: time.Minute * 1,
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		//read the bytes off the response body
		respBytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		//unmarshall bytes onto the struct
		var discoverystruct openidconnect.OpenIDDiscoveryConfig
		err = json.Unmarshal(respBytes, &discoverystruct)
		if err != nil {
			return nil, err
		}
		//now get the keys from that endpoint
		keyset, err := jwk.FetchHTTP(discoverystruct.KeysEndpoint)
		if err != nil {
			return nil, fmt.Errorf("Failed to get keys from the endpoint specified by the provider's discovery endpoint: %s. %v", discoverystruct.KeysEndpoint, err)
		}
		//if no keys exposed, return error
		if len(keyset.Keys) < 1 {
			return nil, fmt.Errorf("No keys found from keys endpoint (%s)", discoverystruct.KeysEndpoint)
		}
		//materialize the keys onto an ID to Key map
		kidtoKeyMAP := map[string]interface{}{}
		for _, key := range keyset.Keys {
			kidtoKeyMAP[key.Kid()], err = key.Materialize()
			if err != nil {
				return nil, fmt.Errorf("Failed to materialize key %s: %s", key.Kid(), err)
			}
		}
		//if the correct key [id matching that of the token] is found, then convert it to rsa.PublicKey
		if signersPubKey, ok := kidtoKeyMAP[kid]; ok {
			//read pemBlock bytes off map
			pubPEMData, isByteSlice := (signersPubKey).([]byte)
			if !isByteSlice {
				return nil, fmt.Errorf("Could not read bytes off public key")
			}
			//convert bytes to public key pem block
			block, _ := pem.Decode(pubPEMData)
			if block == nil || block.Type != "PUBLIC KEY" {
				return nil, fmt.Errorf("failed to decode PEM block containing public key")
			}
			//convert pem block to PubKey
			pub, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				log.Fatal(err)
			}
			//return the pubkey
			return pub, nil
		}
		//return error if the key of matching ID was not in found
		return nil, fmt.Errorf("No key found for the given kid")
	})
	if err != nil {
		return nil, fmt.Errorf("[ERROR] Could not parse token: %s", err)
	}
	if token == nil || !token.Valid {
		return nil, fmt.Errorf("[ERROR] Token is invalid")
	}
	//We'll only use/check HS512
	if token.Method != jwt.SigningMethodRS512 {
		return nil, fmt.Errorf("[ERROR] Signing Algorithm: %s, not supported", token.Method.Alg())
	}
	// Now to verify individual claims (functions, except groups, inherited from JWT StandardClaims)
	now := time.Now().Unix()
	//Verify text claims
	if !cc.VerifyIssuer(iss, true) {
		return nil, fmt.Errorf("[ERROR] Issuer: Expected %s but was %s", iss, cc.Issuer)
	}
	if !cc.VerifyAudience(aud, true) && aud != "" {
		return nil, fmt.Errorf("[ERROR] Audience: Expected %s but was %s", aud, cc.Audience)
	}
	//Verify time claims
	if !cc.VerifyIssuedAt(now, true) {
		return nil, fmt.Errorf("[ERROR] The token was used before \"IssuedAt\"")
	}
	if !cc.VerifyExpiresAt(now, true) {
		return nil, fmt.Errorf("[ERROR] The token is expired")
	}
	//Verify group Membership
	for _, grp := range grps {
		if !cc.HasGroup(grp) {
			return nil, fmt.Errorf("[ERROR] Token does not contain required group %s", grp)
		}
	}
	return &cc, nil
}
