package cjwt

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/adrianosela/auth/openid"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/lestrrat/go-jwx/jwk"
)

//NewJWT returns a token given claims and a specified signing method
func NewJWT(claims *CustomClaims, signingMethod jwt.SigningMethod) *jwt.Token {
	return jwt.NewWithClaims(signingMethod, claims)
}

//SignJWT signs a JSON Web Token with a given private key
func SignJWT(tk *jwt.Token, key *rsa.PrivateKey) (string, error) {
	return tk.SignedString(key)
}

// ValidateJWT returns the claims within a token as a CustomClaims obect and validates its fields
func ValidateJWT(tkString, iss, aud, url string, grps []string) (*CustomClaims, error) {
	var cc CustomClaims
	// parse onto a jwt token object. Note the in-line use of the KeyFunc type
	token, err := jwt.ParseWithClaims(tkString, &cc, func(tk *jwt.Token) (interface{}, error) {
		// read the key id off the token header
		kid, ok := tk.Header["sig_kid"].(string)
		if !ok {
			return nil, errors.New("Signing Key ID Not in Token Header")
		}
		config, err := openid.Fetch(url)
		if err != nil {
			return nil, fmt.Errorf("could not fetch openid config: %s", err)
		}
		// now get the keys from that endpoint
		keyset, err := jwk.FetchHTTP(config.KeysEndpoint)
		if err != nil {
			return nil, fmt.Errorf("Failed to get keys from the endpoint specified by the provider's discovery endpoint: %s. %v", config.KeysEndpoint, err)
		}
		// if no keys exposed, return error
		if len(keyset.Keys) < 1 {
			return nil, fmt.Errorf("No keys found from keys endpoint (%s)", config.KeysEndpoint)
		}
		// materialize the keys onto an ID to Key map
		kidtoKeyMAP := map[string]interface{}{}
		for _, key := range keyset.Keys {
			kidtoKeyMAP[key.Kid()], err = key.Materialize()
			if err != nil {
				return nil, fmt.Errorf("Failed to materialize key %s: %s", key.Kid(), err)
			}
		}
		// if the correct key [id matching that of the token] is found, then convert it to rsa.PublicKey
		if signersPubKey, ok := kidtoKeyMAP[kid]; ok {
			// read pemBlock bytes off map
			pubPEMData, isByteSlice := (signersPubKey).([]byte)
			if !isByteSlice {
				return nil, fmt.Errorf("Could not read bytes off public key")
			}
			// convert bytes to public key pem block
			block, _ := pem.Decode(pubPEMData)
			if block == nil || block.Type != "PUBLIC KEY" {
				return nil, fmt.Errorf("failed to decode PEM block containing public key")
			}
			// convert pem block to PubKey
			pub, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				log.Fatal(err)
			}
			// return the pubkey
			return pub, nil
		}
		// return error if the key of matching ID was not in found
		return nil, fmt.Errorf("No key found for the given kid")
	})
	if err != nil {
		return nil, fmt.Errorf("[ERROR] Could not parse token: %s", err)
	}
	if token == nil || !token.Valid {
		return nil, fmt.Errorf("[ERROR] Token is invalid")
	}
	// we'll only use/check HS512
	if token.Method != jwt.SigningMethodRS512 {
		return nil, fmt.Errorf("[ERROR] Signing Algorithm: %s, not supported", token.Method.Alg())
	}
	// verify text claims
	if !cc.VerifyIssuer(iss, true) {
		return nil, fmt.Errorf("[ERROR] Issuer: Expected %s but was %s", iss, cc.Issuer)
	}
	if !cc.VerifyAudience(aud, true) && aud != "" {
		return nil, fmt.Errorf("[ERROR] Audience: Expected %s but was %s", aud, cc.Audience)
	}
	// verify time claims
	now := time.Now().Unix()
	if !cc.VerifyIssuedAt(now, true) {
		return nil, fmt.Errorf("[ERROR] The token was used before \"IssuedAt\"")
	}
	if !cc.VerifyExpiresAt(now, true) {
		return nil, fmt.Errorf("[ERROR] The token is expired")
	}
	// verify group membership
	for _, grp := range grps {
		if !cc.HasGroup(grp) {
			return nil, fmt.Errorf("[ERROR] Token does not contain required group %s", grp)
		}
	}
	return &cc, nil
}
