package customJWT

import (
	"crypto/rsa"
	"encoding/json"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	uuid "github.com/satori/go.uuid"
)

/* _______StandardClaims:______________
Audience  string `json:"aud,omitempty"`
ExpiresAt int64  `json:"exp,omitempty"`
Id        string `json:"jti,omitempty"`
IssuedAt  int64  `json:"iat,omitempty"`
Issuer    string `json:"iss,omitempty"`
NotBefore int64  `json:"nbf,omitempty"`
Subject   string `json:"sub,omitempty"`
_______________________________________
*/

//CustomClaims represents claims we wish to make and verify with JWTs
type CustomClaims struct {
	jwt.StandardClaims          //inherits JSON web token standard claims:
	Groups             []string `json:"grps,omitempty"`
}

//NewCustomClaims returns a new CustomClaims object
func NewCustomClaims(sub, aud, iss string, grps []string, lifetime time.Duration) *CustomClaims {
	return &CustomClaims{
		StandardClaims: jwt.StandardClaims{
			Audience:  aud,
			ExpiresAt: time.Now().Add(lifetime).Unix(),
			Id:        uuid.NewV4().String(),
			IssuedAt:  time.Now().Unix(),
			Issuer:    iss,
			NotBefore: time.Now().Unix(),
			Subject:   sub,
		},
		Groups: grps,
	}
}

//HasGroup returns true if a CustomClaims object contains a given group as part of its grp claims
func (c *CustomClaims) HasGroup(groupID string) bool {
	for _, grp := range c.Groups {
		if grp == groupID {
			return true
		}
	}
	return false
}

//StdClaimsToCustomClaims populates a CustomClaims struct with a given map of std claims
func StdClaimsToCustomClaims(stdClaims *jwt.MapClaims) (*CustomClaims, error) {
	//marshall the std claims
	stdClaimsBytes, err := json.Marshal(stdClaims)
	if err != nil {
		return nil, err
	}
	//Unmarshal onto a CustomClaims object
	var cc *CustomClaims
	err = json.Unmarshal(stdClaimsBytes, cc)
	if err != nil {
		return nil, err
	}
	return cc, nil
}

//NewJWT returns a token given claims and a specified signing method
func NewJWT(claims *CustomClaims, signingMethod jwt.SigningMethod) *jwt.Token {
	return jwt.NewWithClaims(signingMethod, claims)
}

//SignJWT signs a JSON Web Token with a given private key
func SignJWT(tk *jwt.Token, key *rsa.PrivateKey) (string, error) {
	return tk.SignedString(key)
}
