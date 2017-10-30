package store

import (
	"bytes"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/adrianosela/AuthService/customJWT"
	"github.com/adrianosela/AuthService/keys"
	jwtgo "github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	uuid "github.com/satori/go.uuid"
	jose "github.com/square/go-jose"
)

type MockDB struct {
	sync.RWMutex //inherit lock behavior
	Groups       map[string]*Group
	Users        map[string]*User
	PublicKeys   map[string]*KeyMetadata
	SigningKey   *rsa.PrivateKey
	SigningKeyID string
}

//NewMockDB returns a new MockDB
func NewMockDB() *MockDB {
	return &MockDB{
		Groups:       map[string]*Group{},
		Users:        map[string]*User{},
		PublicKeys:   map[string]*KeyMetadata{},
		SigningKey:   nil,
		SigningKeyID: "",
	}
}

//addGroup will add a new group to the database
func (db *MockDB) AddGroup(gp *Group) error {
	db.Lock()
	defer db.Unlock()
	//add the group to the map
	db.Groups[gp.ID] = gp
	log.Printf("[MOCK_DB] Added New Group: {\"name\":\"%s\",\"id\":\"%s\"}", gp.Name, gp.ID)
	return nil
}

//deleteGroup will remove a group given its group id
func (db *MockDB) DeleteGroup(id string) error {
	db.Lock()
	defer db.Unlock()
	//if the entry exists delete its value
	if _, ok := db.Groups[id]; ok {
		delete(db.Groups, id)
		log.Printf("[MOCK_DB] Deleted Group: {\"id\":\"%s\"}", id)
		return nil
	}
	//if not found
	return errors.New("Group with id=%d not found in store")
}

//addUserToGroup will add a user of a given id to a group of given id
func (db *MockDB) AddUserToGroup(userID, groupID, membershipType string) error {
	db.Lock()
	defer db.Unlock()
	//check userID is not empty
	if userID == "" {
		return errors.New("Empty user id")
	}
	//if the entry exists then add the user
	if grp, ok := db.Groups[groupID]; ok {
		if membershipType == "OWNER" {
			grp.Owners = append(grp.Owners, userID)
			log.Printf("[MOCK_DB] Added User: {\"id\":\"%s\"} as an OWNER to Group: {\"id\":\"%s\"}", userID, groupID)
			return nil
		}
		if membershipType == "MEMBER" {
			grp.Members = append(grp.Members, userID)
			log.Printf("[MOCK_DB] Added User: {\"id\":\"%s\"} as a MEMBER to Group: {\"id\":\"%s\"}", userID, groupID)
			return nil
		}
		return fmt.Errorf("Invalid membership type specified: %s", membershipType)
	}
	//if group not found
	return fmt.Errorf("Group with id=%s not found in store", groupID)
}

//removeUserFromGroup will remove a user of a given id from a group of given id
func (db *MockDB) RemoveUserFromGroup(userID, groupID, membershipType string) error {
	db.Lock()
	defer db.Unlock()
	//check userID is not empty
	if userID == "" {
		return errors.New("Empty user id")
	}
	var err error
	//if the entry exists then remove the user
	if grp, ok := db.Groups[groupID]; ok {
		if membershipType == "OWNER" {
			grp.Owners, err = removeStrFromSlice(groupID, grp.Owners)
			if err == nil {
				log.Printf("[MOCK_DB] Removed User: {\"id\":\"%s\"} as an OWNER to Group: {\"id\":\"%s\"}", userID, groupID)
			}
			return err
		}
		if membershipType == "MEMBER" {
			grp.Members, err = removeStrFromSlice(groupID, grp.Members)
			if err == nil {
				log.Printf("[MOCK_DB] Removed User: {\"id\":\"%s\"} as a MEMBER to Group: {\"id\":\"%s\"}", userID, groupID)
			}
			return err
		}
		return fmt.Errorf("Invalid membership type specified: %s", membershipType)
	}
	//if group not found
	return fmt.Errorf("Group with id=%s not found in store", groupID)
}

//addUser will add a new user to the database
func (db *MockDB) AddUser(username, password, email string) (string, error) {
	usr := &User{
		Email: email,
		ID:    uuid.NewV4().String(),
	}

	passbytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("[ERROR] Could not hash password, user %s was not added", username)
	}

	usr.Secret = passbytes
	log.Printf("[DEBUG] user: %s, password: %s", username, password)

	//add the user to the map of username to user object
	db.Lock()
	db.Users[username] = usr
	db.Unlock()

	log.Printf("[MOCK_DB] Added New User: {\"uname\":\"%s\",\"id\":\"%s\"}", username, usr.ID)
	return usr.ID, nil
}

//deleteUser will remove a user from the database
func (db *MockDB) DeleteUser(id string) error {
	db.Lock()
	defer db.Unlock()
	//if the entry exists then delete it
	if _, ok := db.Users[id]; ok {
		delete(db.Users, id)
		log.Printf("[MOCK_DB] Deleted User: {\"id\":\"%s\"} from DB", id)
		return nil
	}
	//if user not found
	return fmt.Errorf("User with id=%s not found in store", id)
}

//saveKey will add a new key to the database given an an id and a description
func (db *MockDB) SaveKey(id string, key *rsa.PrivateKey, lifetime time.Duration) error {
	db.Lock()
	defer db.Unlock()

	if key == nil {
		log.Fatal("[KEYS] Could not save key: Key was nil")
	}

	db.SigningKey = key
	db.SigningKeyID = id
	//convert the public key to pem and store as our key object in the db
	pemkey, err := keys.RSAPublicKeyToPEM(&key.PublicKey)
	if err != nil {
		log.Fatal("[ERROR] Could not convert key to pem")
	}
	//add the key to the map
	keyStruct := KeyMetadata{
		ID:           id,
		KeyPem:       pemkey,
		InvalidAfter: time.Now().Add(lifetime),
	}

	db.PublicKeys[id] = &keyStruct

	//FIXME begin

	bts, err := json.Marshal(keyStruct)
	if err != nil {
		log.Fatal("[ERROR] Could not marshall key")
		return errors.New("[ERROR] Could not marshall key")
	}

	req, err := http.NewRequest("POST", "http://keystore.adrianosela.com/key", bytes.NewBuffer(bts))
	if err != nil {
		log.Fatal("[ERROR] Could not publish key to keystore")
		return errors.New("[ERROR] Could not publish key to keystore")
	}

	cli := http.Client{}

	resp, err := cli.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		log.Fatal("[ERROR] Could not publish key to keystore" + strconv.Itoa(resp.StatusCode))
		return errors.New("[ERROR] Could not publish key to keystore")
	}

	//FIXME end

	log.Printf("[KEYS] Added New Key: {\"id\":\"%s\"}", id)
	return nil
}

//deleteKey will remove a key from the database
func (db *MockDB) DeleteKey(id string) error {
	db.Lock()
	defer db.Unlock()
	//delete the key
	//if the entry exists then delete it
	if _, ok := db.PublicKeys[id]; ok {
		delete(db.PublicKeys, id)
		log.Printf("[MOCK_DB] Deleted Key: {\"id\":\"%s\"}", id)
		return nil
	}
	//if user not found
	return fmt.Errorf("Key with id=%s not found in store", id)
}

func (db *MockDB) GetKeys() (map[string]*KeyMetadata, error) {
	db.Lock()
	defer db.Unlock()
	return db.PublicKeys, nil
}

func removeStrFromSlice(str string, sli []string) ([]string, error) {
	for idx, elem := range sli {
		if elem == str {
			//if the index is not that of the last
			if idx < len(sli)-1 {
				sli = append(sli[:idx], sli[idx+1:]...)
				return sli, nil
			}
			//if its the last
			sli = sli[:idx]
			return sli, nil
		}
	}
	return nil, errors.New("String Not Found")
}

func (db *MockDB) SharePubKeyHandler(w http.ResponseWriter, r *http.Request) {
	keys, err := db.GetKeys()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, fmt.Sprintf("[ERROR] : %v", err))
		return
	}

	keyset := jose.JsonWebKeySet{
		Keys: []jose.JsonWebKey{},
	}

	for kid, key := range keys {
		keyset.Keys = append(keyset.Keys, jose.JsonWebKey{
			Key:       key.KeyPem,
			Algorithm: "RS512",
			Use:       "sig",
			KeyID:     kid,
		})
	}

	keysBytes, err := json.Marshal(keyset)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, fmt.Sprintf("[ERROR] : %v", err))
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, string(keysBytes))
	return
}

type GetTokenResponse struct {
	Token      string `json:"token"` //Spec recommends returning in the body to avoid header size limitations
	ValidUntil int64  `json:"valid_until"`
}

func (db *MockDB) GetTokenHandler(w http.ResponseWriter, r *http.Request) {
	//for now picking up basic auth but not actually using it
	username, password, ok := r.BasicAuth()
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, fmt.Sprintf("[ERROR]: No basic credentials provided"))
		return
	}

	if !db.PassedBasicAuth(username, password) {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, fmt.Sprintf("[ERROR]: Incorrect username or password"))
		return
	}

	userID, err := db.GetUserID(username)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, fmt.Sprintf("[ERROR]: User passed basic auth but no records found")) //think of something better later
		return
	}

	claims := customJWT.NewCustomClaims(userID, "adrianosela/all", "http://localhost:8888", []string{}, time.Hour*1)

	db.RLock()
	//fill in group membership info
	claims.Groups = db.getUserMemberGroups(userID)

	//grab the signing key and id
	signingKey := db.SigningKey
	id := db.SigningKeyID

	db.RUnlock()

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

//GetUserID returns the user ID of a user given his/her username
func (db *MockDB) GetUserID(uname string) (string, error) {
	db.RLock()
	defer db.RUnlock()
	//if found return the id, else error
	if user, ok := db.Users[uname]; ok {
		return user.ID, nil
	}
	return "", fmt.Errorf("Username %s not in store", uname)
}

type ListGroupsResponse struct {
	Groups []Group `json:"groups"`
}

//ListGroupsHandler is an HTTP Req. Handler that lists groups in the database
func (db *MockDB) ListGroupsHandler(w http.ResponseWriter, r *http.Request) {
	db.RLock() //note this could be more fine grained
	defer db.RUnlock()

	grps := []Group{}
	for id, grp := range db.Groups {
		grps = append(grps, Group{
			ID:          id,
			Name:        grp.Name,
			Description: grp.Description,
		})
	}

	respBytes, err := json.Marshal(&ListGroupsResponse{
		Groups: grps,
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, fmt.Sprintf("[ERROR]: Could not marshall response: %v", err)) //for now, later will want to hide
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, string(respBytes))
	return
}

//ShowGroupHandler is an HTTP Req. Handler that lists groups in the database
func (db *MockDB) ShowGroupHandler(w http.ResponseWriter, r *http.Request) {
	db.RLock() //could be more finegrained
	defer db.RUnlock()

	vars := mux.Vars(r)

	if gid, ok := vars["group_id"]; ok {
		respBytes, err := json.Marshal(&Group{
			Name:    db.Groups[gid].Name,
			ID:      db.Groups[gid].ID,
			Members: db.Groups[gid].Members,
			Owners:  db.Groups[gid].Owners,
		})
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError) //for now
			fmt.Fprint(w, string("Could not marhall response"))
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, string(respBytes))
		return
	}
	w.WriteHeader(http.StatusNotFound)
	fmt.Fprint(w, string("Group not found")) //for now, later will want to hide
	return
}

func (db *MockDB) getUserMemberGroups(userid string) []string {
	db.RLock()
	defer db.RUnlock()
	memberOf := []string{}
	for groupid, grp := range db.Groups {
		if isInSlice(userid, grp.Members) {
			memberOf = append(memberOf, groupid)
		}
	}
	return memberOf
}

func isInSlice(lookfor string, sli []string) bool {
	for _, str := range sli {
		if lookfor == str {
			return true
		}
	}
	return false
}

//PassedBasicAuth takes in basic auth credentials, hashes the password and compares against the hash in store
func (db *MockDB) PassedBasicAuth(uname, pass string) bool {
	db.RLock()
	defer db.RUnlock()

	if user, ok := db.Users[uname]; ok {
		if err := bcrypt.CompareHashAndPassword(user.Secret, []byte(pass)); err == nil {
			return true
		}
		return false
	}

	return false
}
