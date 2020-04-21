package store

import "net/http"

//Datastore will allow us to implement a database in multiple ways
type Datastore interface {
	// AddGroup will add a new group to the database
	AddGroup(*Group) error

	// DeleteGroup will remove a group given its group id
	DeleteGroup(string) error

	// AddUserToGroup will add a user of a given id to a group of given id
	AddUserToGroup(string, string, string) error

	// RemoveUserFromGroup will remove a user of a given id from a group of given id
	RemoveUserFromGroup(string, string, string) error

	// AddUser will add a new user to the database given username, password, and email, returns the ID
	AddUser(string, string, string) (string, error)

	// GetUserID gets a user's ID given their username
	GetUserID(string) (string, error)

	// DeleteUser will remove a user from the database
	DeleteUser(string) error

	// HTTP Endpoint Handler for listing groups
	ListGroupsHandler(http.ResponseWriter, *http.Request)

	// HTTP Endpoint Handler for showing a group
	ShowGroupHandler(http.ResponseWriter, *http.Request)

	PassedBasicAuth(string, string) bool
	GetUserMemberGroups(string) []string
}

type Group struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Members     []string `json:"members,omitempty"` //list of member user uuids
	Owners      []string `json:"owners,omitempty"`  //list of owner user uuids
}

type User struct {
	ID     string `json:"id"`
	Secret []byte `json:"hashed"`
	Email  string `json:"email"`
}
