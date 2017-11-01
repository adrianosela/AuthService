package store

import "net/http"

//Datastore will allow us to implement a database in multiple ways
type Datastore interface {
	//addGroup will add a new group to the database
	AddGroup(*Group) error

	//deleteGroup will remove a group given its group id
	DeleteGroup(string) error

	//addUserToGroup will add a user of a given id to a group of given id
	AddUserToGroup(string, string, string) error

	//removeUserFromGroup will remove a user of a given id from a group of given id
	RemoveUserFromGroup(string, string, string) error

	//addUser will add a new user to the database given username, password, and email, returns the ID
	AddUser(string, string, string) (string, error)

	//To get a user ID given its username
	GetUserID(string) (string, error)

	//deleteUser will remove a user from the database
	DeleteUser(string) error

	//HTTP Endpoint Handler for listing groups
	ListGroupsHandler(http.ResponseWriter, *http.Request)

	//HTTP Endpoint Handler for showing a group
	ShowGroupHandler(http.ResponseWriter, *http.Request)

	PassedBasicAuth(string, string) bool

	GetUserMemberGroups(string) []string
}

type Group struct {
	Name        string   `json:"name"`
	ID          string   `json:"id"`
	Description string   `json:"description,omitempty"`
	Members     []string `json:"members,omitempty"` //list of member user uuids
	Owners      []string `json:"owners,omitempty"`  //list of owner user uuids
}

type User struct {
	ID     string `json:"id"`
	Secret []byte `json:"hashed"`
	Email  string `json:"email"`
}
