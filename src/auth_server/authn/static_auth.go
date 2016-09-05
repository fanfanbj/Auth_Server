package authn

import (
	"encoding/json"
	"golang.org/x/crypto/bcrypt"
)

type Requirements struct {
	Password *PasswordString `yaml:"password,omitempty" json:"password,omitempty"`
}

type staticUsersAuth struct {
	users map[string]*Requirements
}

func (r Requirements) String() string {
	p := r.Password
	if p != nil {
		pm := PasswordString("***")
		r.Password = &pm
	}
	b, _ := json.Marshal(r)
	r.Password = p
	return string(b)
}

func NewStaticUserAuth(users map[string]*Requirements) *staticUsersAuth {
	return &staticUsersAuth{users: users}
}

func (sua *staticUsersAuth) Authenticate(user string, password PasswordString) (bool, error) {
	reqs := sua.users[user]
	if reqs == nil {
		return false, NoMatch
	}
	if reqs.Password != nil {
		if bcrypt.CompareHashAndPassword([]byte(*reqs.Password), []byte(password)) != nil {
			return false, nil
		}
	}
	return true, nil
}

func (sua *staticUsersAuth) Stop() {
}

func (sua *staticUsersAuth) Name() string {
	return "static"
}
