package auther

import (
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"fmt"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

const sessionExpiry = 14 * time.Duration(24) * time.Hour

// Authenticator is an interface for authentication functions.
//
// Authenticator is an interface to be used for critical authentication
// functionality; registering, logging in and out, and authenticating a user's
// token. Under the hood, it uses a database dependency to store user data and
// session information.
type Authenticator interface {
	Signup(fullname, username, password string) (string, error)
	Signin(username, password string) (string, error)
	Signout(token string) error
	Authenticate(token string) (User, error)
}

// UserID is a type for an ID of a user in the database.
//
// This is meant to provide extensibility; changing this to a string (for
// example, if UUIDs were used as IDs) should be straightforward and require
// minimal changes.
type UserID int

// User is the basic user information returned to the caller on authentication.
type User struct {
	ID       UserID `json:"id"`
	Username string `json:"username"`
	FullName string `json:"fullname"`
}

// userRow includes a User, and the password information of that user.
type userRow struct {
	User
	PasswordHash string `json:"-"`
	PasswordSalt string `json:"-"`
	IsDisabled   bool   `json:"-"`
}

// UserSession stores a user's logged-in session.
type UserSession struct {
	SessionKey   string
	UserID       UserID
	LoginTime    time.Time
	LastSeenTime time.Time
}

type authenticator struct {
	db AuthDatabase
}

// NewAuthenticator returns an implementation of Authenticator.
//
// This function takes a `sql.DB` and returns an
// Authenticator using that instance.
func NewPSQLAuthenticator(sqldb *sql.DB) (Authenticator, error) {
	db, err := NewPSQLAuthDatabase(sqldb)
	if err != nil {
		return &authenticator{}, fmt.Errorf("failed to initialize PSQL auth database: %s", err.Error())
	}

	return &authenticator{
		db: db,
	}, nil
}

func NewInMemoryAuthenticator() (Authenticator, error) {
	db := NewInMemoryAuthDatabase()

	return &authenticator{
		db: db,
	}, nil
}

func (a *authenticator) Signup(fullname, username, password string) (string, error) {
	_, err := a.db.GetUser(username)
	if err == nil {
		return "", fmt.Errorf("username %s already in use", username)
	}

	passwordSalt, err := generateSalt()
	if err != nil {
		return "", fmt.Errorf("failed to generate salt: %s", err.Error())
	}

	passwordHash := hash([]byte(password), []byte(passwordSalt))

	u, err := a.db.AddUser(username, fullname, passwordHash, passwordSalt, false)
	if err != nil {
		return "", fmt.Errorf("failed to add user to database: %s", err.Error())
	}

	token, err := generateToken()
	if err != nil {
		return "", fmt.Errorf("failed to generate token: %s", err.Error())
	}

	err = a.db.CreateUserSession(token, u.ID, time.Now(), time.Now())
	if err != nil {
		return "", fmt.Errorf("failed to create user session: %s", err.Error())
	}

	return token, nil
}

func (a *authenticator) Signin(username, password string) (string, error) {
	u, err := a.db.GetUser(username)
	if err != nil {
		return "", fmt.Errorf("failed to lookup username: %s", err.Error())
	}

	h := hash([]byte(password), []byte(u.PasswordSalt))
	cmp := subtle.ConstantTimeCompare([]byte(h), []byte(u.PasswordHash))
	if cmp == 0 {
		return "", fmt.Errorf("invalid password for user %s", username)
	}

	token, err := generateToken()
	if err != nil {
		return "", fmt.Errorf("failed to generate token: %s", err.Error())
	}

	err = a.db.CreateUserSession(token, u.ID, time.Now(), time.Now())
	if err != nil {
		return "", fmt.Errorf("failed to create user session: %s", err.Error())
	}

	return token, nil
}

func (a *authenticator) Signout(token string) error {
	return a.db.RemoveUserSession(token)
}

func (a *authenticator) Authenticate(token string) (User, error) {
	session, err := a.db.GetUserSession(token)
	if err != nil {
		return User{}, fmt.Errorf("error looking up session: %s", err.Error())
	}

	if time.Since(session.LoginTime) > sessionExpiry {
		return User{}, fmt.Errorf("session expired")
	}

	err = a.db.UpdateUserSessionLastSeenTime(token, time.Now())
	if err != nil {
		return User{}, fmt.Errorf("error updating last seen time: %s", err.Error())
	}

	user, err := a.db.GetUserByID(session.UserID)
	if err != nil {
		return User{}, fmt.Errorf("error retrieving user: %s", err.Error())
	}

	return user.User, nil
}

func hash(password, salt []byte) string {
	hashBytes := pbkdf2.Key(password, salt, 4096, 32, sha1.New)
	return string(hashBytes)
}

func generateToken() (string, error) {
	b := make([]byte, 48)
	_, err := rand.Read(b)
	if err != nil {
		return "", fmt.Errorf("error generating random bytes: %s", err.Error())
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

func generateSalt() (string, error) {
	b := make([]byte, 48)
	_, err := rand.Read(b)
	if err != nil {
		return "", fmt.Errorf("error generating random bytes: %s", err.Error())
	}
	return base64.StdEncoding.EncodeToString(b), nil
}
