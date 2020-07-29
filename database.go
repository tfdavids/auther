package auther

import (
	"database/sql"
	"fmt"
	"time"
)

type AuthDatabase interface {
	AddUser(username, fullName, passwordHash, passwordSalt string, isDisabled bool) (userRow, error)
	GetUser(username string) (userRow, error)
	GetUserByID(userID UserID) (userRow, error)
	CreateUserSession(token string, userID UserID, loginTime time.Time, lastSeenTime time.Time) error
	GetUserSession(token string) (UserSession, error)
	UpdateUserSessionLastSeenTime(token string, lastSeenTime time.Time) error
	RemoveUserSession(token string) error
}

type inMemoryAuthDatabase struct {
	nextID       int
	users        []userRow
	userSessions []UserSession
}

func NewInMemoryAuthDatabase() AuthDatabase {
	return &inMemoryAuthDatabase{
		nextID:       0,
		users:        []userRow{},
		userSessions: []UserSession{},
	}
}

func (db *inMemoryAuthDatabase) AddUser(username, fullName, passwordHash, passwordSalt string, isDisabled bool) (userRow, error) {
	for _, u := range db.users {
		if u.Username == username {
			return userRow{}, fmt.Errorf("username already in use")
		}
	}

	u := userRow{
		User: User{
			ID:       UserID(db.nextID),
			Username: username,
			FullName: fullName,
		},
		PasswordHash: passwordHash,
		PasswordSalt: passwordSalt,
		IsDisabled:   isDisabled,
	}

	db.users = append(db.users, u)
	db.nextID++

	return u, nil
}

func (db *inMemoryAuthDatabase) GetUser(username string) (userRow, error) {
	for _, u := range db.users {
		if u.Username == username {
			return u, nil
		}
	}

	return userRow{}, fmt.Errorf("user not found")
}

func (db *inMemoryAuthDatabase) GetUserByID(userID UserID) (userRow, error) {
	for _, u := range db.users {
		if u.ID == userID {
			return u, nil
		}
	}

	return userRow{}, fmt.Errorf("user not found")
}

func (db *inMemoryAuthDatabase) CreateUserSession(token string, userID UserID, loginTime time.Time, lastSeenTime time.Time) error {
	s := UserSession{
		SessionKey:   token,
		UserID:       userID,
		LoginTime:    loginTime,
		LastSeenTime: lastSeenTime,
	}

	db.userSessions = append(db.userSessions, s)

	return nil
}

func (db *inMemoryAuthDatabase) GetUserSession(token string) (UserSession, error) {
	for _, s := range db.userSessions {
		if s.SessionKey == token {
			return s, nil
		}
	}

	return UserSession{}, fmt.Errorf("user session not found")
}

func (db *inMemoryAuthDatabase) UpdateUserSessionLastSeenTime(token string, lastSeenTime time.Time) error {
	for i, s := range db.userSessions {
		if s.SessionKey == token {
			db.userSessions[i].LastSeenTime = lastSeenTime
			return nil
		}
	}

	return fmt.Errorf("user session not found")
}

func (db *inMemoryAuthDatabase) RemoveUserSession(token string) error {
	for i, s := range db.userSessions {
		if s.SessionKey == token {
			db.userSessions = append(db.userSessions[:i], db.userSessions[i+1:]...)
			return nil
		}
	}

	return fmt.Errorf("user session not found")
}

type psqlAuthDatabase struct {
	db *sql.DB
}

func NewPSQLAuthDatabase(db *sql.DB) (AuthDatabase, error) {
	_, err := db.Query(`CREATE TABLE IF NOT EXISTS users (
		id serial,
		username text NOT NULL,
		fullname text NOT NULL,
		passwordhash bytea NOT NULL,
		passwordsalt bytea NOT NULL,
		isdisabled bool NOT NULL
	)`)
	if err != nil {
		return &psqlAuthDatabase{}, fmt.Errorf("failed to create users table: %s", err.Error())
	}

	_, err = db.Query(`CREATE TABLE IF NOT EXISTS usersessions (
		sessionkey text NOT NULL,
		userid int NOT NULL,
		logintime int NOT NULL,
		lastseentime int NOT NULL
	)`)
	if err != nil {
		return &psqlAuthDatabase{}, fmt.Errorf("failed to create user sessions table: %s", err.Error())
	}

	return &psqlAuthDatabase{
		db: db,
	}, nil
}

func (p *psqlAuthDatabase) AddUser(username, fullName, passwordHash, passwordSalt string, isDisabled bool) (userRow, error) {
	var id int

	row := p.db.QueryRow("INSERT INTO users(username, fullname, passwordhash, passwordsalt, isdisabled) VALUES($1, $2, $3, $4, $5) RETURNING id", username, fullName, []byte(passwordHash), []byte(passwordSalt), isDisabled)

	err := row.Scan(&id)
	if err != nil {
		return userRow{}, fmt.Errorf("error creating user: %s", err.Error())
	}

	return p.GetUser(username)
}

func (p *psqlAuthDatabase) GetUser(username string) (userRow, error) {
	var result userRow

	row := p.db.QueryRow("SELECT id, username, fullname, passwordhash, passwordsalt, isdisabled FROM users WHERE username = $1", username)
	err := row.Scan(&result.ID, &result.Username, &result.FullName, &result.PasswordHash, &result.PasswordSalt, &result.IsDisabled)
	if err != nil {
		return userRow{}, fmt.Errorf("error retrieving user: %s", err.Error())
	}

	return result, nil
}

func (p *psqlAuthDatabase) GetUserByID(userID UserID) (userRow, error) {
	var result userRow

	row := p.db.QueryRow("SELECT id, username, fullname, passwordhash, passwordsalt, isdisabled FROM users WHERE id = $1", userID)
	err := row.Scan(&result.ID, &result.Username, &result.FullName, &result.PasswordHash, &result.PasswordSalt, &result.IsDisabled)
	if err != nil {
		return userRow{}, fmt.Errorf("error retrieving user: %s", err.Error())
	}

	return result, nil
}

func (p *psqlAuthDatabase) CreateUserSession(token string, userID UserID, loginTime time.Time, lastSeenTime time.Time) error {
	_, err := p.db.Exec("INSERT INTO usersessions(sessionkey, userid, logintime, lastseentime) VALUES($1, $2, $3, $4)", token, userID, loginTime.Unix(), lastSeenTime.Unix())

	if err != nil {
		return fmt.Errorf("error creating user: %s", err.Error())
	}

	return nil
}

func (p *psqlAuthDatabase) GetUserSession(token string) (UserSession, error) {
	var loginTime int64
	var lastSeenTime int64
	var result UserSession

	row := p.db.QueryRow("SELECT sessionkey, userid, logintime, lastseentime FROM usersessions WHERE sessionkey = $1", token)
	err := row.Scan(&result.SessionKey, &result.UserID, &loginTime, &lastSeenTime)
	if err != nil {
		return UserSession{}, fmt.Errorf("error retrieving user session: %s", err.Error())
	}

	result.LoginTime = time.Unix(loginTime, 0)
	result.LastSeenTime = time.Unix(lastSeenTime, 0)

	return result, nil
}

func (p *psqlAuthDatabase) UpdateUserSessionLastSeenTime(token string, lastSeenTime time.Time) error {
	_, err := p.db.Exec("UPDATE usersessions SET lastseentime = $1 WHERE sessionkey = $2", lastSeenTime.Unix(), token)

	if err != nil {
		return fmt.Errorf("error updating last seen time: %s", err.Error())
	}

	return nil
}

func (p *psqlAuthDatabase) RemoveUserSession(token string) error {
	_, err := p.db.Exec("DELETE FROM usersessions WHERE sessionkey = $1", token)

	if err != nil {
		return fmt.Errorf("error deleting session: %s", err.Error())
	}

	return nil
}
