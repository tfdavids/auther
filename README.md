# Auther

Auther is a Go library to handle user authentication, i.e. registration, login, and logout.

# Usage

## Interface

```
type Authenticator interface {
	Signup(fullname, username, password string) (string, error)
	Signin(username, password string) (string, error)
	Signout(token string) error
	Authenticate(token string) (User, error)
}

type User struct {
	ID       UserID `json:"id"`
	Username string `json:"username"`
	FullName string `json:"fullname"`
}
```

## Example

```
import auther "github.com/tfdavids/auther"

func main() {
  // db := ...
  
  a, err := auther.NewPSQLAuthenticator(db)
  if err != nil {
    // handle error
  }

  _, err = a.Signup("John Smith", "jsmith", "supersecretpassword")
  if err != nil {
    // handle error
  }

  // we could have kept the token above, but let's sign in here  
  token, err := a.Signin("jsmith", "supersecretpassword")
  if err != nil {
    // handle error
  }

  user, err := a.Authenticate(token)
  if err != nil {
    // handle error
  }

  err = a.Signout(token)
  if err != nil {
    // handle error
  }

  // the following will throw an error, since we've signed out
  user, err = a.Authenticate(token)
  // ...
}
```

# Security

Passwords are hashed using the [PBKDF2 algorithm](https://godoc.org/golang.org/x/crypto/pbkdf2), with 4096 iterations and a `keyLen` of 32, and the SHA1 hash function. Each password is salted with a unique 48-byte salt, which is stored in the database along with the hashed password. Plaintext passwords are never stored in the database.

Session tokens are 48-byte random strings and can be stored in local storage for persistent login.
