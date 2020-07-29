package auther

import (
	"os"
	"testing"
)

const (
	testFullname1 = "John Smith"
	testUsername1 = "foo"
	testPassword1 = "bar"
	testPassword2 = "baz"
)

func TestSignup(t *testing.T) {
	a, err := NewInMemoryAuthenticator()
	if err != nil {
		t.Fatalf("Failed to create authenticator: %s", err.Error())
	}

	_, err = a.Signup(testFullname1, testUsername1, testPassword1)
	if err != nil {
		t.Errorf("Error signing up: %s", err.Error())
	}
}

func TestSignupFailsWithDuplicateName(t *testing.T) {
	a, err := NewInMemoryAuthenticator()
	if err != nil {
		t.Fatalf("Failed to create authenticator: %s", err.Error())
	}

	_, err = a.Signup(testFullname1, testUsername1, testPassword1)
	if err != nil {
		t.Fatalf("Error signing up: %s", err.Error())
	}

	_, err = a.Signup(testFullname1, testUsername1, testPassword2)
	if err == nil {
		t.Errorf("Failed to throw an error on duplicate username")
	}
}

func TestSignin(t *testing.T) {
	a, err := NewInMemoryAuthenticator()
	if err != nil {
		t.Fatalf("Failed to create authenticator: %s", err.Error())
	}

	_, err = a.Signup(testFullname1, testUsername1, testPassword1)
	if err != nil {
		t.Fatalf("Error signing up: %s", err.Error())
	}

	_, err = a.Signin(testUsername1, testPassword1)
	if err != nil {
		t.Errorf("Failed to sign in: %s", err.Error())
	}
}

func TestSigninFailsWhenNotRegistered(t *testing.T) {
	a, err := NewInMemoryAuthenticator()
	if err != nil {
		t.Fatalf("Failed to create authenticator: %s", err.Error())
	}

	_, err = a.Signin(testUsername1, testPassword1)
	if err == nil {
		t.Errorf("Failed to throw an error when not signed up")
	}
}

func TestSigninFailsWithWrongPassword(t *testing.T) {
	a, err := NewInMemoryAuthenticator()
	if err != nil {
		t.Fatalf("Failed to create authenticator: %s", err.Error())
	}

	_, err = a.Signup(testFullname1, testUsername1, testPassword1)
	if err != nil {
		t.Fatalf("Error signing up: %s", err.Error())
	}

	_, err = a.Signin(testUsername1, testPassword2)
	if err == nil {
		t.Errorf("Failed to reject signin with wrong password")
	}
}

func TestAuthenticate(t *testing.T) {
	a, err := NewInMemoryAuthenticator()
	if err != nil {
		t.Fatalf("Failed to create authenticator: %s", err.Error())
	}

	token, err := a.Signup(testFullname1, testUsername1, testPassword1)
	if err != nil {
		t.Fatalf("Error signing up: %s", err.Error())
	}

	_, err = a.Authenticate(token)
	if err != nil {
		t.Errorf("Error authenticating with token: %s", err.Error())
	}
}

func TestAuthenticateWithSigninToken(t *testing.T) {
	a, err := NewInMemoryAuthenticator()
	if err != nil {
		t.Fatalf("Failed to create authenticator: %s", err.Error())
	}

	_, err = a.Signup(testFullname1, testUsername1, testPassword1)
	if err != nil {
		t.Fatalf("Error signing up: %s", err.Error())
	}

	token, err := a.Signin(testUsername1, testPassword1)
	if err != nil {
		t.Fatalf("Error signing in: %s", err.Error())
	}

	_, err = a.Authenticate(token)
	if err != nil {
		t.Fatalf("Error authenticating with token: %s", err.Error())
	}
}

func TestAuthenticateFailsWithMissingToken(t *testing.T) {
	a, err := NewInMemoryAuthenticator()
	if err != nil {
		t.Fatalf("Failed to create authenticator: %s", err.Error())
	}

	_, err = a.Signup(testFullname1, testUsername1, testPassword1)
	if err != nil {
		t.Fatalf("Error signing up: %s", err.Error())
	}

	_, err = a.Authenticate("")
	if err == nil {
		t.Errorf("No error when authenticating with missing token")
	}
}

func TestSignout(t *testing.T) {
	a, err := NewInMemoryAuthenticator()
	if err != nil {
		t.Fatalf("Failed to create authenticator: %s", err.Error())
	}

	token, err := a.Signup(testFullname1, testUsername1, testPassword1)
	if err != nil {
		t.Fatalf("Error signing up: %s", err.Error())
	}

	err = a.Signout(token)
	if err != nil {
		t.Errorf("Error signing out: %s", err.Error())
	}
}

func TestSignoutFailsWithInvalidToken(t *testing.T) {
	a, err := NewInMemoryAuthenticator()
	if err != nil {
		t.Fatalf("Failed to create authenticator: %s", err.Error())
	}

	err = a.Signout("")
	if err == nil {
		t.Errorf("Failed to throw error when signing out with invalid token")
	}
}

func TestAuthenticateFailsAfterSignout(t *testing.T) {
	a, err := NewInMemoryAuthenticator()
	if err != nil {
		t.Fatalf("Failed to create authenticator: %s", err.Error())
	}

	token, err := a.Signup(testFullname1, testUsername1, testPassword1)
	if err != nil {
		t.Fatalf("Error signing up: %s", err.Error())
	}

	err = a.Signout(token)
	if err != nil {
		t.Fatalf("Error signing out: %s", err.Error())
	}

	_, err = a.Authenticate(token)
	if err == nil {
		t.Errorf("No error when authenticating with signed-out token")
	}
}

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
