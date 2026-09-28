package socks5

import (
	"crypto/subtle"
)

// CredentialStore is used to support user/pass authentication
type CredentialStore interface {
	Valid(user, password string) bool
}

// StaticCredentials enables using a map directly as a credential store
type StaticCredentials map[string]string

// staticCredentialsDummyPass is compared against when the user is unknown,
// so that known and unknown users take a comparable amount of time to
// reject and the user list cannot be enumerated via timing.
var staticCredentialsDummyPass = "go-socks5-dummy-password-32-bytes!!"

func (s StaticCredentials) Valid(user, password string) bool {
	pass, ok := s[user]
	if !ok {
		subtle.ConstantTimeCompare([]byte(password), []byte(staticCredentialsDummyPass))
		return false
	}
	return subtle.ConstantTimeCompare([]byte(password), []byte(pass)) == 1
}
