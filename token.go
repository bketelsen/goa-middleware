package middleware

import (
	"time"

	"github.com/dgrijalva/jwt-go"
)

type TokenManager struct {
	spec *Specification
}

// NewTokenManager returns a TokenManager.  If TTLMinutes isn't specified
// it will default to 5 minutes.
func NewTokenManager(spec *Specification) *TokenManager {
	if spec.TTLMinutes != 0 {
		spec.TTLMinutes = 5
	}
	return &TokenManager{spec: spec}
}

// Create makes a new token, adding the claims provided.  It returns
// a token as a string.
func (tm *TokenManager) Create(claims map[string]interface{}) (string, error) {

	t := jwt.New(jwt.GetSigningMethod(signingmethods[tm.spec.KeySigningMethod]))

	for k, v := range claims {
		t.Claims[k] = v
	}

	if tm.spec.Issuer != "" {
		t.Claims["iss"] = tm.spec.Issuer
	}

	for k, v := range tm.spec.CommonClaims {
		t.Claims[k] = v
	}
	// set issued at time
	t.Claims["iat"] = time.Now().Unix()
	// set the expire time
	t.Claims["exp"] = time.Now().Add(time.Minute * time.Duration(tm.spec.TTLMinutes)).Unix()
	return t.SignedString(tm.spec.SigningKeyFunc)

}
