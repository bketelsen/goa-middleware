package middleware

import (
	"time"

	"github.com/dgrijalva/jwt-go"
)

type TokenSpecification struct {
	TTLMinutes int
	Issuer     string
}

type TokenManager struct {
	spec TokenSpecification
}

// NewTokenManager returns a TokenManager.  If TTLMinutes isn't specified
// it will default to 5 minutes.
func NewTokenManager(spec TokenSpecification) *TokenManager {
	if spec.TTLMinutes != 0 {
		spec.TTLMinutes = 5
	}
	return &TokenManager{spec: spec}
}
func (tm *TokenManager) Create(claims map[string]interface{}) (string, error) {
	// create a signer for hmac256
	t := jwt.New(jwt.GetSigningMethod("HS256"))

	for k, v := range claims {
		t.Claims[k] = v
	}

	if tm.spec.Issuer != "" {
		t.Claims["iss"] = tm.spec.Issuer
	}
	// set issued at time
	t.Claims["iat"] = time.Now().Unix()
	// set the expire time
	t.Claims["exp"] = time.Now().Add(time.Minute * time.Duration(tm.spec.TTLMinutes)).Unix()
	return t.SignedString(hmacTestKey)

}
