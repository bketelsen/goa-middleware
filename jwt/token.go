package jwt

import (
	"fmt"
	"time"

	"github.com/RangelReale/osin"
	"github.com/dgrijalva/jwt-go"
)

const (
	ttldefault        = 5
	refreshttldefault = 1440 // default to one day
)

// TokenManager provides for the creation of access and refresh JWT Tokens
type TokenManager struct {
	spec *Specification
}

// NewTokenManager returns a TokenManager.  If TTLMinutes isn't specified
// it will default to 5 minutes.  Use the same Specification as you use for
// Middleware() to ensure your tokens are compatible.
func NewTokenManager(spec *Specification) *TokenManager {
	if spec.TTLMinutes == 0 {
		spec.TTLMinutes = ttldefault
	}
	if spec.RefreshTTLMinutes == 0 {
		spec.RefreshTTLMinutes = refreshttldefault
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
	bytes, err := tm.spec.SigningKeyFunc()
	if err != nil {
		return "", fmt.Errorf("Error retrieving Signing Key: %v", err)
	}
	return t.SignedString(bytes)

}

// GenerateAuthorizeToken satisfies the AuthorizeTokenGen interface for RangelReale/osin
// So that osin may be used for storage and token generation.  GenerateAuthorizeToken
// returns an access token
func (tm *TokenManager) GenerateAuthorizeToken(data *osin.AuthorizeData) (string, error) {

	t := jwt.New(jwt.GetSigningMethod(signingmethods[tm.spec.KeySigningMethod]))
	if tm.spec.Issuer != "" {
		t.Claims["iss"] = tm.spec.Issuer
	}

	for k, v := range tm.spec.CommonClaims {
		t.Claims[k] = v
	}
	t.Claims["scopes"] = data.Scope
	// set issued at time
	t.Claims["iat"] = data.CreatedAt.Unix()
	// set the expire time
	t.Claims["exp"] = time.Now().Add(time.Second * time.Duration(data.ExpiresIn)).Unix()
	bytes, err := tm.spec.SigningKeyFunc()
	if err != nil {
		return "", fmt.Errorf("Error retrieving Signing Key: %v", err)
	}
	return t.SignedString(bytes)

}

// GenerateAccessToken satisfies the AuthorizeTokenGen interface for RangelReale/osin
// So that osin may be used for storage and token generation.  GenerateAccessToken
// creates both an access token and a refresh token.
func (tm *TokenManager) GenerateAccessToken(data *osin.AccessData, generaterefresh bool) (accesstoken string, refreshtoken string, err error) {
	t := jwt.New(jwt.GetSigningMethod(signingmethods[tm.spec.KeySigningMethod]))
	if tm.spec.Issuer != "" {
		t.Claims["iss"] = tm.spec.Issuer
	}

	for k, v := range tm.spec.CommonClaims {
		t.Claims[k] = v
	}
	t.Claims["scopes"] = data.Scope
	// set issued at time
	t.Claims["iat"] = data.CreatedAt.Unix()
	// set the expire time
	t.Claims["exp"] = time.Now().Add(time.Second * time.Duration(data.ExpiresIn)).Unix()
	bytes, err := tm.spec.SigningKeyFunc()
	if err != nil {
		return "", "", fmt.Errorf("Error retrieving Signing Key: %v", err)
	}
	accesstoken, err = t.SignedString(bytes)
	if err != nil {
		return "", "", err
	}
	r := jwt.New(jwt.GetSigningMethod(signingmethods[tm.spec.KeySigningMethod]))
	if tm.spec.Issuer != "" {
		r.Claims["iss"] = tm.spec.Issuer
	}

	for k, v := range tm.spec.CommonClaims {
		r.Claims[k] = v
	}
	r.Claims["scopes"] = data.Scope
	// set issued at time
	r.Claims["iat"] = data.CreatedAt.Unix()
	// set the expire time
	r.Claims["exp"] = time.Now().Add(time.Minute * time.Duration(tm.spec.RefreshTTLMinutes)).Unix()
	bytes, err = tm.spec.SigningKeyFunc()
	if err != nil {
		return "", "", fmt.Errorf("Error retrieving Signing Key: %v", err)
	}
	refreshtoken, err = r.SignedString(bytes)
	return accesstoken, refreshtoken, err
}
