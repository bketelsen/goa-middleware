package jwt

import (
	"fmt"
	"net/http"
	"strings"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/raphael/goa"
)

// SigningMethod is the enum that lists the supported token signature hashing algorithms.
type SigningMethod int

const (
	_                    = iota
	RSA256 SigningMethod = iota + 1
	RSA384
	RSA512
	HMAC256
	HMAC384
	HMAC512
	ECDSA256
	ECDSA384
	ECDSA512
)

var signingmethods map[SigningMethod]string

func init() {
	signingmethods = make(map[SigningMethod]string)

	signingmethods[RSA256] = "RS256"
	signingmethods[RSA384] = "RS512"
	signingmethods[RSA512] = "RS512"
	signingmethods[HMAC256] = "HS256"
	signingmethods[HMAC384] = "HS384"
	signingmethods[HMAC512] = "HS512"
	signingmethods[ECDSA256] = "ES256"
	signingmethods[ECDSA384] = "ES384"
	signingmethods[ECDSA512] = "ES512"
}

// JWTKey is the JWT middleware key used to store the token in the context.
const JWTKey middlewareKey = 0

// JWTKey is the JWT middleware key used to store the token in the context.
const TokenManagerKey middlewareKey = 1

// JWTHeader is the name of the header used to transmit the JWT token.
const JWTHeader = "Authorization"

// ValidationKeyfunc is a function that takes a token and returns the key to validate that
// token, which allows it to use inforamtion from the key itself to choose the key
// to return.
type ValidationKeyfunc func(*jwt.Token) (interface{}, error)

func keyFuncWrapper(k ValidationKeyfunc) jwt.Keyfunc {
	return func(tok *jwt.Token) (interface{}, error) {
		return k(tok)
	}
}

// KeyFunc is a function that returns the key to sign a
// token.  It should return a []byte (for all)
// or a *rsa.PrivateKey or *ecdsa.PrivateKey
type KeyFunc func() (interface{}, error)

// Specification describes the JWT authorization properties.
// It is used to both instantiate a middleware and a token manager.
// The middleware uses the specification properties to authorize the incoming
// request while the token manager uses it to create authorization tokens.
type Specification struct {
	// TokenHeader is the HTTP header to search for the JWT Token
	// Defaults to "Authorization"
	TokenHeader string
	// TokenParam is the request parameter to parse for the JWT Token
	// Defaults to "token"
	TokenParam string
	// AllowParam is a flag that determines whether it is allowable
	// to parse tokens from the querystring
	// Defaults to false
	AllowParam bool
	// ValidationFunc is a function that returns the key to validate the JWT
	// Required, no default
	ValidationFunc ValidationKeyfunc
	// AuthOptions is a flag that determines whether a token is required on OPTIONS
	// requests
	AuthOptions bool
	// TTLMinutes is the TTL for tokens that are generated
	TTLMinutes int
	// Issuer is the name of the issuer that will be inserted into the
	// generated token's claims
	Issuer string
	// KeySigningMethod determines the type of key that will be used to sign
	// Tokens.
	KeySigningMethod SigningMethod
	// SigningKeyFunc is a function that retu
	SigningKeyFunc KeyFunc
	// CommonClaims is a list of claims added to all tokens issued
	CommonClaims map[string]interface{}
}

// Middleware is a middleware that retrieves a JWT token from the request if present and
// injects it into the context.  It checks for the token in the HTTP Headers first, then the querystring if
// the specification "AllowParam" is true.
// Retrieve it using ctx.Value(JWTKey).
func Middleware(spec *Specification) goa.Middleware {
	if spec.TokenHeader == "" {
		spec.TokenHeader = "Authorization"
	}
	if spec.TokenParam == "" {
		spec.TokenParam = "token"
	}
	return func(h goa.Handler) goa.Handler {
		return func(ctx *goa.Context) error {
			// If AuthOptions is false, and this is an OPTIONS request
			// just let the request fly
			if !spec.AuthOptions && ctx.Request().Method == "OPTIONS" {
				return h(ctx)
			}

			var found bool
			var token string
			header := ctx.Request().Header.Get(spec.TokenHeader)

			if header != "" {
				parts := strings.Split(header, " ")
				if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
					// This is an error
				}
				token = parts[1]
				found = true
			}
			if !found && spec.AllowParam {
				token = ctx.Request().URL.Query().Get(spec.TokenParam)

			}

			if token == "" {
				err := ctx.Respond(http.StatusUnauthorized, []byte(http.StatusText(http.StatusUnauthorized)))
				return err
			}
			parsed, err := jwt.Parse(token, keyFuncWrapper(spec.ValidationFunc))
			if err != nil {
				msg := fmt.Sprintf("Error parsing token: %s", err.Error())
				err = ctx.Respond(http.StatusUnauthorized, []byte(msg))
				return err
			}
			if parsed.Valid {
				ctx.SetValue(JWTKey, parsed)
			} else {
				msg := "Invalid Token"
				err = ctx.Respond(http.StatusUnauthorized, []byte(msg))
				return err
			}

			return h(ctx)
		}

	}
}
