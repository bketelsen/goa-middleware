package middleware

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/raphael/goa"
)

// JWTKey is the JWT middleware key used to store the token in the context.
const JWTKey middlewareKey = 0

// JWTHeader is the name of the header used to transmit the JWT token.
const JWTHeader = "Authorization"

// Keyfunc is a function that takes a token and returns the key to validate that
// token, which allows it to use inforamtion from the key itself to choose the key
// to return.
type Keyfunc func(*jwt.Token) (interface{}, error)

func keyFuncWrapper(k Keyfunc) jwt.Keyfunc {
	return func(tok *jwt.Token) (interface{}, error) {
		return k(tok)
	}
}

//TEMP
// Sample data from http://tools.ietf.org/html/draft-jones-json-web-signature-04#appendix-A.1
var hmacTestKey, _ = ioutil.ReadFile("test/hmacTestKey")

type JWTSpecification struct {
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
	ValidationFunc Keyfunc
	// AuthOptions is a flag that determines whether a token is required on OPTIONS
	// requests
	AuthOptions bool
}

// JWTMiddleware is a middleware that retrieves a JWT token from the request if present and
// injects it into the context.  It checks for the token in the HTTP Headers first, then the querystring if
// the specification "AllowParam" is true.
// Retrieve it using ctx.Value(JWTKey).
func JWTMiddleware(spec JWTSpecification) goa.Middleware {
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
