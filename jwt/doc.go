/*
Package jwt makes it possible to authorize API requests using JSON Web Tokens,
see https://jwt.io/introduction/

Middleware

The package provides a middleware that can be mounted on controllers that require authentication.
The JWT middleware is instantiated using the package Middleware function. This function accepts
a specification that describes the various properties used by the JWT signature and validation
algorithms.

	spec := &jwt.Specification{
		AllowParam:       false,      // Pass tokens in headers only
		AuthOptions:      false,      // Do not authorize OPTIONS requests
		TTLMinutes:       1440,       // Tokens are valid for 24 hours
		Issuer:           "me.com",   // me.com issued the token
		KeySigningMethod: jwt.RSA256, // Use the RSA256 hashing algorithm to sign tokens
		SigningKeyFunc:   privateKey, // privateKey returns the key used to sign tokens
		ValidationFunc:   pubKey,     // pubKey returns the key used to validate tokens
	}
	authorizedController.Use(jwt.Middleware(spec))

Token Manager

The package also exposes a token manager that creates the JWT tokens. The manager is instantiated
using the same specification used to create the middleware:

	var tm *jwt.TokenManager = jwt.NewTokenManager(spec)

	func Login(ctx *goa.Context) error {
		// ...
		// Authorize request using ctx, initialize tenant id if necessary etc.
		// ...
		claims := map[string]interface{}{
			"accountID": accountID,
		}
		token, err := tm.Create(claims)
		if err != nil {
			return err
		}
		return ctx.Respond(200, token) // You'll probably need something different here
	}

*/
package jwt
