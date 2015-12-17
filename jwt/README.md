# JWT Middleware 


This package provides a [goa](http://goa.design) middleware that checks requests for valid
JWT keys.  If a key is found, it is made available in goa's context for use in the controllers.

It also includes a Token Manager which can be used to create JWT tokens that are valid for use
with the middleware.  TokenManager also implements the *TokenGen* interfaces of github.com/RangelReale/osin
so that it can be used to generate tokens for your custom osin-based Oauth2 implementation.


## Middleware Usage
Middleware can be applied at the application or service level in goa.  To use a middleware,
create an instance of it first, then apply it using the `Use` function of your application or service:
```go
	spec := &jwt.Specification{
		AllowParam:       false,
		AuthOptions:      false,
		TTLMinutes:       60,
		Issuer:           "api.me.com",
		KeySigningMethod: jwt.RSA256,
		SigningKeyFunc:   privateKey,
		ValidationFunc:   pubKey,
	}

	tm := jwt.NewTokenManager(spec)

	// Generate a test token
	claims := make(map[string]interface{})
	claims["custom"] = "hotrod"
	t, err := tm.Create(claims)
	fmt.Println(t)
	fmt.Println(err)

	// Mount "application" controller
	c := NewApplicationController(service)
	// Require a valid JWT Token for any routes
	// on this controller
	c.Use(jwt.Middleware(spec))
```

## TokenManager Usage
TokenManager uses the same specification as the JWT Middleware.  Instantiate it
with the `NewTokenManager` function: 
```go
	spec := &jwt.Specification{
		AllowParam:       false,
		AuthOptions:      false,
		TTLMinutes:       60,
		Issuer:           "api.me.com",
		KeySigningMethod: jwt.RSA256,
		SigningKeyFunc:   privateKey,
		ValidationFunc:   pubKey,
	}

	tm := jwt.NewTokenManager(spec)

	// Generate a test token
	claims := make(map[string]interface{})
	claims["custom"] = "hotrod"
	t, err := tm.Create(claims)
	fmt.Println(t)
	fmt.Println(err)
```

Generally you will want to create a custom response type to carry your token:

```go

	type LoginResponse struct {
		Token string
		...
	}

	token, err := tm.Create(...)

	resp:= &LoginResponse{
		Token = token
	}

```
