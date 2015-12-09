package jwt_test

import (
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	jwtg "github.com/dgrijalva/jwt-go"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/raphael/goa"
	"github.com/raphael/goa-middleware/jwt"
)

var signingKey = []byte("jwtsecretsauce")

// Sample data from http://tools.ietf.org/html/draft-jones-json-web-signature-04#appendix-A.1
var hmacTestKey, _ = ioutil.ReadFile("test/hmacTestKey")
var rsaSampleKey, _ = ioutil.ReadFile("test/sample_key")
var rsaSampleKeyPub, _ = ioutil.ReadFile("test/sample_key.pub")

var _ = Describe("JWT Middleware", func() {
	var ctx *goa.Context
	var spec *jwt.Specification
	var req *http.Request
	var err error
	var token *jwtg.Token
	var tokenString string
	params := map[string]string{"param": "value"}
	query := map[string][]string{"query": []string{"qvalue"}}
	payload := map[string]interface{}{"payload": 42}
	validFunc := func(token *jwtg.Token) (interface{}, error) {
		return signingKey, nil
	}

	BeforeEach(func() {
		req, err = http.NewRequest("POST", "/goo", strings.NewReader(`{"payload":42}`))
		Ω(err).ShouldNot(HaveOccurred())
		rw := new(TestResponseWriter)
		ctx = goa.NewContext(nil, req, rw, params, query, payload)
		spec = &jwt.Specification{
			AllowParam:     true,
			ValidationFunc: validFunc,
		}
		token = jwtg.New(jwtg.SigningMethodHS256)
		token.Claims["exp"] = time.Now().Add(time.Hour * 24).Unix()
		token.Claims["random"] = "42"
		tokenString, err = token.SignedString(signingKey)
		Ω(err).ShouldNot(HaveOccurred())
	})

	It("requires a jwt token be present", func() {

		h := func(ctx *goa.Context) error {
			ctx.JSON(200, "ok")
			return nil
		}
		jw := jwt.Middleware(spec)(h)
		Ω(jw(ctx)).ShouldNot(HaveOccurred())
		Ω(ctx.ResponseStatus()).Should(Equal(http.StatusUnauthorized))

	})

	It("returns the jwt token that was sent as a header", func() {

		req.Header.Set("Authorization", "bearer "+tokenString)
		h := func(ctx *goa.Context) error {
			ctx.JSON(200, "ok")
			return nil
		}
		jw := jwt.Middleware(spec)(h)
		Ω(jw(ctx)).ShouldNot(HaveOccurred())
		Ω(ctx.ResponseStatus()).Should(Equal(http.StatusOK))
		tok, err := jwtg.Parse(tokenString, validFunc)
		Ω(err).ShouldNot(HaveOccurred())
		Ω(ctx.Value(jwt.JWTKey)).Should(Equal(tok))
		// Are these negative tests necessary?  If the above test passes
		// this one can't pass, right?
		Ω(ctx.Value(jwt.JWTKey)).ShouldNot(Equal("bearer TOKEN"))
	})

	It("returns the custom claims", func() {

		req.Header.Set("Authorization", "bearer "+tokenString)
		h := func(ctx *goa.Context) error {
			ctx.JSON(200, "ok")
			return nil
		}
		jw := jwt.Middleware(spec)(h)
		Ω(jw(ctx)).ShouldNot(HaveOccurred())
		Ω(ctx.ResponseStatus()).Should(Equal(http.StatusOK))
		tok, err := jwtg.Parse(tokenString, validFunc)
		Ω(err).ShouldNot(HaveOccurred())
		Ω(ctx.Value(jwt.JWTKey)).Should(Equal(tok))
		ctxtok := ctx.Value(jwt.JWTKey).(*jwtg.Token)
		clms := ctxtok.Claims
		Ω(clms["random"]).Should(Equal("42"))
	})

	It("returns the jwt token that was sent as a querystring", func() {
		req, err = http.NewRequest("POST", "/goo?token="+tokenString, strings.NewReader(`{"payload":42}`))
		Ω(err).ShouldNot(HaveOccurred())
		rw := new(TestResponseWriter)
		ctx = goa.NewContext(nil, req, rw, params, query, payload)
		spec = &jwt.Specification{
			AllowParam:     true,
			ValidationFunc: validFunc,
		}
		h := func(ctx *goa.Context) error {
			ctx.JSON(200, "ok")
			return nil
		}
		jw := jwt.Middleware(spec)(h)
		Ω(jw(ctx)).ShouldNot(HaveOccurred())
		Ω(ctx.ResponseStatus()).Should(Equal(http.StatusOK))
		tok, err := jwtg.Parse(tokenString, validFunc)
		Ω(err).ShouldNot(HaveOccurred())
		Ω(ctx.Value(jwt.JWTKey)).Should(Equal(tok))
		// Are these negative tests necessary?  If the above test passes
		// this one can't pass, right?
		Ω(ctx.Value(jwt.JWTKey)).ShouldNot(Equal("TOKEN"))
	})

})
var _ = Describe("JWT Token HMAC", func() {
	var claims map[string]interface{}
	var spec *jwt.Specification
	var tm *jwt.TokenManager
	validFunc := func() (interface{}, error) {
		return hmacTestKey, nil
	}
	keyFunc := func(*jwtg.Token) (interface{}, error) {
		return hmacTestKey, nil
	}
	spec = &jwt.Specification{
		Issuer:           "goa",
		TTLMinutes:       20,
		KeySigningMethod: jwt.HMAC256,
		SigningKeyFunc:   validFunc,
	}
	tm = jwt.NewTokenManager(spec)
	BeforeEach(func() {
		claims = make(map[string]interface{})

		claims["randomstring"] = "43"

	})

	It("creates a valid token", func() {
		tok, err := tm.Create(claims)
		Ω(err).ShouldNot(HaveOccurred())
		Ω(len(tok)).ShouldNot(BeZero())
	})
	It("contains the intended claims", func() {
		tok, err := tm.Create(claims)
		Ω(err).ShouldNot(HaveOccurred())
		rettok, err := jwtg.Parse(tok, keyFunc)
		Ω(err).ShouldNot(HaveOccurred())
		rndmstring := rettok.Claims["randomstring"].(string)
		Ω(rndmstring).Should(Equal("43"))
	})

})
var _ = Describe("JWT Token RSA", func() {
	var claims map[string]interface{}
	var spec *jwt.Specification
	var tm *jwt.TokenManager
	validFunc := func() (interface{}, error) {
		return rsaSampleKey, nil
	}
	keyFunc := func(*jwtg.Token) (interface{}, error) {
		return rsaSampleKeyPub, nil
	}
	spec = &jwt.Specification{
		Issuer:           "goa",
		TTLMinutes:       20,
		KeySigningMethod: jwt.RSA256,
		SigningKeyFunc:   validFunc,
	}
	tm = jwt.NewTokenManager(spec)
	BeforeEach(func() {
		claims = make(map[string]interface{})

		claims["randomstring"] = "43"

	})

	It("creates a valid token", func() {
		tok, err := tm.Create(claims)
		Ω(err).ShouldNot(HaveOccurred())
		Ω(len(tok)).ShouldNot(BeZero())
	})
	It("contains the intended claims", func() {
		tok, err := tm.Create(claims)
		Ω(err).ShouldNot(HaveOccurred())
		rettok, err := jwtg.Parse(tok, keyFunc)
		Ω(err).ShouldNot(HaveOccurred())
		rndmstring := rettok.Claims["randomstring"].(string)
		Ω(rndmstring).Should(Equal("43"))
	})

})

type TestResponseWriter struct {
	ParentHeader http.Header
	Body         []byte
	Status       int
}

func (t *TestResponseWriter) Header() http.Header {
	return t.ParentHeader
}

func (t *TestResponseWriter) Write(b []byte) (int, error) {
	t.Body = append(t.Body, b...)
	return len(b), nil
}

func (t *TestResponseWriter) WriteHeader(s int) {
	t.Status = s
}
