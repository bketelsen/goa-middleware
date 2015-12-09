package jwt_test

import (
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/raphael/goa"
)

var signingKey = []byte("jwtsecretsauce")

// Sample data from http://tools.ietf.org/html/draft-jones-json-web-signature-04#appendix-A.1
var hmacTestKey, _ = ioutil.ReadFile("test/hmacTestKey")

var _ = Describe("JWT Middleware", func() {
	var ctx *goa.Context
	var spec middleware.JWTSpecification
	var req *http.Request
	var err error
	var token *jwt.Token
	var tokenString string
	params := map[string]string{"param": "value"}
	query := map[string][]string{"query": []string{"qvalue"}}
	payload := map[string]interface{}{"payload": 42}
	validFunc := func(token *jwt.Token) (interface{}, error) {
		return signingKey, nil
	}

	BeforeEach(func() {
		req, err = http.NewRequest("POST", "/goo", strings.NewReader(`{"payload":42}`))
		Ω(err).ShouldNot(HaveOccurred())
		rw := new(TestResponseWriter)
		ctx = goa.NewContext(nil, req, rw, params, query, payload)
		spec = middleware.JWTSpecification{
			AllowParam:     true,
			ValidationFunc: validFunc,
		}
		token = jwt.New(jwt.SigningMethodHS256)
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
		jw := middleware.JWTMiddleware(spec)(h)
		Ω(jw(ctx)).ShouldNot(HaveOccurred())
		Ω(ctx.ResponseStatus()).Should(Equal(http.StatusUnauthorized))

	})

	It("returns the jwt token that was sent as a header", func() {

		req.Header.Set("Authorization", "bearer "+tokenString)
		h := func(ctx *goa.Context) error {
			ctx.JSON(200, "ok")
			return nil
		}
		jw := middleware.JWTMiddleware(spec)(h)
		Ω(jw(ctx)).ShouldNot(HaveOccurred())
		Ω(ctx.ResponseStatus()).Should(Equal(http.StatusOK))
		tok, err := jwt.Parse(tokenString, validFunc)
		Ω(err).ShouldNot(HaveOccurred())
		Ω(ctx.Value(middleware.JWTKey)).Should(Equal(tok))
		// Are these negative tests necessary?  If the above test passes
		// this one can't pass, right?
		Ω(ctx.Value(middleware.JWTKey)).ShouldNot(Equal("bearer TOKEN"))
	})

	It("returns the custom claims", func() {

		req.Header.Set("Authorization", "bearer "+tokenString)
		h := func(ctx *goa.Context) error {
			ctx.JSON(200, "ok")
			return nil
		}
		jw := middleware.JWTMiddleware(spec)(h)
		Ω(jw(ctx)).ShouldNot(HaveOccurred())
		Ω(ctx.ResponseStatus()).Should(Equal(http.StatusOK))
		tok, err := jwt.Parse(tokenString, validFunc)
		Ω(err).ShouldNot(HaveOccurred())
		Ω(ctx.Value(middleware.JWTKey)).Should(Equal(tok))
		ctxtok := ctx.Value(middleware.JWTKey).(*jwt.Token)
		clms := ctxtok.Claims
		Ω(clms["random"]).Should(Equal("42"))
	})

	It("returns the jwt token that was sent as a querystring", func() {
		req, err = http.NewRequest("POST", "/goo?token="+tokenString, strings.NewReader(`{"payload":42}`))
		Ω(err).ShouldNot(HaveOccurred())
		rw := new(TestResponseWriter)
		ctx = goa.NewContext(nil, req, rw, params, query, payload)
		spec = middleware.JWTSpecification{
			AllowParam:     true,
			ValidationFunc: validFunc,
		}
		h := func(ctx *goa.Context) error {
			ctx.JSON(200, "ok")
			return nil
		}
		jw := middleware.JWTMiddleware(spec)(h)
		Ω(jw(ctx)).ShouldNot(HaveOccurred())
		Ω(ctx.ResponseStatus()).Should(Equal(http.StatusOK))
		tok, err := jwt.Parse(tokenString, validFunc)
		Ω(err).ShouldNot(HaveOccurred())
		Ω(ctx.Value(middleware.JWTKey)).Should(Equal(tok))
		// Are these negative tests necessary?  If the above test passes
		// this one can't pass, right?
		Ω(ctx.Value(middleware.JWTKey)).ShouldNot(Equal("TOKEN"))
	})

})
var _ = Describe("JWT Token", func() {
	var claims map[string]interface{}
	var spec middleware.TokenSpecification
	var tm *middleware.TokenManager
	validFunc := func(token *jwt.Token) (interface{}, error) {
		return hmacTestKey, nil
	}
	spec = middleware.TokenSpecification{
		Issuer:         "goa",
		TTLMinutes:     20,
		SigningKeyFunc: validFunc,
	}
	tm = middleware.NewTokenManager(spec)
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
		rettok, err := jwt.Parse(tok, validFunc)
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
