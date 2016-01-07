package gzip_test

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/url"
	"strings"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/raphael/goa"
	gzm "github.com/raphael/goa-middleware/gzip"
	"gopkg.in/inconshreveable/log15.v2"
)

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

var _ = Describe("Gzip", func() {
	var handler *testHandler
	var ctx *goa.Context
	var req *http.Request
	var rw *TestResponseWriter
	params := url.Values{"param": []string{"value"}}
	payload := map[string]interface{}{"payload": 42}

	BeforeEach(func() {
		var err error
		req, err = http.NewRequest("POST", "/foo/bar", strings.NewReader(`{"payload":42}`))
		req.Header.Set("Accept-Encoding", "gzip")
		Ω(err).ShouldNot(HaveOccurred())
		rw = &TestResponseWriter{
			ParentHeader: http.Header{},
		}

		ctx = goa.NewContext(nil, req, rw, params, payload)
		handler = new(testHandler)
		logger := log15.New("test", "test")
		logger.SetHandler(handler)
		ctx.Logger = logger
	})

	It("encodes response using gzip", func() {
		h := func(ctx *goa.Context) error {
			ctx.Write([]byte("gzip me!"))
			ctx.WriteHeader(http.StatusOK)
			return nil
		}
		t := gzm.Middleware(gzip.BestCompression)(h)
		err := t(ctx)
		Ω(err).ShouldNot(HaveOccurred())
		Ω(ctx.ResponseStatus()).Should(Equal(http.StatusOK))

		gzr, err := gzip.NewReader(bytes.NewReader(rw.Body))
		Ω(err).ShouldNot(HaveOccurred())
		buf := bytes.NewBuffer(nil)
		io.Copy(buf, gzr)
		Ω(err).ShouldNot(HaveOccurred())
		Ω(buf.String()).Should(Equal("gzip me!"))
	})

})

type testHandler struct {
	Records []*log15.Record
}

func (t *testHandler) Log(r *log15.Record) error {
	t.Records = append(t.Records, r)
	return nil
}
