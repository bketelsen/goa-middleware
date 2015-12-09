package deferpanic

import (
	"net/http"

	"github.com/deferpanic/deferclient/deferstats"
	"github.com/raphael/goa"
)

// DeferPanic sets up the DeferPanic stats capture, error wrapper, panic recovery and http time
// measurement.
func DeferPanic(service goa.Service, key string) goa.Middleware {
	dps := deferstats.NewClient(key)
	errorHandler := service.ErrorHandler()
	service.SetErrorHandler(func(ctx *goa.Context, err error) {
		if _, ok := err.(*goa.BadRequestError); !ok {
			// Don't report bad requests
			dps.Wrap(err)
		}
		errorHandler(ctx, err)
	})
	go dps.CaptureStats()
	return func(h goa.Handler) goa.Handler {
		return func(ctx *goa.Context) (err error) {
			defer dps.Persist()
			dph := dps.HTTPHandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				err = h(ctx)
			})
			dph(ctx, ctx.Request())
			return
		}
	}
}
