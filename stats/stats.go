package stats

import (
	"fmt"
	"time"

	"github.com/armon/go-metrics"
	"github.com/raphael/goa"
)

// Reporter is a middleware that reports statistics to any sink
// supported by github.com/armon/go-metrics, which currently
// includes statsd, prometheus and others
func Reporter(sink metrics.MetricSink) goa.Middleware {
	return func(h goa.Handler) goa.Handler {
		return func(ctx *goa.Context) error {
			start := time.Now()
			err := h(ctx)
			r := ctx.Request()
			key := fmt.Sprintf("%s_%s", r.Method, r.URL.String())
			metrics.MeasureSince([]string{key}, start)
			return err
		}

	}

}
