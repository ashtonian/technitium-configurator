package technitium

import (
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var _ http.RoundTripper = (*LoggedTransport)(nil)

// LoggedTransport logs each request's method, path, status and duration at
// debug level. Bodies are never logged: they carry passwords, tokens, TSIG
// secrets and app credentials.
type LoggedTransport struct {
	base   http.RoundTripper
	logger *slog.Logger
}

type Option func(*LoggedTransport)

// WithBaseTransport overrides the underlying RoundTripper.
func WithBaseTransport(rt http.RoundTripper) Option {
	return func(t *LoggedTransport) {
		if rt != nil {
			t.base = rt
		}
	}
}

// WithLogger sets a custom slog.Logger.
func WithLogger(l *slog.Logger) Option {
	return func(t *LoggedTransport) {
		if l != nil {
			t.logger = l
		}
	}
}

// NewLoggedTransport returns a transport over http.DefaultTransport that logs
// to slog.Default().
func NewLoggedTransport(opts ...Option) *LoggedTransport {
	t := &LoggedTransport{
		base:   http.DefaultTransport,
		logger: slog.Default(),
	}
	for _, o := range opts {
		o(t)
	}
	return t
}

func (t *LoggedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if !t.logger.Enabled(req.Context(), slog.LevelDebug) {
		return t.base.RoundTrip(req)
	}

	start := time.Now()
	resp, err := t.base.RoundTrip(req)
	attrs := []any{
		"method", req.Method,
		"path", req.URL.Path,
		"query", redactQuery(req.URL.Query()),
		"duration", time.Since(start),
	}
	if err != nil {
		t.logger.DebugContext(req.Context(), "http request failed", append(attrs, "error", err)...)
		return nil, err
	}
	t.logger.DebugContext(req.Context(), "http request", append(attrs, "status", resp.StatusCode)...)
	return resp, nil
}

// secretParams are parameter names whose values must never be logged. The
// client sends these in form bodies, so this only guards against misuse.
var secretParams = map[string]bool{
	"token":               true,
	"pass":                true,
	"newpass":             true,
	"password":            true,
	"primarynodepassword": true,
	"proxypassword":       true,
	"sharedsecret":        true,
	"totp":                true,
}

func redactQuery(q url.Values) string {
	for k := range q {
		if secretParams[strings.ToLower(k)] {
			q.Set(k, "REDACTED")
		}
	}
	return q.Encode()
}
