package technitium

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"log/slog"
)

var _ http.RoundTripper = (*LoggedTransport)(nil)

type LoggedTransport struct {
	base     http.RoundTripper
	logger   *slog.Logger
	maxBytes int
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

// WithMaxBodyBytes caps the number of bytes copied from each body (0 = unlimited).
func WithMaxBodyBytes(n int) Option {
	return func(t *LoggedTransport) {
		if n >= 0 {
			t.maxBytes = n
		}
	}
}

// New creates a Transport with the provided options.
// Defaults: http.DefaultTransport, slog.Default(), 0 body cap.
func NewLoggedTransport(opts ...Option) *LoggedTransport {
	t := &LoggedTransport{
		base:     http.DefaultTransport,
		logger:   slog.Default(),
		maxBytes: 0,
	}
	for _, o := range opts {
		o(t)
	}
	return t
}

func (t *LoggedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if !t.logger.Handler().Enabled(req.Context(), slog.LevelDebug) {
		return t.base.RoundTrip(req)
	}

	start := time.Now()

	reqBodyBytes, newReqBody, _ := grab(req.Body, t.maxBytes)
	req.Body = newReqBody

	resp, err := t.base.RoundTrip(req)
	elapsed := time.Since(start)

	if err != nil {
		t.logger.DebugContext(req.Context(),
			"http request error",
			"method", req.Method,
			"url", req.URL.String(),
			"err", err,
			"duration", elapsed,
			"req_body", asValue(req.Header, reqBodyBytes),
		)
		return nil, err
	}

	respBodyBytes, newRespBody, _ := grab(resp.Body, t.maxBytes)
	resp.Body = newRespBody

	t.logger.DebugContext(req.Context(),
		"http request",
		"method", req.Method,
		"url", req.URL.String(),
		"status", resp.StatusCode,
		"duration", elapsed,
		"req_headers", req.Header,
		"resp_headers", resp.Header,
		"req_body", asValue(req.Header, reqBodyBytes),
		"resp_body", asValue(resp.Header, respBodyBytes),
	)

	return resp, nil
}

// grab copies up to n bytes from rc, returns (data, replacement, readErrNonEOF).
func grab(rc io.ReadCloser, n int) ([]byte, io.ReadCloser, error) {
	if rc == nil {
		return nil, rc, nil
	}
	defer rc.Close()

	var buf bytes.Buffer
	var err error
	if n <= 0 {
		_, err = io.Copy(&buf, rc)
	} else {
		_, err = io.CopyN(&buf, rc, int64(n))
		_, _ = io.Copy(io.Discard, rc) // drain rest
	}
	if err != nil && err != io.EOF {
		return nil, nil, err
	}

	return buf.Bytes(), io.NopCloser(bytes.NewReader(buf.Bytes())), nil
}

// asValue decides how to represent the body in logs.
//
// If the header advertises JSON (application/json or +json) and the
// body parses, the parsed value is returned; otherwise the raw string.
func asValue(h http.Header, body []byte) any {
	if len(body) == 0 {
		return ""
	}

	ct := h.Get("Content-Type")
	if isJSONContentType(ct) {
		var v any
		if err := json.Unmarshal(body, &v); err == nil {
			return v // structured
		}
	}
	return string(body) // fallback
}

// isJSONContentType reports true for application/json or */*+json.
func isJSONContentType(ct string) bool {
	ct = strings.ToLower(ct)
	return strings.Contains(ct, "application/json") || strings.HasSuffix(ct, "+json")
}
