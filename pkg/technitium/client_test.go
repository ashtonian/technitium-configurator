package technitium

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type seenRequest struct {
	method, path, rawQuery, auth, body string
}

func newTestServer(t *testing.T, reply func(path string) string) (*Client, *[]seenRequest) {
	t.Helper()
	var seen []seenRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		seen = append(seen, seenRequest{r.Method, r.URL.Path, r.URL.RawQuery, r.Header.Get("Authorization"), string(body)})
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, reply(r.URL.Path))
	}))
	t.Cleanup(srv.Close)

	c, err := NewClient(&ClientConfig{APIURL: srv.URL, Timeout: 5 * time.Second})
	require.NoError(t, err)
	return c, &seen
}

func TestCredentialsStayOutOfURLs(t *testing.T) {
	c, seen := newTestServer(t, func(path string) string {
		if path == "/api/user/login" {
			return `{"status":"ok","token":"session-token"}`
		}
		return `{"status":"ok","response":{}}`
	})
	ctx := context.Background()

	require.NoError(t, c.Login(ctx, "admin", "s3cret", ""))
	require.NoError(t, c.ChangePassword(ctx, "s3cret", "n3w"))
	require.NoError(t, c.SetDNSSettings(ctx, &DnsSettings{EnableBlocking: ptr(false)}))

	require.Len(t, *seen, 3)
	for _, r := range *seen {
		assert.Equal(t, http.MethodPost, r.method, r.path)
		assert.Empty(t, r.rawQuery, "%s must not carry a query string", r.path)
	}
	login, change, settings := (*seen)[0], (*seen)[1], (*seen)[2]

	form, err := url.ParseQuery(login.body)
	require.NoError(t, err)
	assert.Equal(t, "s3cret", form.Get("pass"))
	assert.Empty(t, login.auth)

	assert.Equal(t, "Bearer session-token", change.auth)
	form, err = url.ParseQuery(change.body)
	require.NoError(t, err)
	assert.Equal(t, "n3w", form.Get("newPass"))

	assert.Equal(t, "Bearer session-token", settings.auth)
	assert.JSONEq(t, `{"enableBlocking":false}`, settings.body)
}

func TestAPIErrorClassification(t *testing.T) {
	tests := []struct {
		reply  string
		target error
	}{
		{`{"status":"error","errorMessage":"Zone already exists: example.test"}`, ErrAlreadyExists},
		{`{"status":"error","errorMessage":"Cannot add record: record already exists."}`, ErrAlreadyExists},
		{`{"status":"error","errorMessage":"DNS application already exists: NO DATA"}`, ErrAlreadyExists},
		{`{"status":"error","errorMessage":"Record already exists. Use overwrite option if you wish to overwrite existing record."}`, ErrSingletonRecordExists},
		{`{"status":"invalid-token","errorMessage":"Invalid token or session expired."}`, ErrInvalidToken},
		{`{"status":"2fa-required","errorMessage":"A time-based one-time password (TOTP) is required."}`, ErrTwoFactorRequired},
	}
	for _, tt := range tests {
		t.Run(tt.target.Error(), func(t *testing.T) {
			c, _ := newTestServer(t, func(string) string { return tt.reply })
			_, err := c.ListZones(context.Background())
			require.Error(t, err)
			assert.ErrorIs(t, err, tt.target)

			var apiErr *APIError
			require.ErrorAs(t, err, &apiErr)
			assert.Equal(t, "/api/zones/list", apiErr.Endpoint)
		})
	}

	c, _ := newTestServer(t, func(string) string {
		return `{"status":"error","errorMessage":"No reverse zone available to add PTR record."}`
	})
	_, err := c.AddRecord(context.Background(), AddRecordRequest{Domain: "www.example.test", Type: RT_A, IPAddress: "192.0.2.1"})
	require.Error(t, err)
	assert.False(t, errors.Is(err, ErrAlreadyExists), "a real failure must not look like a skip")
	assert.False(t, errors.Is(err, ErrSingletonRecordExists))
}

func TestTokenUserUsesGivenToken(t *testing.T) {
	c, seen := newTestServer(t, func(string) string {
		return `{"status":"ok","username":"admin","token":"stored"}`
	})
	c.SetToken("session")
	user, err := c.TokenUser(context.Background(), "stored")
	require.NoError(t, err)
	assert.Equal(t, "admin", user)
	assert.Equal(t, "Bearer stored", (*seen)[0].auth)
}

func TestTransportErrorOmitsURL(t *testing.T) {
	c, err := NewClient(&ClientConfig{APIURL: "http://127.0.0.1:1", Timeout: time.Second})
	require.NoError(t, err)
	_, err = c.GetRecords(context.Background(), "secret-name.example.test", "")
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "127.0.0.1:1/api")
	assert.NotContains(t, err.Error(), "domain=")
	assert.Contains(t, err.Error(), "GET /api/zones/records/get")
}

func TestNonOKHTTPStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "gateway down", http.StatusBadGateway)
	}))
	t.Cleanup(srv.Close)
	c, err := NewClient(&ClientConfig{APIURL: srv.URL, Timeout: time.Second})
	require.NoError(t, err)

	err = c.Status(context.Background())
	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr)
	assert.Equal(t, http.StatusBadGateway, apiErr.HTTPStatus)
}

func TestRedactQuery(t *testing.T) {
	q := url.Values{"zone": {"example.test"}, "token": {"t"}, "pass": {"p"}, "proxyPassword": {"x"}}
	got, err := url.ParseQuery(redactQuery(q))
	require.NoError(t, err)
	assert.Equal(t, "example.test", got.Get("zone"))
	for _, k := range []string{"token", "pass", "proxyPassword"} {
		assert.Equal(t, "REDACTED", got.Get(k), k)
	}
}

func TestNewClientRejectsBadURL(t *testing.T) {
	for _, u := range []string{"dns-server:5380", "ftp://dns", "http://dns:5380/?token=x"} {
		_, err := NewClient(&ClientConfig{APIURL: u, Timeout: time.Second})
		assert.Error(t, err, u)
	}
}
