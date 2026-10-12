package technitium

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// maxResponseBytes bounds how much of a response body is read. Full-zone
// record listings are the largest responses the client requests.
const maxResponseBytes = 64 << 20

// Client is a Technitium DNS Server HTTP API client. It does not
// authenticate on construction; call Login or SetToken first.
type Client struct {
	base  string
	token string
	hc    *http.Client
}

// NewClient returns a client for cfg.APIURL.
func NewClient(cfg *ClientConfig) (*Client, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	// Errors never include the URL: it may carry credentials.
	u, err := url.Parse(strings.TrimRight(cfg.APIURL, "/"))
	switch {
	case err != nil:
		return nil, errors.New("API URL is not a valid URL")
	case u.Scheme != "http" && u.Scheme != "https":
		return nil, errors.New("API URL must use http or https")
	case u.Host == "":
		return nil, errors.New("API URL has no host")
	case u.User != nil:
		return nil, errors.New("API URL must not contain credentials; use DNS_API_TOKEN or DNS_USERNAME and DNS_PASSWORD")
	case u.RawQuery != "" || u.Fragment != "":
		return nil, errors.New("API URL must not contain a query or fragment")
	}
	return &Client{
		base: u.String(),
		hc: &http.Client{
			Transport: NewLoggedTransport(),
			Timeout:   cfg.Timeout,
			// A followed redirect turns a POST into a GET and drops its form.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

// SetToken sets the session or API token sent with every request.
func (c *Client) SetToken(token string) { c.token = token }

// Token returns the current session or API token.
func (c *Client) Token() string { return c.token }

type envelope struct {
	Status       string          `json:"status"`
	ErrorMessage string          `json:"errorMessage"`
	Response     json.RawMessage `json:"response"`
}

// get calls a read endpoint and returns the "response" member of the envelope.
func (c *Client) get(ctx context.Context, path string, params url.Values) (json.RawMessage, error) {
	raw, err := c.getRaw(ctx, path, params)
	if err != nil {
		return nil, err
	}
	return responseMember(path, raw)
}

func (c *Client) getRaw(ctx context.Context, path string, params url.Values) ([]byte, error) {
	target := c.base + path
	if len(params) > 0 {
		target += "?" + params.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	return c.send(req, path, c.token)
}

// postForm calls a mutating endpoint with a form body, which keeps
// credentials and record data out of URLs.
func (c *Client) postForm(ctx context.Context, path string, form url.Values) (json.RawMessage, error) {
	raw, err := c.postFormRaw(ctx, path, form)
	if err != nil {
		return nil, err
	}
	return responseMember(path, raw)
}

func (c *Client) postFormRaw(ctx context.Context, path string, form url.Values) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	return c.send(req, path, c.token)
}

// postJSON calls an endpoint that parses a JSON body (only /api/settings/set).
func (c *Client) postJSON(ctx context.Context, path string, body any) (json.RawMessage, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("%s: encode body: %w", path, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	raw, err := c.send(req, path, c.token)
	if err != nil {
		return nil, err
	}
	return responseMember(path, raw)
}

// send executes req with token as a bearer credential and returns the raw
// body once the envelope reports status "ok".
func (c *Client) send(req *http.Request, path, token string) ([]byte, error) {
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		// *url.Error embeds the full request URL; report the path only.
		var uerr *url.Error
		if errors.As(err, &uerr) {
			err = uerr.Err
		}
		return nil, fmt.Errorf("%s %s: %w", req.Method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("%s %s: read response: %w", req.Method, path, err)
	}

	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return nil, &APIError{Endpoint: path, HTTPStatus: resp.StatusCode,
			Message: "the server redirected to " + resp.Header.Get("Location") + "; use that address as the API URL"}
	}

	var env envelope
	decodeErr := json.Unmarshal(raw, &env)
	if resp.StatusCode != http.StatusOK {
		apiErr := &APIError{Endpoint: path, HTTPStatus: resp.StatusCode, Status: env.Status, Message: env.ErrorMessage}
		if decodeErr != nil || apiErr.Message == "" {
			apiErr.Message = http.StatusText(resp.StatusCode)
		}
		return nil, apiErr
	}
	if decodeErr != nil {
		return nil, fmt.Errorf("%s %s: decode response: %w", req.Method, path, decodeErr)
	}
	if env.Status != "ok" {
		return nil, &APIError{Endpoint: path, HTTPStatus: resp.StatusCode, Status: env.Status, Message: env.ErrorMessage}
	}
	return raw, nil
}

func responseMember(path string, raw []byte) (json.RawMessage, error) {
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("%s: decode response: %w", path, err)
	}
	return env.Response, nil
}

func decodeResponse[T any](path string, raw []byte) (*T, error) {
	var v T
	if len(raw) == 0 {
		return &v, nil
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, fmt.Errorf("%s: decode response: %w", path, err)
	}
	return &v, nil
}

// jsonToFormValues marshals a struct using its json tags, then converts the
// resulting key-value pairs to url.Values suitable for form-encoded POST.
// String arrays are joined with commas; object arrays are sent as JSON strings.
func jsonToFormValues(v any) (url.Values, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}

	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}

	vals := url.Values{}
	for k, raw := range m {
		if string(raw) == "null" {
			continue
		}
		var s string
		if json.Unmarshal(raw, &s) == nil {
			vals.Set(k, s)
			continue
		}
		var strs []string
		if json.Unmarshal(raw, &strs) == nil {
			vals.Set(k, strings.Join(strs, ","))
			continue
		}
		vals.Set(k, string(raw))
	}

	return vals, nil
}

// Status reports whether the web service answers. It needs no authentication.
func (c *Client) Status(ctx context.Context) error {
	_, err := c.getRaw(ctx, "/api/status", nil)
	return err
}

// WaitReady polls /api/status until the server answers or timeout elapses.
func (c *Client) WaitReady(ctx context.Context, timeout, interval time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	for {
		err := c.Status(ctx)
		if err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("server not ready after %s: %w", timeout, err)
		case <-time.After(interval):
		}
	}
}

// CreateTokenResponse is the /api/user/createToken reply and the token file format.
type CreateTokenResponse struct {
	Username  string `json:"username,omitempty" yaml:"username,omitempty"`
	TokenName string `json:"tokenName,omitempty" yaml:"tokenName,omitempty"`
	Token     string `json:"token,omitempty" yaml:"token,omitempty"`
}

// CreateToken creates a non-expiring API token with the privileges of username.
func (c *Client) CreateToken(ctx context.Context, username, password, tokenName string) (*CreateTokenResponse, error) {
	const path = "/api/user/createToken"
	raw, err := c.postFormRaw(ctx, path, url.Values{
		"user":      {username},
		"pass":      {password},
		"tokenName": {tokenName},
	})
	if err != nil {
		return nil, err
	}
	resp, err := decodeResponse[CreateTokenResponse](path, raw)
	if err != nil {
		return nil, err
	}
	if resp.Token == "" {
		return nil, fmt.Errorf("%s: response contained no token", path)
	}
	return resp, nil
}

// Login creates a session for username and uses its token for later calls.
// totp is the one-time password for a user with two-factor authentication,
// or "".
func (c *Client) Login(ctx context.Context, username, password, totp string) error {
	const path = "/api/user/login"
	form := url.Values{
		"user":        {username},
		"pass":        {password},
		"includeInfo": {"false"},
	}
	if totp != "" {
		form.Set("totp", totp)
	}
	raw, err := c.postFormRaw(ctx, path, form)
	if err != nil {
		return err
	}
	resp, err := decodeResponse[struct {
		Token string `json:"token"`
	}](path, raw)
	if err != nil {
		return err
	}
	if resp.Token == "" {
		return fmt.Errorf("%s: response contained no token", path)
	}
	c.token = resp.Token
	return nil
}

// ChangePassword changes the password of the logged-in user.
func (c *Client) ChangePassword(ctx context.Context, currentPassword, newPassword string) error {
	_, err := c.postForm(ctx, "/api/user/changePassword", url.Values{
		"pass":    {currentPassword},
		"newPass": {newPassword},
	})
	return err
}

// TokenUser returns the user that token belongs to. The error matches
// ErrInvalidToken when the server does not recognise the token.
func (c *Client) TokenUser(ctx context.Context, token string) (string, error) {
	const path = "/api/user/session/get"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, nil)
	if err != nil {
		return "", err
	}
	raw, err := c.send(req, path, token)
	if err != nil {
		return "", err
	}
	resp, err := decodeResponse[struct {
		Username string `json:"username"`
	}](path, raw)
	if err != nil {
		return "", err
	}
	return resp.Username, nil
}
