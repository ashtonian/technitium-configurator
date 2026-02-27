package technitium

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/go-querystring/query"
)

// Client represents a Technitium DNS Server API client
type Client struct {
	Base      string
	Token     string
	hc        *http.Client
	transport http.RoundTripper
	timeout   time.Duration
}

// NewClient creates a new Technitium DNS Server API client with the given configuration
func NewClient(cfg *ClientConfig) (*Client, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	t := NewLoggedTransport()
	client := &Client{
		Base:  strings.TrimRight(cfg.APIURL, "/"),
		Token: cfg.APIToken,
		hc: &http.Client{
			Transport: t,
			Timeout:   cfg.Timeout,
		},
		transport: t,
		timeout:   cfg.Timeout,
	}

	// If we have username/password but no token, try to login
	if cfg.Username != "" && cfg.Password != "" && cfg.APIToken == "" {
		ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
		defer cancel()

		if _, err := client.Login(ctx, cfg.Username, cfg.Password); err != nil {
			return nil, fmt.Errorf("failed to login: %w", err)
		}
	}

	return client, nil
}

// normalizePath ensures consistent path handling by:
// 1. Removing leading slashes from the path
// 2. Joining base and path with a single slash while preserving URL protocol
func (c *Client) normalizePath(p string) string {
	p = strings.TrimLeft(p, "/")
	baseURL, err := url.Parse(c.Base)
	if err != nil {
		return c.Base + "/" + p
	}
	joined, err := url.JoinPath(baseURL.String(), p)
	if err != nil {
		return c.Base + "/" + p
	}
	return joined
}

func (c *Client) callGET(ctx context.Context, path string, in any) (*apiResp, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	qs, err := query.Values(in)
	if err != nil {
		return nil, err
	}

	if c.Token != "" {
		qs.Set("token", c.Token)
	}

	u := fmt.Sprintf("%s?%s", c.normalizePath(path), qs.Encode())
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.hc.Do(request)
	if err != nil {
		return nil, err
	}
	return parse(resp)
}

func (c *Client) callPOST(ctx context.Context, path string, body any) (*apiResp, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	p := url.Values{}
	if c.Token != "" {
		p.Set("token", c.Token)
	}
	var b bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&b).Encode(body); err != nil {
			return nil, err
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s?%s", c.normalizePath(path), p.Encode()), &b)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	return parse(resp)
}

// callPOSTForm sends a form-encoded POST request. It marshals the struct via
// its json tags (using jsonToFormValues) so that all request structs can use a
// single set of json+yaml tags. Only the /api/settings/set endpoint supports a
// raw JSON body (callPOST); every other mutating endpoint requires form encoding.
func (c *Client) callPOSTForm(ctx context.Context, path string, in any) (*apiResp, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	vals, err := jsonToFormValues(in)
	if err != nil {
		return nil, err
	}
	if c.Token != "" {
		vals.Set("token", c.Token)
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		c.normalizePath(path),
		strings.NewReader(vals.Encode()),
	)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")

	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	return parse(resp)
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
		// JSON string → unquoted value
		var s string
		if json.Unmarshal(raw, &s) == nil {
			vals.Set(k, s)
			continue
		}
		// String array → comma-separated (e.g. dnsServerLocalEndPoints)
		var strs []string
		if json.Unmarshal(raw, &strs) == nil {
			vals.Set(k, strings.Join(strs, ","))
			continue
		}
		// Numbers, bools, object arrays → literal JSON representation
		vals.Set(k, string(raw))
	}

	return vals, nil
}

// unmarshalResp is a generic helper that unmarshals an apiResp.Response
// into the target type, eliminating repeated decode boilerplate.
func unmarshalResp[T any](r *apiResp) (*T, error) {
	var v T
	if err := json.Unmarshal(r.Response, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

// callGETDirect performs a GET request and decodes the full response body into
// dest. Unlike callGET, it does not expect the standard {status, response}
// envelope (used by Login and CreateToken).
func (c *Client) callGETDirect(ctx context.Context, path string, params any, dest any) (httpCode int, err error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	qs, err := query.Values(params)
	if err != nil {
		return 0, err
	}
	if c.Token != "" {
		qs.Set("token", c.Token)
	}

	u := fmt.Sprintf("%s?%s", c.normalizePath(path), qs.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return 0, err
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	return resp.StatusCode, json.NewDecoder(resp.Body).Decode(dest)
}

// validateDirectResp validates a response where status/error fields are at the
// top level rather than nested in a "response" envelope.
func validateDirectResp(httpCode int, decodeErr error, status, errMsg, message string) error {
	if httpCode != 0 && httpCode != http.StatusOK {
		msg := errMsg
		if msg == "" {
			msg = message
		}
		if decodeErr == nil && msg != "" {
			return fmt.Errorf("HTTP %d: %s", httpCode, msg)
		}
		return fmt.Errorf("HTTP %d", httpCode)
	}
	if decodeErr != nil {
		return decodeErr
	}
	if status != "" && status != "ok" {
		msg := errMsg
		if msg == "" {
			msg = message
		}
		if msg == "" {
			msg = status
		}
		return errors.New(msg)
	}
	return nil
}

func extractErrMsg(r *apiResp) string {
	msg := r.ErrorMessage
	if msg == "" {
		msg = r.Message
	}
	if msg == "" {
		msg = r.Status
	}
	return msg
}

func parse(resp *http.Response) (*apiResp, error) {
	defer resp.Body.Close()

	var r apiResp
	decodeErr := json.NewDecoder(resp.Body).Decode(&r)

	if resp.StatusCode != http.StatusOK {
		if decodeErr == nil && (r.ErrorMessage != "" || r.Message != "") {
			return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, extractErrMsg(&r))
		}
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	if decodeErr != nil {
		return nil, decodeErr
	}

	if r.Status != "ok" {
		return nil, errors.New(extractErrMsg(&r))
	}
	return &r, nil
}

type apiResp struct {
	Status       string          `json:"status"`
	Message      string          `json:"message,omitempty"`
	ErrorMessage string          `json:"errorMessage,omitempty"`
	Response     json.RawMessage `json:"response,omitempty"`
}

type CreateTokenResponse struct {
	Username     string `json:"username,omitempty" yaml:"username,omitempty"`
	TokenName    string `json:"tokenName,omitempty" yaml:"tokenName,omitempty"`
	Token        string `json:"token,omitempty" yaml:"token,omitempty"`
	Status       string `json:"status,omitempty" yaml:"status,omitempty"`
	ErrorMessage string `json:"errorMessage,omitempty" yaml:"-"`
	Message      string `json:"message,omitempty" yaml:"-"`
}

// CreateToken creates a non-expiring API token for the specified user.
// The token will have the same privileges as the user account.
func (c *Client) CreateToken(ctx context.Context, username, password, tokenName string) (*CreateTokenResponse, error) {
	params := struct {
		User      string `url:"user"`
		Pass      string `url:"pass"`
		TokenName string `url:"tokenName"`
	}{
		User:      username,
		Pass:      password,
		TokenName: tokenName,
	}

	var resp CreateTokenResponse
	code, decodeErr := c.callGETDirect(ctx, "/api/user/createToken", params, &resp)
	if err := validateDirectResp(code, decodeErr, resp.Status, resp.ErrorMessage, resp.Message); err != nil {
		return nil, fmt.Errorf("create token: %w", err)
	}
	return &resp, nil
}

type LoginResponse struct {
	DisplayName  string          `json:"displayName,omitempty"`
	Username     string          `json:"username,omitempty"`
	Token        string          `json:"token,omitempty"`
	Info         json.RawMessage `json:"info,omitempty"`
	Status       string          `json:"status,omitempty"`
	ErrorMessage string          `json:"errorMessage,omitempty"`
	Message      string          `json:"message,omitempty"`
}

// Login authenticates with the server and returns a session token.
// On successful login, the client's token is automatically updated.
func (c *Client) Login(ctx context.Context, username, password string) (*LoginResponse, error) {
	params := struct {
		User        string `url:"user"`
		Pass        string `url:"pass"`
		IncludeInfo bool   `url:"includeInfo"`
	}{
		User:        username,
		Pass:        password,
		IncludeInfo: false,
	}

	var resp LoginResponse
	code, decodeErr := c.callGETDirect(ctx, "/api/user/login", params, &resp)
	if err := validateDirectResp(code, decodeErr, resp.Status, resp.ErrorMessage, resp.Message); err != nil {
		return nil, fmt.Errorf("login: %w", err)
	}
	c.Token = resp.Token
	return &resp, nil
}

func (c *Client) ChangePassword(ctx context.Context, currentPassword, newPassword string) error {
	params := struct {
		Pass    string `url:"pass"`
		NewPass string `url:"newPass"`
	}{
		Pass:    currentPassword,
		NewPass: newPassword,
	}

	_, err := c.callGET(ctx, "/api/user/changePassword", params)
	return err
}
