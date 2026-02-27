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

func (c *Client) callPOSTForm(ctx context.Context, path string, in any) (*apiResp, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	qs, err := query.Values(in)
	if err != nil {
		return nil, err
	}
	if c.Token != "" {
		qs.Set("token", c.Token)
	}

	u := c.normalizePath(path)
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		u,
		strings.NewReader(qs.Encode()),
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
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	params := struct {
		User      string `url:"user"`
		Pass      string `url:"pass"`
		TokenName string `url:"tokenName"`
	}{
		User:      username,
		Pass:      password,
		TokenName: tokenName,
	}

	qs, err := query.Values(params)
	if err != nil {
		return nil, err
	}

	path := "/api/user/createToken"
	u := fmt.Sprintf("%s?%s", c.normalizePath(path), qs.Encode())
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.hc.Do(request)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var tokenResp CreateTokenResponse
	decodeErr := json.NewDecoder(resp.Body).Decode(&tokenResp)

	if resp.StatusCode != http.StatusOK {
		if decodeErr == nil && (tokenResp.ErrorMessage != "" || tokenResp.Message != "") {
			msg := tokenResp.ErrorMessage
			if msg == "" {
				msg = tokenResp.Message
			}
			return nil, fmt.Errorf("create token: HTTP %d: %s", resp.StatusCode, msg)
		}
		return nil, fmt.Errorf("create token: HTTP %d", resp.StatusCode)
	}

	if decodeErr != nil {
		return nil, fmt.Errorf("create token: %w", decodeErr)
	}

	if tokenResp.Status != "" && tokenResp.Status != "ok" {
		msg := tokenResp.ErrorMessage
		if msg == "" {
			msg = tokenResp.Message
		}
		if msg == "" {
			msg = tokenResp.Status
		}
		return nil, fmt.Errorf("create token: %s", msg)
	}

	return &tokenResp, nil
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
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	params := struct {
		User        string `url:"user"`
		Pass        string `url:"pass"`
		IncludeInfo bool   `url:"includeInfo"`
	}{
		User:        username,
		Pass:        password,
		IncludeInfo: false,
	}

	qs, err := query.Values(params)
	if err != nil {
		return nil, err
	}
	path := "/api/user/login"
	u := fmt.Sprintf("%s?%s", c.normalizePath(path), qs.Encode())
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.hc.Do(request)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var loginResp LoginResponse
	decodeErr := json.NewDecoder(resp.Body).Decode(&loginResp)

	if resp.StatusCode != http.StatusOK {
		if decodeErr == nil && (loginResp.ErrorMessage != "" || loginResp.Message != "") {
			msg := loginResp.ErrorMessage
			if msg == "" {
				msg = loginResp.Message
			}
			return nil, fmt.Errorf("login: HTTP %d: %s", resp.StatusCode, msg)
		}
		return nil, fmt.Errorf("login: HTTP %d", resp.StatusCode)
	}

	if decodeErr != nil {
		return nil, fmt.Errorf("login: %w", decodeErr)
	}

	if loginResp.Status != "" && loginResp.Status != "ok" {
		msg := loginResp.ErrorMessage
		if msg == "" {
			msg = loginResp.Message
		}
		if msg == "" {
			msg = loginResp.Status
		}
		return nil, fmt.Errorf("login: %s", msg)
	}

	// Update the client's token on successful login
	c.Token = loginResp.Token

	return &loginResp, nil
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
