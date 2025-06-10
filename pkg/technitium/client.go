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

	"github.com/google/go-querystring/query"
)

type Client struct {
	Base      string
	Token     string
	hc        *http.Client
	transport http.RoundTripper
}

/*
TODO:
- add/update apps
*/

func NewClient(base, token string) *Client {
	t := NewLoggedTransport()
	return &Client{
		Base:  strings.TrimRight(base, "/"),
		Token: token,
		hc: &http.Client{
			Transport: t,
		},
	}
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
	p := url.Values{}
	p.Set("token", c.Token)
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
	qs, _ := query.Values(in)
	qs.Set("token", c.Token)

	url := c.normalizePath(path)
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		url,
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

func parse(resp *http.Response) (*apiResp, error) {
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	var r apiResp
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, err
	}
	if r.Status != "ok" {
		if r.Message == "" {
			r.Message = r.Status // fallback to status if no message
		}
		return nil, errors.New(r.Message)
	}
	return &r, nil
}

type apiResp struct {
	Status   string          `json:"status"`
	Message  string          `json:"message,omitempty"`
	Response json.RawMessage `json:"response,omitempty"`
}

type CreateTokenResponse struct {
	Username  string `json:"username"`
	TokenName string `json:"tokenName"`
	Token     string `json:"token"`
	Status    string `json:"status"`
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

	resp, err := c.callGET(ctx, "/api/user/createToken", params)
	if err != nil {
		return nil, err
	}

	var tokenResp CreateTokenResponse
	if err := json.Unmarshal(resp.Response, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal token response: %w", err)
	}

	return &tokenResp, nil
}

type LoginResponse struct {
	DisplayName string          `json:"displayName"`
	Username    string          `json:"username"`
	Token       string          `json:"token"`
	Info        json.RawMessage `json:"info,omitempty"`
	Status      string          `json:"status"`
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
		IncludeInfo: true,
	}

	resp, err := c.callGET(ctx, "/api/user/login", params)
	if err != nil {
		return nil, err
	}

	var loginResp LoginResponse
	if err := json.Unmarshal(resp.Response, &loginResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal login response: %w", err)
	}

	// Update the client's token on successful login
	c.Token = loginResp.Token

	return &loginResp, nil
}

func (c *Client) ChangePassword(ctx context.Context, newPassword string) error {
	params := struct {
		Pass string `url:"pass"`
	}{
		Pass: newPassword,
	}

	_, err := c.callGET(ctx, "/api/user/changePassword", params)
	return err
}
