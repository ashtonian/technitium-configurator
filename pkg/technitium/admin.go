package technitium

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
)

// Administration declares groups, users and section permissions. Groups and
// users are created if absent; descriptions, display names, disabled state,
// session timeouts, group membership and permissions are applied on every
// run. Membership and permissions are merged: groups, users and grants the
// file does not name are left as they are.
type Administration struct {
	Groups      []GroupConfig      `yaml:"groups,omitempty"`
	Users       []UserConfig       `yaml:"users,omitempty"`
	Permissions []PermissionConfig `yaml:"permissions,omitempty"`
}

type GroupConfig struct {
	Name        string  `yaml:"name"`
	Description *string `yaml:"description,omitempty"`
}

type UserConfig struct {
	Username    string  `yaml:"username"`
	DisplayName *string `yaml:"displayName,omitempty"`
	// The initial password, used only when the run creates the user. Give at
	// most one of password, passwordFile or passwordEnv; a user the server
	// does not have yet needs one.
	Password              string   `yaml:"password,omitempty"`
	PasswordFile          string   `yaml:"passwordFile,omitempty"`
	PasswordEnv           string   `yaml:"passwordEnv,omitempty"`
	Disabled              *bool    `yaml:"disabled,omitempty"`
	SessionTimeoutSeconds *int     `yaml:"sessionTimeoutSeconds,omitempty"`
	Groups                []string `yaml:"groups,omitempty"`
}

// PermissionConfig grants groups and users access to one section. Each
// entry lists the access it gets: view, modify, delete.
type PermissionConfig struct {
	Section string              `yaml:"section"`
	Groups  map[string][]string `yaml:"groups,omitempty"`
	Users   map[string][]string `yaml:"users,omitempty"`
}

// PermissionSections are the sections /api/admin/permissions/set accepts.
var PermissionSections = []string{"Dashboard", "Zones", "Cache", "Allowed", "Blocked", "Apps", "DnsClient", "Settings", "DhcpServer", "Administration", "Logs"}

// InitialPassword resolves the password source.
func (u UserConfig) InitialPassword() (string, error) {
	switch {
	case u.Password != "":
		return u.Password, nil
	case u.PasswordFile != "":
		b, err := os.ReadFile(u.PasswordFile)
		if err != nil {
			return "", fmt.Errorf("read passwordFile: %w", err)
		}
		return strings.TrimRight(string(b), "\r\n"), nil
	case u.PasswordEnv != "":
		p, ok := os.LookupEnv(u.PasswordEnv)
		if !ok || p == "" {
			return "", fmt.Errorf("environment variable %s is not set", u.PasswordEnv)
		}
		return p, nil
	}
	return "", fmt.Errorf("the user does not exist and has no password, passwordFile or passwordEnv to create it with")
}

func (a *Administration) validate(v *validator, o origins) {
	groups := map[string]string{}
	for i, g := range a.Groups {
		at := fmt.Sprintf("%s (%s)", o.at("administration.groups", i), g.Name)
		key := strings.ToLower(g.Name)
		switch first, dup := groups[key]; {
		case g.Name == "":
			v.addf("%s: name is required", o.at("administration.groups", i))
		case dup:
			v.addf("%s: duplicate group; first declared at %s", at, first)
		default:
			groups[key] = at
		}
		v.maxLen(at+".description", g.Description, 255)
	}
	users := map[string]string{}
	for i, u := range a.Users {
		at := fmt.Sprintf("%s (%s)", o.at("administration.users", i), u.Username)
		key := strings.ToLower(u.Username)
		switch first, dup := users[key]; {
		case u.Username == "":
			v.addf("%s: username is required", o.at("administration.users", i))
		case dup:
			v.addf("%s: duplicate user; first declared at %s", at, first)
		default:
			users[key] = at
		}
		sources := 0
		for _, s := range []string{u.Password, u.PasswordFile, u.PasswordEnv} {
			if s != "" {
				sources++
			}
		}
		// The source is read only when the user has to be created, so it
		// may be gone on later runs.
		if sources > 1 {
			v.addf("%s: give only one of password, passwordFile or passwordEnv", at)
		}
		v.min(at+".sessionTimeoutSeconds", u.SessionTimeoutSeconds, 0)
	}
	seen := map[string]string{}
	for i, p := range a.Permissions {
		at := fmt.Sprintf("%s (%s)", o.at("administration.permissions", i), p.Section)
		section, ok := matchSection(p.Section)
		if !ok {
			v.addf("%s: section must be one of %s", at, strings.Join(PermissionSections, ", "))
			continue
		}
		if first, dup := seen[section]; dup {
			v.addf("%s: section listed twice; first declared at %s", at, first)
		} else {
			seen[section] = at
		}
		for who, access := range p.Groups {
			validateAccess(v, at+".groups."+who, access)
		}
		for who, access := range p.Users {
			validateAccess(v, at+".users."+who, access)
		}
	}
}

func builtinGroup(lower string) bool {
	switch lower {
	case "administrators", "dns administrators", "dhcp administrators", "everyone":
		return true
	}
	return false
}

func matchSection(s string) (string, bool) {
	for _, name := range PermissionSections {
		if strings.EqualFold(s, name) {
			return name, true
		}
	}
	return "", false
}

func validateAccess(v *validator, at string, access []string) {
	for _, a := range access {
		switch strings.ToLower(a) {
		case "view", "modify", "delete":
		default:
			v.addf("%s: access %q must be view, modify or delete", at, a)
		}
	}
}

// Access is the set of permission flags for one group or user.
type Access struct{ View, Modify, Delete bool }

// ParseAccess converts a declared access list.
func ParseAccess(list []string) Access {
	var a Access
	for _, s := range list {
		switch strings.ToLower(s) {
		case "view":
			a.View = true
		case "modify":
			a.Modify = true
		case "delete":
			a.Delete = true
		}
	}
	return a
}

// List returns the declared form of a.
func (a Access) List() []string {
	var l []string
	if a.View {
		l = append(l, "view")
	}
	if a.Modify {
		l = append(l, "modify")
	}
	if a.Delete {
		l = append(l, "delete")
	}
	return l
}

// ServerUser is an entry of /api/admin/users/get.
type ServerUser struct {
	Username              string   `json:"username"`
	DisplayName           string   `json:"displayName"`
	Type                  string   `json:"type"`
	Disabled              bool     `json:"disabled"`
	SessionTimeoutSeconds int      `json:"sessionTimeoutSeconds"`
	MemberOfGroups        []string `json:"memberOfGroups"`
}

// ServerGroup is an entry of /api/admin/groups/list.
type ServerGroup struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// SectionPermissions is the /api/admin/permissions/get response.
type SectionPermissions struct {
	Section          string `json:"section"`
	UserPermissions  []PermissionEntry
	GroupPermissions []PermissionEntry
}

// PermissionEntry is one grant. Name is the username or group name.
type PermissionEntry struct {
	Name string
	Access
}

func (c *Client) ListUsers(ctx context.Context) ([]ServerUser, error) {
	const path = "/api/admin/users/list"
	raw, err := c.get(ctx, path, nil)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	resp, err := decodeResponse[struct {
		Users []ServerUser `json:"users"`
	}](path, raw)
	if err != nil {
		return nil, err
	}
	return resp.Users, nil
}

func (c *Client) GetUser(ctx context.Context, username string) (*ServerUser, error) {
	const path = "/api/admin/users/get"
	raw, err := c.get(ctx, path, url.Values{"user": {username}, "includeGroups": {"true"}})
	if err != nil {
		return nil, fmt.Errorf("get user %q: %w", username, err)
	}
	return decodeResponse[ServerUser](path, raw)
}

func (c *Client) CreateUser(ctx context.Context, username, password, displayName string) error {
	form := url.Values{"user": {username}, "pass": {password}}
	if displayName != "" {
		form.Set("displayName", displayName)
	}
	if _, err := c.postForm(ctx, "/api/admin/users/create", form); err != nil {
		return fmt.Errorf("create user %q: %w", username, err)
	}
	return nil
}

// SetUser applies the given user fields; nil fields are left unchanged.
func (c *Client) SetUser(ctx context.Context, username string, displayName *string, disabled *bool, sessionTimeout *int, memberOfGroups []string) error {
	form := url.Values{"user": {username}}
	if displayName != nil {
		form.Set("displayName", *displayName)
	}
	if disabled != nil {
		form.Set("disabled", strconv.FormatBool(*disabled))
	}
	if sessionTimeout != nil {
		form.Set("sessionTimeoutSeconds", strconv.Itoa(*sessionTimeout))
	}
	if memberOfGroups != nil {
		form.Set("memberOfGroups", strings.Join(memberOfGroups, ","))
	}
	if _, err := c.postForm(ctx, "/api/admin/users/set", form); err != nil {
		return fmt.Errorf("update user %q: %w", username, err)
	}
	return nil
}

func (c *Client) ListGroups(ctx context.Context) ([]ServerGroup, error) {
	const path = "/api/admin/groups/list"
	raw, err := c.get(ctx, path, nil)
	if err != nil {
		return nil, fmt.Errorf("list groups: %w", err)
	}
	resp, err := decodeResponse[struct {
		Groups []ServerGroup `json:"groups"`
	}](path, raw)
	if err != nil {
		return nil, err
	}
	return resp.Groups, nil
}

func (c *Client) CreateGroup(ctx context.Context, name, description string) error {
	if _, err := c.postForm(ctx, "/api/admin/groups/create", url.Values{"group": {name}, "description": {description}}); err != nil {
		return fmt.Errorf("create group %q: %w", name, err)
	}
	return nil
}

func (c *Client) SetGroupDescription(ctx context.Context, name, description string) error {
	if _, err := c.postForm(ctx, "/api/admin/groups/set", url.Values{"group": {name}, "description": {description}}); err != nil {
		return fmt.Errorf("update group %q: %w", name, err)
	}
	return nil
}

func (c *Client) GetPermissions(ctx context.Context, section string) (*SectionPermissions, error) {
	const path = "/api/admin/permissions/get"
	raw, err := c.get(ctx, path, url.Values{"section": {section}})
	if err != nil {
		return nil, fmt.Errorf("get %s permissions: %w", section, err)
	}
	return decodePermissions(path, raw)
}

// SetPermissions replaces a section's grants and returns the grants the
// server kept, which leave out names it does not know.
func (c *Client) SetPermissions(ctx context.Context, section string, users, groups []PermissionEntry) (*SectionPermissions, error) {
	const path = "/api/admin/permissions/set"
	encode := func(entries []PermissionEntry) string {
		var parts []string
		for _, e := range entries {
			parts = append(parts, e.Name, strconv.FormatBool(e.View), strconv.FormatBool(e.Modify), strconv.FormatBool(e.Delete))
		}
		return strings.Join(parts, "|")
	}
	form := url.Values{"section": {section}, "userPermissions": {encode(users)}, "groupPermissions": {encode(groups)}}
	raw, err := c.postForm(ctx, path, form)
	if err != nil {
		return nil, fmt.Errorf("set %s permissions: %w", section, err)
	}
	return decodePermissions(path, raw)
}

func decodePermissions(path string, raw []byte) (*SectionPermissions, error) {
	type entry struct {
		Username  string `json:"username"`
		Name      string `json:"name"`
		CanView   bool   `json:"canView"`
		CanModify bool   `json:"canModify"`
		CanDelete bool   `json:"canDelete"`
	}
	resp, err := decodeResponse[struct {
		Section          string  `json:"section"`
		UserPermissions  []entry `json:"userPermissions"`
		GroupPermissions []entry `json:"groupPermissions"`
	}](path, raw)
	if err != nil {
		return nil, err
	}
	out := &SectionPermissions{Section: resp.Section}
	for _, e := range resp.UserPermissions {
		out.UserPermissions = append(out.UserPermissions, PermissionEntry{e.Username, Access{e.CanView, e.CanModify, e.CanDelete}})
	}
	for _, e := range resp.GroupPermissions {
		out.GroupPermissions = append(out.GroupPermissions, PermissionEntry{e.Name, Access{e.CanView, e.CanModify, e.CanDelete}})
	}
	return out, nil
}

// MergePermissions sets the declared grants on top of the current ones,
// keeping every grant the file does not name. changed reports whether the
// result differs from current.
func MergePermissions(current []PermissionEntry, declared map[string][]string) (merged []PermissionEntry, changed bool) {
	merged = append(merged, current...)
	names := make([]string, 0, len(declared))
	for n := range declared {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		want := ParseAccess(declared[name])
		found := false
		for i := range merged {
			if strings.EqualFold(merged[i].Name, name) {
				found = true
				if merged[i].Access != want {
					merged[i].Access = want
					changed = true
				}
			}
		}
		if !found {
			merged = append(merged, PermissionEntry{Name: name, Access: want})
			changed = true
		}
	}
	return merged, changed
}
