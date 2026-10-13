package technitium

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"reflect"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// maskedSecret is what /api/settings/get returns for stored passwords.
const maskedSecret = "************"

// Export reads the server's configuration into the configure schema, so it
// can be edited and applied again. Records the server creates with a zone
// (SOA, apex NS, DNSSEC) and data owned by catalogs or a cluster are left
// out. notes lists what the result does not capture.
func Export(ctx context.Context, c *Client) (cfg *Config, notes []string, err error) {
	cfg = &Config{}

	state, stateErr := c.GetClusterState(ctx)
	clusterCatalog := ""
	if stateErr == nil && state.ClusterInitialized {
		clusterCatalog = CanonicalName(state.CatalogZone())
		notes = append(notes, fmt.Sprintf("This server is a cluster %s node of %s; the cluster section is not exported.", selfType(state), state.ClusterDomain))
	}

	if cfg.DNSSettings, err = exportSettings(ctx, c, clusterCatalog); err != nil {
		return nil, nil, err
	}

	zoneNotes, err := exportZones(ctx, c, cfg, clusterCatalog)
	if err != nil {
		return nil, nil, err
	}
	notes = append(notes, zoneNotes...)

	appNotes, err := exportApps(ctx, c, cfg)
	if err != nil {
		return nil, nil, err
	}
	notes = append(notes, appNotes...)

	adminNotes, err := exportAdministration(ctx, c, cfg)
	if err != nil {
		return nil, nil, err
	}
	notes = append(notes, adminNotes...)
	return cfg, notes, nil
}

func selfType(s *ClusterState) string {
	if n, ok := s.Self(); ok {
		return strings.ToLower(string(n.Type))
	}
	return "member"
}

func exportSettings(ctx context.Context, c *Client, clusterCatalog string) (*DnsSettings, error) {
	raw, err := c.GetSettingsRaw(ctx)
	if err != nil {
		return nil, err
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return nil, err
	}
	var s DnsSettings
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("decode settings: %w", err)
	}
	// Masked passwords would overwrite the real ones when applied.
	for _, p := range []**string{&s.WebServiceTlsCertificatePassword, &s.DnsTlsCertificatePassword} {
		if *p != nil && **p == maskedSecret {
			*p = nil
		}
	}
	// The getter nests the proxy; the setter takes flat fields.
	var proxy *struct {
		Type     string   `json:"type"`
		Address  string   `json:"address"`
		Port     int      `json:"port"`
		Username *string  `json:"username"`
		Password *string  `json:"password"`
		Bypass   []string `json:"bypass"`
	}
	if r, ok := raw["proxy"]; ok {
		_ = json.Unmarshal(r, &proxy)
	}
	if proxy != nil {
		s.ProxyType, s.ProxyAddress, s.ProxyPort = &proxy.Type, &proxy.Address, &proxy.Port
		s.ProxyUsername, s.ProxyPassword = proxy.Username, proxy.Password
		s.ProxyBypass = &proxy.Bypass
	} else {
		none := "None"
		s.ProxyType = &none
	}
	// The cluster's own TSIG key belongs to the cluster; applying an old
	// copy would replace its secret.
	if s.TsigKeys != nil && clusterCatalog != "" {
		var keys []TsigKey
		for _, k := range *s.TsigKeys {
			if CanonicalName(k.KeyName) != clusterCatalog {
				keys = append(keys, k)
			}
		}
		s.TsigKeys = &keys
	}
	return &s, nil
}

func exportZones(ctx context.Context, c *Client, cfg *Config, clusterCatalog string) ([]string, error) {
	zones, err := c.ListZones(ctx)
	if err != nil {
		return nil, err
	}
	types := map[string]ZoneType{}
	for _, z := range zones {
		types[ZoneKey(z.Name)] = z.Type
	}
	sort.Slice(zones, func(i, j int) bool { return zones[i].Name < zones[j].Name })

	var notes []string
	for _, z := range zones {
		name := ZoneKey(z.Name)
		catalog := CanonicalName(z.Catalog)
		switch {
		case z.Internal, clusterCatalog != "" && name == clusterCatalog:
			continue
		case catalog != "" && types[catalog] == ZoneSecondaryCatalog:
			// Provisioned by a secondary catalog, not declared here.
			continue
		}
		opts, err := c.GetZoneOptions(ctx, ZoneName(z.Name))
		if err != nil {
			return nil, err
		}
		zc := ZoneConfig{ZoneCreateRequest: ZoneCreateRequest{Zone: ZoneName(z.Name), Type: z.Type}}
		// Membership of the cluster catalog is the default on a primary, so
		// there a zone outside it says so explicitly.
		switch {
		case catalog != "" && catalog != clusterCatalog:
			zc.Catalog = &z.Catalog
		case catalog == "" && clusterCatalog != "" && CatalogMemberTypes[z.Type]:
			none := ""
			zc.Catalog = &none
		}
		if z.Disabled {
			zc.Disabled = &z.Disabled
		}
		switch z.Type {
		case ZoneSecondary, ZoneStub, ZoneSecondaryForwarder, ZoneSecondaryCatalog:
			zc.PrimaryNameServerAddresses = opts.PrimaryNameServerAddresses
			if opts.PrimaryZoneTransferProtocol != "" {
				p := ZoneTransferProtocol(opts.PrimaryZoneTransferProtocol)
				zc.ZoneTransferProtocol = &p
			}
			if opts.PrimaryZoneTransferTsigKeyName != "" {
				zc.TsigKeyName = &opts.PrimaryZoneTransferTsigKeyName
			}
			if opts.ValidateZone {
				zc.ValidateZone = &opts.ValidateZone
			}
		case ZoneForwarder:
			// Its FWD records are exported as records instead.
			off := false
			zc.InitializeForwarder = &off
		}
		zc.ACLSettings = exportACL(opts)
		if catalog != "" {
			zc.OverrideCatalogQueryAccess = trueOrNil(opts.OverrideCatalogQueryAccess)
			zc.OverrideCatalogZoneTransfer = trueOrNil(opts.OverrideCatalogZoneTransfer)
			zc.OverrideCatalogNotify = trueOrNil(opts.OverrideCatalogNotify)
			zc.ACLSettings = withoutInheritedACL(zc.ACLSettings, opts)
		}
		cfg.Zones = append(cfg.Zones, zc)

		if z.Type != ZonePrimary && z.Type != ZoneForwarder {
			continue
		}
		entries, err := c.ListZoneRecords(ctx, ZoneName(z.Name))
		if err != nil {
			return nil, err
		}
		// The server lists an RRset's values in the order they were added,
		// which differs between servers; sorting keeps exports comparable.
		sort.SliceStable(entries, func(i, j int) bool {
			a, b := entries[i], entries[j]
			if an, bn := CanonicalName(a.Name), CanonicalName(b.Name); an != bn {
				return an < bn
			}
			if at, bt := a.Type.Canonical(), b.Type.Canonical(); at != bt {
				return at < bt
			}
			return ValueKeyOf(a) < ValueKeyOf(b)
		})
		skipped := 0
		omitted := map[string]int{}
		for _, e := range entries {
			typ := e.Type.Canonical()
			apex := CanonicalName(e.Name) == CanonicalName(z.Name)
			if apex && (typ == RT_NS || typ == "SOA") {
				continue
			}
			if e.Disabled {
				skipped++
				continue
			}
			if reason := Unexportable(e); reason != "" {
				omitted[reason]++
				continue
			}
			r, ok := RecordFromEntry(ZoneName(z.Name), e)
			if !ok {
				omitted[string(typ)+" records could not be read back"]++
				continue
			}
			cfg.Records = append(cfg.Records, r)
		}
		if skipped > 0 {
			notes = append(notes, fmt.Sprintf("Zone %s: %d disabled record(s) are not exported.", ZoneName(z.Name), skipped))
		}
		reasons := make([]string, 0, len(omitted))
		for reason := range omitted {
			reasons = append(reasons, reason)
		}
		sort.Strings(reasons)
		for _, reason := range reasons {
			notes = append(notes, fmt.Sprintf("Zone %s: %d record(s) not exported: %s.", ZoneName(z.Name), omitted[reason], reason))
		}
	}
	return notes, nil
}

func trueOrNil(b bool) *bool {
	if !b {
		return nil
	}
	return &b
}

func exportACL(o *ZoneOptions) *ACLSettings {
	acl := &ACLSettings{}
	set := false
	str := func(s string) *string {
		if s == "" {
			return nil
		}
		set = true
		return &s
	}
	list := func(l []string) []string {
		if len(l) == 0 {
			return nil
		}
		set = true
		return l
	}
	if q := str(o.QueryAccess); q != nil {
		v := ZoneAccessOption(*q)
		acl.QueryAccess = &v
	}
	acl.QueryAccessNetworkACL = list(o.QueryAccessNetworkACL)
	if x := str(o.ZoneTransfer); x != nil {
		v := ZoneTransferOption(*x)
		acl.ZoneTransfer = &v
	}
	acl.ZoneTransferNetworkACL = list(o.ZoneTransferNetworkACL)
	acl.ZoneTransferTsigKeys = list(o.ZoneTransferTsigKeyNames)
	if n := str(o.Notify); n != nil {
		v := NotifyOption(*n)
		acl.Notify = &v
	}
	acl.NotifyNameServers = list(o.NotifyNameServers)
	acl.NotifySecondaryCatalogNameSrvrs = list(o.NotifySecondaryCatalogsNameServers)
	if u := str(o.Update); u != nil {
		v := UpdateOption(*u)
		acl.Update = &v
	}
	acl.UpdateNetworkACL = list(o.UpdateNetworkACL)
	if len(o.UpdateSecurityPolicies) > 0 {
		var parts []string
		for _, p := range o.UpdateSecurityPolicies {
			parts = append(parts, p.TsigKeyName, p.Domain, strings.Join(p.AllowedTypes, ","))
		}
		s := strings.Join(parts, "|")
		acl.UpdateSecPolicies = &s
		set = true
	}
	if !set {
		return nil
	}
	return acl
}

// withoutInheritedACL drops the ACL groups a catalog member takes from its
// catalog: the member's own values are not in effect, and declaring them
// would only draw a warning on apply.
func withoutInheritedACL(acl *ACLSettings, opts *ZoneOptions) *ACLSettings {
	if acl == nil {
		return nil
	}
	if !opts.OverrideCatalogQueryAccess {
		acl.QueryAccess, acl.QueryAccessNetworkACL = nil, nil
	}
	if !opts.OverrideCatalogZoneTransfer {
		acl.ZoneTransfer, acl.ZoneTransferNetworkACL, acl.ZoneTransferTsigKeys = nil, nil, nil
	}
	if !opts.OverrideCatalogNotify {
		acl.Notify, acl.NotifyNameServers = nil, nil
	}
	if reflect.ValueOf(*acl).IsZero() {
		return nil
	}
	return acl
}

func exportApps(ctx context.Context, c *Client, cfg *Config) ([]string, error) {
	installed, err := c.ListApps(ctx)
	if err != nil {
		return nil, err
	}
	if len(installed) == 0 {
		return nil, nil
	}
	var notes []string
	// Without the store's list, whether an app is in the store is unknown,
	// so one note covers every app instead of claiming each is absent.
	storeApps, storeErr := c.listStoreApps(ctx)
	if storeErr != nil {
		names := make([]string, len(installed))
		for i, app := range installed {
			names[i] = app.Name
		}
		notes = append(notes, fmt.Sprintf("The App Store could not be read (%v), so no app has a url; add one to each of %s to install it on another server.", storeErr, strings.Join(names, ", ")))
	}
	store := make(map[string]storeApp, len(storeApps))
	for _, a := range storeApps {
		store[a.Name] = a
	}
	for _, app := range installed {
		ac := AppConfig{Name: app.Name}
		if s, ok := store[app.Name]; ok {
			ac.Url = s.URL
			if s.Version != app.Version {
				notes = append(notes, fmt.Sprintf("App %s: v%s is installed; the url is the store's current v%s.", app.Name, app.Version, s.Version))
			}
		} else if storeErr == nil {
			notes = append(notes, fmt.Sprintf("App %s is not in the App Store, so it has no url; add one to install it on another server.", app.Name))
		}
		config, err := c.GetAppConfig(ctx, app.Name)
		if err != nil {
			return nil, err
		}
		if strings.TrimSpace(config) != "" {
			if n, err := jsonToYAML(stripJSONComments(config)); err != nil {
				notes = append(notes, fmt.Sprintf("App %s: its config is not valid JSON and is not exported.", app.Name))
			} else {
				ac.Config = *n
			}
		}
		cfg.Apps = append(cfg.Apps, ac)
	}
	return notes, nil
}

type storeApp struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	URL     string `json:"url"`
}

func (c *Client) listStoreApps(ctx context.Context) ([]storeApp, error) {
	const path = "/api/apps/listStoreApps"
	raw, err := c.get(ctx, path, nil)
	if err != nil {
		return nil, err
	}
	resp, err := decodeResponse[struct {
		StoreApps []storeApp `json:"storeApps"`
	}](path, raw)
	if err != nil {
		return nil, err
	}
	return resp.StoreApps, nil
}

func exportAdministration(ctx context.Context, c *Client, cfg *Config) ([]string, error) {
	adm := &Administration{}
	groups, err := c.ListGroups(ctx)
	if err != nil {
		return nil, err
	}
	for _, g := range groups {
		if builtinGroup(strings.ToLower(g.Name)) {
			continue
		}
		gc := GroupConfig{Name: g.Name}
		if g.Description != "" {
			d := g.Description
			gc.Description = &d
		}
		adm.Groups = append(adm.Groups, gc)
	}
	users, err := c.ListUsers(ctx)
	if err != nil {
		return nil, err
	}
	for _, u := range users {
		if u.Type != "" && !strings.EqualFold(u.Type, "Local") {
			continue // SSO and LDAP users are provisioned by their provider
		}
		cur, err := c.GetUser(ctx, u.Username)
		if err != nil {
			return nil, err
		}
		uc := UserConfig{Username: cur.Username, Groups: cur.MemberOfGroups}
		if cur.DisplayName != "" && cur.DisplayName != cur.Username {
			d := cur.DisplayName
			uc.DisplayName = &d
		}
		if cur.Disabled {
			uc.Disabled = &cur.Disabled
		}
		if cur.SessionTimeoutSeconds != 0 {
			uc.SessionTimeoutSeconds = &cur.SessionTimeoutSeconds
		}
		adm.Users = append(adm.Users, uc)
	}
	for _, section := range PermissionSections {
		p, err := c.GetPermissions(ctx, section)
		if err != nil {
			return nil, err
		}
		pc := PermissionConfig{Section: section, Groups: map[string][]string{}, Users: map[string][]string{}}
		for _, e := range p.GroupPermissions {
			pc.Groups[e.Name] = e.List()
		}
		for _, e := range p.UserPermissions {
			pc.Users[e.Name] = e.List()
		}
		if len(pc.Groups) == 0 {
			pc.Groups = nil
		}
		if len(pc.Users) == 0 {
			pc.Users = nil
		}
		if pc.Groups != nil || pc.Users != nil {
			adm.Permissions = append(adm.Permissions, pc)
		}
	}
	if len(adm.Groups) > 0 || len(adm.Users) > 0 || len(adm.Permissions) > 0 {
		cfg.Administration = adm
	}
	var notes []string
	if len(adm.Users) > 0 {
		notes = append(notes, "Users are exported without passwords. Add password, passwordFile or passwordEnv to any user the file must be able to create.")
	}
	return notes, nil
}

// MarshalExport renders an exported config as YAML with a header that
// names the server and lists the notes.
func MarshalExport(cfg *Config, server string, notes []string) ([]byte, error) {
	var body strings.Builder
	enc := yaml.NewEncoder(&body)
	enc.SetIndent(2)
	if err := enc.Encode(cfg); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	var sb strings.Builder
	sb.WriteString("# Exported by technitium-configurator from " + redactURL(server) + ".\n")
	sb.WriteString("# It contains secrets (TSIG keys, proxy and app credentials): keep it private.\n")
	for _, n := range notes {
		sb.WriteString("# - " + n + "\n")
	}
	sb.WriteString(body.String())
	return []byte(sb.String()), nil
}

func redactURL(s string) string {
	u, err := url.Parse(s)
	if err != nil {
		return "the server"
	}
	u.User = nil
	u.RawQuery = ""
	return u.String()
}
