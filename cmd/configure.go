package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/ashtonian/technitium-configurator/v3/pkg/technitium"
)

// applier runs one configure pass. Settings, zone options, app config,
// cluster options and administration details are written on every run.
// Zones, records, apps, groups and users are created only when absent;
// finding one already there is a skip, not a failure. Anything else that
// fails is collected, the run continues, and the command exits non-zero.
type applier struct {
	client  *technitium.Client
	cfg     *technitium.ClientConfig
	desired *technitium.Config

	created, applied, unchanged, conflicts int
	failures                               []string

	zoneRecords  map[string]map[string][]technitium.RecordEntry
	recordGroups []*technitium.RecordGroup
	// clusterState caches the topology read; cluster init and join reset it.
	clusterState    *technitium.ClusterState
	clusterStateErr error
}

func (a *applier) cluster(ctx context.Context) (*technitium.ClusterState, error) {
	if a.clusterState == nil && a.clusterStateErr == nil {
		a.clusterState, a.clusterStateErr = a.client.GetClusterState(ctx)
	}
	return a.clusterState, a.clusterStateErr
}

func (a *applier) fail(item string, err error) {
	slog.Error("Failed", "item", item, "error", err)
	a.failures = append(a.failures, fmt.Sprintf("%s: %v", item, err))
}

func (a *applier) conflict(item, msg string) {
	slog.Warn(msg, "item", item)
	a.conflicts++
}

func (a *applier) run(ctx context.Context) error {
	if err := a.planRecords(ctx); err != nil {
		return err
	}
	if err := a.checkServerDomain(ctx); err != nil {
		return err
	}
	if err := a.checkClusterOptions(ctx); err != nil {
		return err
	}
	// Settings come before the cluster: cluster init adds its own TSIG key,
	// and a later settings call that omitted it would be rejected.
	if err := a.applySettings(ctx); err != nil {
		return err
	}
	if cc := a.desired.Cluster; cc != nil {
		if err := a.applyCluster(ctx, cc); err != nil {
			return err
		}
	}
	a.applyAdministration(ctx)
	clusterCatalog, err := a.clusterCatalog(ctx)
	if err != nil {
		return err
	}
	if err := a.applyZones(ctx, clusterCatalog); err != nil {
		return err
	}
	// FWD records decide how the server resolves names, including the App
	// Store's, so they come before apps; other records come after, so APP
	// records reference an installed app.
	a.applyRecords(ctx, func(t technitium.RecordType) bool { return t == technitium.RT_FWD })
	a.applyApps(ctx)
	a.applyRecords(ctx, func(t technitium.RecordType) bool { return t != technitium.RT_FWD })

	slog.Info("Configuration complete",
		"created", a.created,
		"applied", a.applied,
		"unchanged", a.unchanged,
		"conflicts", a.conflicts,
		"failed", len(a.failures))
	if len(a.failures) > 0 {
		return fmt.Errorf("%d operation(s) failed: %s", len(a.failures), strings.Join(a.failures, "; "))
	}
	return nil
}

// checkServerDomain stops before any change when the file's server domain
// is outside the domain of the cluster this server already belongs to; the
// server would reject it on every run.
func (a *applier) checkServerDomain(ctx context.Context) error {
	s := a.desired.DNSSettings
	if s == nil || s.DnsServerDomain == nil {
		return nil
	}
	state, err := a.cluster(ctx)
	if err != nil || !state.ClusterInitialized {
		// Validation already covers a cluster declared in the file.
		return nil
	}
	cluster := technitium.CanonicalName(state.ClusterDomain)
	if !technitium.InClusterDomain(*s.DnsServerDomain, cluster) {
		return fmt.Errorf("dnsSettings.dnsServerDomain %q is outside this server's cluster domain %q; use a name ending in .%s",
			*s.DnsServerDomain, cluster, cluster)
	}
	return nil
}

// checkClusterOptions stops before any change when the primary's timing
// options, with the ones the file leaves out at their current values, break
// the server's rule that config refresh is slower than heartbeat refresh.
func (a *applier) checkClusterOptions(ctx context.Context) error {
	cc := a.desired.Cluster
	if cc == nil || cc.Mode != "primary" || cc.Options().IsEmpty() {
		return nil
	}
	current := technitium.DefaultClusterOptions
	if state, err := a.cluster(ctx); err == nil && state.ClusterInitialized {
		current = state.Options()
	}
	if err := cc.Options().Merge(current).Check(); err != nil {
		where := "cluster"
		if origin := a.desired.Origin("cluster"); origin != "" {
			where = origin + ": cluster"
		}
		return fmt.Errorf("%s: %w (options left out keep their current values)", where, err)
	}
	return nil
}

func (a *applier) applySettings(ctx context.Context) error {
	s := a.desired.DNSSettings
	if s == nil {
		return nil
	}
	var current map[string]json.RawMessage
	if s.TsigKeys != nil || s.SetsWebServiceKeys() {
		var err error
		if current, err = a.client.GetSettingsRaw(ctx); err != nil {
			return fmt.Errorf("read current settings: %w", err)
		}
	}
	if s.TsigKeys != nil {
		// Keys the config does not name (the cluster catalog key) must be
		// sent back, or the server rejects the call.
		var existing []technitium.TsigKey
		if raw, ok := current["tsigKeys"]; ok {
			if err := json.Unmarshal(raw, &existing); err != nil {
				return fmt.Errorf("read current TSIG keys: %w", err)
			}
		}
		merged := technitium.MergeTsigKeys(existing, *s.TsigKeys)
		s.TsigKeys = &merged
	}
	restarts := current != nil && s.RestartsWebService(current)

	if err := a.client.SetDNSSettings(ctx, s); err != nil {
		return err
	}
	a.applied++
	slog.Info("DNS settings applied")

	if restarts {
		// The server restarts its web service 2 seconds after replying.
		slog.Info("The settings change restarts the web service; waiting for it to come back")
		if err := sleepCtx(ctx, 4*time.Second); err != nil {
			return err
		}
		timeout := a.cfg.WaitTimeout
		if timeout == 0 {
			timeout = 30 * time.Second
		}
		if err := a.client.WaitReady(ctx, timeout, 2*time.Second); err != nil {
			return fmt.Errorf("web service did not come back after the settings change; if the change moved it (port, addresses or TLS), re-run against the new address: %w", err)
		}
	}
	return nil
}

func (a *applier) applyCluster(ctx context.Context, cc *technitium.ClusterConfig) error {
	state, err := a.cluster(ctx)
	if err != nil {
		return err
	}

	if !state.ClusterInitialized {
		if cc.Mode == "primary" {
			if _, err := a.client.ClusterInit(ctx, cc.Domain, cc.NodeIPs); err != nil {
				return err
			}
			slog.Info("Cluster initialized", "domain", cc.Domain)
			if err := a.reauthenticate(ctx, a.cfg.Username, a.cfg.Password, ""); err != nil {
				return err
			}
		} else {
			req := technitium.ClusterJoinRequest{
				SecondaryNodeIPs:    cc.NodeIPs,
				PrimaryNodeURL:      cc.PrimaryURL,
				PrimaryNodeIP:       cc.PrimaryIP,
				PrimaryNodeUsername: cc.PrimaryUsername,
				PrimaryNodePassword: cc.PrimaryPassword,
				PrimaryNodeTotp:     cc.PrimaryTotp,
				IgnoreCertErrors:    cc.IgnoreCertErrors,
			}
			if _, err := a.client.ClusterJoin(ctx, req); err != nil {
				return err
			}
			slog.Info("Joined cluster", "primaryURL", cc.PrimaryURL)
			// Joining replaces this node's users with the primary's, so the
			// session continues as the primary's user. A one-time password
			// stays valid for its time step, so the join's code is reused.
			if err := a.reauthenticate(ctx, cc.PrimaryUsername, cc.PrimaryPassword, cc.PrimaryTotp); err != nil {
				return err
			}
		}
		a.created++
		a.clusterState, a.clusterStateErr = nil, nil
		if state, err = a.cluster(ctx); err != nil {
			return err
		}
	} else {
		slog.Info("Cluster already initialized", "domain", state.ClusterDomain, "nodes", len(state.Nodes))
	}

	self, ok := state.Self()
	if !ok {
		return errors.New("cluster state does not list this node")
	}
	wantType := technitium.ClusterNodeTypeSecondary
	if cc.Mode == "primary" {
		wantType = technitium.ClusterNodeTypePrimary
	}
	if self.Type != wantType {
		return fmt.Errorf("cluster.mode is %q but this node is the cluster %s", cc.Mode, self.Type)
	}
	if cc.Mode == "primary" && !technitium.SameName(state.ClusterDomain, cc.Domain) {
		return fmt.Errorf("cluster.domain is %q but this node's cluster is %q", cc.Domain, state.ClusterDomain)
	}

	if want := cc.NodeIPList(); !sameIPSet(want, self.IPAddresses) {
		if err := a.client.UpdateNodeIPAddresses(ctx, want); err != nil {
			return err
		}
		a.applied++
		slog.Info("Cluster node IP addresses updated", "from", self.IPAddresses, "to", want)
	}

	if opts := cc.Options(); cc.Mode == "primary" && !opts.IsEmpty() {
		if err := a.client.SetClusterOptions(ctx, opts); err != nil {
			return err
		}
		a.applied++
		slog.Info("Cluster options applied", "options", opts)
	}
	return nil
}

// reauthenticate logs in again after cluster init or join, which replace
// the server's TLS state (and, on join, its users) and can end the session.
// Without a password, the current token is kept.
func (a *applier) reauthenticate(ctx context.Context, username, password, totp string) error {
	if username == "" || password == "" {
		return nil
	}
	var err error
	for attempt := range 5 {
		if err = sleepCtx(ctx, 3*time.Second); err != nil {
			return err
		}
		if err = a.client.Login(ctx, username, password, totp); err == nil {
			slog.Info("Re-authenticated after cluster operation", "user", username)
			return nil
		}
		slog.Debug("Re-login after cluster operation failed; retrying", "attempt", attempt+1, "error", err)
	}
	return fmt.Errorf("re-authenticate as %q after cluster operation: %w", username, err)
}

func sameIPSet(a, b []string) bool {
	norm := func(list []string) []string {
		out := make([]string, 0, len(list))
		for _, s := range list {
			if ip, err := netip.ParseAddr(strings.TrimSpace(s)); err == nil {
				out = append(out, ip.String())
			} else {
				out = append(out, strings.TrimSpace(s))
			}
		}
		sort.Strings(out)
		return out
	}
	return strings.Join(norm(a), ",") == strings.Join(norm(b), ",")
}

// clusterCatalog returns the cluster catalog zone when this server is the
// primary of an initialized cluster, else "".
func (a *applier) clusterCatalog(ctx context.Context) (string, error) {
	needsDefault := false
	for _, z := range a.desired.Zones {
		if z.Catalog == nil && technitium.CatalogMemberTypes[z.Type] {
			needsDefault = true
		}
	}
	state, err := a.cluster(ctx)
	if err != nil {
		if a.desired.Cluster == nil && !needsDefault {
			return "", nil
		}
		// Guessing "standalone" here would create zones that never reach
		// the secondaries without saying so.
		return "", fmt.Errorf("read cluster state to choose zone catalogs (the account needs Administration view permission; or set catalog on each zone, \"\" for none): %w", err)
	}
	if !state.ClusterInitialized {
		return "", nil
	}
	if self, ok := state.Self(); !ok || self.Type != technitium.ClusterNodeTypePrimary {
		return "", nil
	}
	return state.CatalogZone(), nil
}

func (a *applier) applyZones(ctx context.Context, clusterCatalog string) error {
	if len(a.desired.Zones) == 0 {
		return nil
	}
	byName, err := a.zoneInventory(ctx)
	if err != nil {
		return err
	}

	for _, z := range technitium.OrderZones(a.desired.Zones) {
		item := "zone " + z.Zone
		key := technitium.ZoneKey(z.Zone)
		current, exists := byName[key]
		justCreated := false

		if !exists {
			err := a.client.CreateZone(ctx, z.CreateRequest(clusterCatalog))
			switch {
			case err == nil:
				a.created++
				justCreated = true
				slog.Info("Created zone", "zone", z.Zone, "type", z.Type)
			case errors.Is(err, technitium.ErrAlreadyExists):
				// Created since the inventory was read: plan from its real state.
				if byName, err = a.zoneInventory(ctx); err != nil {
					return err
				}
				current, exists = byName[key]
			default:
				a.fail(item, err)
				continue
			}
		}
		if exists {
			if !strings.EqualFold(string(current.Type), string(z.Type)) {
				a.conflict(item, fmt.Sprintf("Zone exists as %s, not %s; left unchanged", current.Type, z.Type))
				continue
			}
			a.unchanged++
			slog.Debug("Zone exists", "zone", z.Zone)
		}

		currentCatalog := technitium.CanonicalName(current.Catalog)
		opts := z.OptionsUpdate(currentCatalog, clusterCatalog)
		if err := a.setZoneOptions(ctx, opts, justCreated); err != nil {
			a.fail(item+" options", err)
			continue
		}
		a.applied++

		var overrides technitium.CatalogOverrides
		if !justCreated && z.MemberAfterOptions(currentCatalog, clusterCatalog) && z.NeedsOverrideCheck() {
			o, err := a.client.GetZoneOptions(ctx, z.Zone)
			if err != nil {
				a.fail(item+" options", err)
				continue
			}
			overrides = technitium.CatalogOverrides{QueryAccess: o.OverrideCatalogQueryAccess, ZoneTransfer: o.OverrideCatalogZoneTransfer, Notify: o.OverrideCatalogNotify}
		}
		for _, group := range z.InheritedACLGroups(currentCatalog, clusterCatalog, overrides) {
			a.conflict(item, "Zone is a catalog member, so its declared "+group+" is not in effect; the catalog's applies")
		}
	}
	return nil
}

func (a *applier) zoneInventory(ctx context.Context) (map[string]technitium.ZoneSummary, error) {
	zones, err := a.client.ListZones(ctx)
	if err != nil {
		return nil, err
	}
	byName := make(map[string]technitium.ZoneSummary, len(zones))
	for _, z := range zones {
		byName[technitium.ZoneKey(z.Name)] = z
	}
	return byName, nil
}

// setZoneOptions retries briefly after creation, when the server can reject
// an options call for a zone it is still loading.
func (a *applier) setZoneOptions(ctx context.Context, opts technitium.ZoneOptionsUpdate, justCreated bool) error {
	attempts := 1
	if justCreated {
		attempts = 3
	}
	var err error
	for i := range attempts {
		if i > 0 {
			if err := sleepCtx(ctx, time.Second); err != nil {
				return err
			}
		}
		if err = a.client.SetZoneOptions(ctx, opts); err == nil {
			return nil
		}
	}
	return err
}

// planRecords groups the declared records against the zones the server has
// and the zones the file declares, and stops before any change when a
// record cannot be placed or a group is contradictory.
func (a *applier) planRecords(ctx context.Context) error {
	if len(a.desired.Records) == 0 {
		return nil
	}
	byName, err := a.zoneInventory(ctx)
	if err != nil {
		return err
	}
	zoneTypes := make(map[string]technitium.ZoneType, len(byName)+len(a.desired.Zones))
	for _, z := range a.desired.Zones {
		zoneTypes[technitium.ZoneKey(z.Zone)] = z.Type
	}
	// The server's type wins: a declared zone of another type is left alone.
	for name, z := range byName {
		zoneTypes[name] = z.Type
	}
	groups, issues := a.desired.GroupRecords(zoneTypes)
	if len(issues) > 0 {
		problems := make([]error, 0, len(issues))
		for _, is := range issues {
			problems = append(problems, fmt.Errorf("%s: %w", a.desired.RecordLabel(is.Index), is.Err))
		}
		return fmt.Errorf("records cannot be applied; nothing was changed: %w", errors.Join(problems...))
	}
	a.recordGroups = groups
	return nil
}

// applyRecords applies the planned record groups whose type matches.
func (a *applier) applyRecords(ctx context.Context, matches func(technitium.RecordType) bool) {
	for _, g := range a.recordGroups {
		if matches(g.Type) {
			a.applyRecordGroup(ctx, g)
		}
	}
}

func (a *applier) applyRecordGroup(ctx context.Context, g *technitium.RecordGroup) {
	item := fmt.Sprintf("record %s %s", g.Name, g.Type)
	records, err := a.recordsIn(ctx, g.Zone)
	if err != nil {
		a.fail(item, err)
		return
	}
	plan := technitium.PlanRecords(*g, records[g.Name+"|"+string(g.Type)])
	a.unchanged += plan.Unchanged
	for _, c := range plan.Conflicts {
		a.conflict(item, c)
	}
	if len(plan.Stale) > 0 {
		values := make([]string, 0, len(plan.Stale))
		for _, e := range plan.Stale {
			values = append(values, technitium.DescribeValue(e))
		}
		slog.Info("Record values on the server that the config does not list; left in place (recordPolicy: replace removes them)",
			"item", item, "values", values)
	}

	if plan.Replace {
		for i, rec := range plan.Add {
			overwrite := i == 0
			rec.Overwrite = &overwrite
			if _, err := a.client.AddRecord(ctx, rec); err != nil {
				a.fail(item, err)
				return
			}
		}
		a.applied++
		slog.Info("Replaced records", "item", item, "values", len(plan.Add))
		return
	}

	for _, rec := range plan.Add {
		if rec.Ptr != nil && *rec.Ptr {
			send, conflict, err := a.ptrNeeded(ctx, rec)
			if err != nil {
				a.fail(item, err)
				continue
			}
			if conflict != "" {
				a.conflict(item, conflict)
			}
			if !send {
				noPtr := false
				rec.Ptr = &noPtr
			}
		}
		_, err := a.client.AddRecord(ctx, rec)
		switch {
		case err == nil:
			a.created++
			slog.Info("Created record", "domain", rec.Domain, "type", rec.Type)
		case errors.Is(err, technitium.ErrAlreadyExists):
			// The server found it identical where the local comparison did not.
			a.unchanged++
		case errors.Is(err, technitium.ErrSingletonRecordExists):
			a.conflict(item, "Record exists with a different value; left unchanged (use recordPolicy: replace to replace it)")
		default:
			a.fail(item, err)
		}
	}
}

// recordsIn returns zone's records keyed by "name|TYPE", reading each zone once.
func (a *applier) recordsIn(ctx context.Context, zone string) (map[string][]technitium.RecordEntry, error) {
	if recs, ok := a.zoneRecords[zone]; ok {
		return recs, nil
	}
	entries, err := a.client.ListZoneRecords(ctx, zone)
	if err != nil {
		return nil, err
	}
	recs := map[string][]technitium.RecordEntry{}
	for _, e := range entries {
		key := technitium.CanonicalName(e.Name) + "|" + string(e.Type.Canonical())
		recs[key] = append(recs[key], e)
	}
	if a.zoneRecords == nil {
		a.zoneRecords = map[string]map[string][]technitium.RecordEntry{}
	}
	a.zoneRecords[zone] = recs
	return recs, nil
}

// ptrNeeded decides whether adding a forward record should also write its
// PTR. The server overwrites an existing PTR, so under create-if-absent an
// existing one is kept: send is false, and conflict explains a mismatch.
func (a *applier) ptrNeeded(ctx context.Context, rec technitium.AddRecordRequest) (send bool, conflict string, err error) {
	addr, err := technitium.ParseIP(rec.IPAddress)
	if err != nil {
		// The server writes the PTR before it checks the forward record, so
		// a PTR that cannot be inspected is never sent.
		return false, "", fmt.Errorf("cannot check the PTR for %q: %w", rec.IPAddress, err)
	}
	entries, err := a.client.GetRecords(ctx, technitium.ReverseName(addr), "")
	if errors.Is(err, technitium.ErrNotFound) {
		// No reverse zone yet: createPtrZone decides on the server.
		return true, "", nil
	}
	if err != nil {
		return false, "", err
	}
	for _, e := range entries {
		if !strings.EqualFold(string(e.Type), string(technitium.RT_PTR)) {
			continue
		}
		var target string
		_ = json.Unmarshal(e.RData["ptrName"], &target)
		if technitium.CanonicalName(target) == technitium.CanonicalName(rec.Domain) {
			return false, "", nil
		}
		return false, fmt.Sprintf("the PTR for %s points to %s; left unchanged (use recordPolicy: replace to replace it)", rec.IPAddress, target), nil
	}
	return true, "", nil
}

func (a *applier) applyApps(ctx context.Context) {
	for _, app := range a.desired.Apps {
		item := "app " + app.Name
		config, hasConfig, err := app.ConfigJSON()
		if err != nil {
			a.fail(item+" config", err)
			continue
		}

		// config/get doubles as the installed check and the current config.
		current, err := a.client.GetAppConfig(ctx, app.Name)
		switch {
		case err == nil:
			a.unchanged++
			slog.Debug("App installed", "app", app.Name)
		case errors.Is(err, technitium.ErrNotFound) && app.Url == "":
			a.fail(item, errors.New("the app is not installed and has no url to install it from"))
			continue
		case errors.Is(err, technitium.ErrNotFound):
			if err := a.client.InstallApp(ctx, app.Name, app.Url); err != nil && !errors.Is(err, technitium.ErrAlreadyExists) {
				a.fail(item, err)
				continue
			}
			a.created++
			slog.Info("Installed app", "app", app.Name)
			current = ""
		default:
			a.fail(item, err)
			continue
		}

		if !hasConfig {
			continue
		}
		if technitium.SameJSON(current, config) {
			slog.Debug("App config unchanged", "app", app.Name)
			continue
		}
		if err := a.client.SetAppConfig(ctx, app.Name, config); err != nil {
			a.fail(item+" config", err)
			continue
		}
		a.applied++
		slog.Info("App config applied", "app", app.Name)
	}
}

func (a *applier) applyAdministration(ctx context.Context) {
	adm := a.desired.Administration
	if adm == nil {
		return
	}
	if len(adm.Groups) > 0 {
		a.applyGroups(ctx, adm.Groups)
	}
	if len(adm.Users) > 0 {
		a.applyUsers(ctx, adm.Users)
	}
	if len(adm.Permissions) == 0 {
		return
	}
	known, err := a.principals(ctx)
	if err != nil {
		a.fail("permissions", err)
		return
	}
	for _, p := range adm.Permissions {
		a.applyPermissions(ctx, p, known)
	}
}

// principals are the users and groups on the server, by lower-case name.
type principals struct{ users, groups map[string]bool }

func (a *applier) principals(ctx context.Context) (principals, error) {
	p := principals{users: map[string]bool{}, groups: map[string]bool{}}
	users, err := a.client.ListUsers(ctx)
	if err != nil {
		return p, err
	}
	for _, u := range users {
		p.users[strings.ToLower(u.Username)] = true
	}
	groups, err := a.client.ListGroups(ctx)
	if err != nil {
		return p, err
	}
	for _, g := range groups {
		p.groups[strings.ToLower(g.Name)] = true
	}
	// groups/list leaves out the built-in Everyone group.
	p.groups["everyone"] = true
	return p, nil
}

func (a *applier) applyGroups(ctx context.Context, groups []technitium.GroupConfig) {
	existing, err := a.client.ListGroups(ctx)
	if err != nil {
		a.fail("groups", err)
		return
	}
	byName := map[string]technitium.ServerGroup{}
	for _, g := range existing {
		byName[strings.ToLower(g.Name)] = g
	}
	for _, g := range groups {
		item := "group " + g.Name
		cur, ok := byName[strings.ToLower(g.Name)]
		if !ok {
			desc := ""
			if g.Description != nil {
				desc = *g.Description
			}
			if err := a.client.CreateGroup(ctx, g.Name, desc); err != nil {
				a.fail(item, err)
				continue
			}
			a.created++
			slog.Info("Created group", "group", g.Name)
			continue
		}
		a.unchanged++
		if g.Description != nil && *g.Description != cur.Description {
			if err := a.client.SetGroupDescription(ctx, cur.Name, *g.Description); err != nil {
				a.fail(item, err)
				continue
			}
			a.applied++
		}
	}
}

func (a *applier) applyUsers(ctx context.Context, users []technitium.UserConfig) {
	existing, err := a.client.ListUsers(ctx)
	if err != nil {
		a.fail("users", err)
		return
	}
	known := map[string]bool{}
	for _, u := range existing {
		known[strings.ToLower(u.Username)] = true
	}
	for _, u := range users {
		item := "user " + u.Username
		if !known[strings.ToLower(u.Username)] {
			password, err := u.InitialPassword()
			if err != nil {
				a.fail(item, err)
				continue
			}
			// The password is never compared or changed after creation.
			displayName := ""
			if u.DisplayName != nil {
				displayName = *u.DisplayName
			}
			if err := a.client.CreateUser(ctx, u.Username, password, displayName); err != nil {
				a.fail(item, err)
				continue
			}
			a.created++
			slog.Info("Created user", "user", u.Username)
		} else {
			a.unchanged++
		}

		cur, err := a.client.GetUser(ctx, u.Username)
		if err != nil {
			a.fail(item, err)
			continue
		}
		var displayName *string
		if u.DisplayName != nil && *u.DisplayName != cur.DisplayName {
			displayName = u.DisplayName
		}
		var disabled *bool
		if u.Disabled != nil && *u.Disabled != cur.Disabled {
			disabled = u.Disabled
		}
		var timeout *int
		if u.SessionTimeoutSeconds != nil && *u.SessionTimeoutSeconds != cur.SessionTimeoutSeconds {
			timeout = u.SessionTimeoutSeconds
		}
		// Membership is merged: groups the file does not name are kept.
		var groups []string
		if missing := missingGroups(u.Groups, cur.MemberOfGroups); len(missing) > 0 {
			groups = append(append([]string(nil), cur.MemberOfGroups...), missing...)
		}
		if displayName == nil && disabled == nil && timeout == nil && groups == nil {
			continue
		}
		if err := a.client.SetUser(ctx, cur.Username, displayName, disabled, timeout, groups); err != nil {
			a.fail(item, err)
			continue
		}
		a.applied++
		slog.Info("Updated user", "user", u.Username)
	}
}

func missingGroups(want, have []string) []string {
	var missing []string
	for _, w := range want {
		found := false
		for _, h := range have {
			if strings.EqualFold(w, h) {
				found = true
				break
			}
		}
		if !found {
			missing = append(missing, w)
		}
	}
	return missing
}

func (a *applier) applyPermissions(ctx context.Context, p technitium.PermissionConfig, known principals) {
	item := "permissions " + p.Section
	// The server drops grants for names it does not know without an error,
	// so a misspelt name would never be granted and would be re-sent on
	// every run.
	var unknown []string
	for name := range p.Groups {
		if !known.groups[strings.ToLower(name)] {
			unknown = append(unknown, "group "+name)
		}
	}
	for name := range p.Users {
		if !known.users[strings.ToLower(name)] {
			unknown = append(unknown, "user "+name)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		a.fail(item, fmt.Errorf("no such %s on the server; declare it under administration or create it first", strings.Join(unknown, ", ")))
		return
	}
	cur, err := a.client.GetPermissions(ctx, p.Section)
	if err != nil {
		a.fail(item, err)
		return
	}
	users, usersChanged := technitium.MergePermissions(cur.UserPermissions, p.Users)
	groups, groupsChanged := technitium.MergePermissions(cur.GroupPermissions, p.Groups)
	if !usersChanged && !groupsChanged {
		a.unchanged++
		return
	}
	kept, err := a.client.SetPermissions(ctx, p.Section, users, groups)
	if err != nil {
		a.fail(item, err)
		return
	}
	_, usersMissing := technitium.MergePermissions(kept.UserPermissions, p.Users)
	_, groupsMissing := technitium.MergePermissions(kept.GroupPermissions, p.Groups)
	if usersMissing || groupsMissing {
		a.fail(item, errors.New("the server did not keep every declared grant"))
		return
	}
	a.applied++
	slog.Info("Permissions applied", "section", p.Section)
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
