package technitium

import (
	"errors"
	"fmt"
	"sort"
)

// desiredCatalog returns the catalog the zone should belong to, or nil to
// leave membership unmanaged. An explicit catalog wins, including "" for
// none; otherwise member-capable zones on a cluster primary join the cluster
// catalog, which is how zones replicate to secondary nodes.
func (z ZoneConfig) desiredCatalog(clusterCatalog string) *string {
	if z.Catalog != nil {
		return z.Catalog
	}
	if clusterCatalog != "" && CatalogMemberTypes[z.Type] {
		return &clusterCatalog
	}
	return nil
}

// CreateRequest returns the zones/create request for z.
func (z ZoneConfig) CreateRequest(clusterCatalog string) ZoneCreateRequest {
	req := z.ZoneCreateRequest
	req.Catalog = nil
	// The server rejects an empty catalog on create; "" only means "none".
	if c := z.desiredCatalog(clusterCatalog); c != nil && *c != "" {
		req.Catalog = c
	}
	return req
}

// OptionsUpdate returns the zones/options/set request for z. currentCatalog
// is the zone's membership on the server ("" when it has none or does not
// exist yet).
func (z ZoneConfig) OptionsUpdate(currentCatalog, clusterCatalog string) ZoneOptionsUpdate {
	catalog := z.desiredCatalog(clusterCatalog)
	// The cluster default never moves a zone an operator put in another catalog.
	if z.Catalog == nil && currentCatalog != "" {
		catalog = nil
	}

	opts := ZoneOptionsUpdate{
		Zone:                       z.Zone,
		Disabled:                   z.Disabled,
		Catalog:                    catalog,
		PrimaryNameServerAddresses: z.PrimaryNameServerAddresses,
		PrimaryXfrProto:            z.ZoneTransferProtocol,
		PrimaryXfrTsigKey:          z.TsigKeyName,
		ValidateZone:               z.ValidateZone,
		OverrideCatalogQueryAccess: z.OverrideCatalogQueryAccess,
		OverrideCatalogZoneXfr:     z.OverrideCatalogZoneTransfer,
		OverrideCatalogNotify:      z.OverrideCatalogNotify,
	}
	if z.ACLSettings != nil {
		opts.ACLSettings = *z.ACLSettings
	}
	return opts
}

// MemberAfterOptions reports whether z will be a catalog member once
// OptionsUpdate has been applied.
func (z ZoneConfig) MemberAfterOptions(currentCatalog, clusterCatalog string) bool {
	switch {
	case z.Catalog != nil:
		return *z.Catalog != ""
	case currentCatalog != "":
		return true
	default:
		return z.desiredCatalog(clusterCatalog) != nil
	}
}

// CatalogOverrides are a zone's current catalog override flags.
type CatalogOverrides struct{ QueryAccess, ZoneTransfer, Notify bool }

// InheritedACLGroups names the aclSettings groups z declares that will not
// take effect without the file saying so: the zone is a catalog member, the
// file does not set the group's override, and the server's override is off,
// so the catalog's settings apply. Setting the override to false is an
// explicit choice to inherit and is not reported. Overrides are never turned
// on implicitly, because on a cluster the catalog's zone transfer and notify
// settings are what replicate the zone to secondaries.
func (z ZoneConfig) InheritedACLGroups(currentCatalog, clusterCatalog string, current CatalogOverrides) []string {
	if z.ACLSettings == nil || !z.MemberAfterOptions(currentCatalog, clusterCatalog) {
		return nil
	}
	inherits := func(declared *bool, cur bool) bool { return declared == nil && !cur }
	acl := z.ACLSettings
	var groups []string
	if inherits(z.OverrideCatalogQueryAccess, current.QueryAccess) && (acl.QueryAccess != nil || acl.QueryAccessNetworkACL != nil) {
		groups = append(groups, "query access (set overrideCatalogQueryAccess)")
	}
	if inherits(z.OverrideCatalogZoneTransfer, current.ZoneTransfer) &&
		(acl.ZoneTransfer != nil || acl.ZoneTransferNetworkACL != nil || acl.ZoneTransferTsigKeys != nil) {
		groups = append(groups, "zone transfer (set overrideCatalogZoneTransfer)")
	}
	if inherits(z.OverrideCatalogNotify, current.Notify) && (acl.Notify != nil || acl.NotifyNameServers != nil) {
		groups = append(groups, "notify (set overrideCatalogNotify)")
	}
	return groups
}

// NeedsOverrideCheck reports whether InheritedACLGroups depends on the
// server's current override flags, which costs an options read.
func (z ZoneConfig) NeedsOverrideCheck() bool {
	return z.ACLSettings != nil &&
		(z.OverrideCatalogQueryAccess == nil || z.OverrideCatalogZoneTransfer == nil || z.OverrideCatalogNotify == nil)
}

// OrderZones returns zones with catalog zones first, so member zones can
// reference a catalog declared later in the file.
func OrderZones(zones []ZoneConfig) []ZoneConfig {
	ordered := append([]ZoneConfig(nil), zones...)
	sort.SliceStable(ordered, func(i, j int) bool {
		return isCatalogType(ordered[i].Type) && !isCatalogType(ordered[j].Type)
	})
	return ordered
}

func isCatalogType(t ZoneType) bool { return t == ZoneCatalog || t == ZoneSecondaryCatalog }

// MergeTsigKeys returns the configured keys plus any server keys the config
// does not name, such as the cluster catalog key. Names compare as the server
// compares them: case-insensitive, IDNA and without a trailing dot.
func MergeTsigKeys(existing, configured []TsigKey) []TsigKey {
	merged := make([]TsigKey, len(configured), len(configured)+len(existing))
	copy(merged, configured)
	for _, e := range existing {
		named := false
		for _, c := range configured {
			if SameName(c.KeyName, e.KeyName) {
				named = true
				break
			}
		}
		if !named {
			merged = append(merged, e)
		}
	}
	return merged
}

// RecordGroup is the declared records for one name and type in one zone.
type RecordGroup struct {
	Zone, Name string
	Type       RecordType
	Policy     string
	Records    []AddRecordRequest
}

// RecordPlan says what a run does for one group.
type RecordPlan struct {
	// Add lists the values to add. With Replace it is the complete set,
	// written so that it replaces whatever is there.
	Add       []AddRecordRequest
	Replace   bool
	Unchanged int
	Conflicts []string
	// Stale lists values on the server the file does not declare. Merge
	// leaves them in place and reports them.
	Stale []RecordEntry
}

// RecordIssue is a declared record a run cannot apply. Index is its
// position in Config.Records. NoZone marks a record no known zone contains,
// which validation cannot judge without the server's zones.
type RecordIssue struct {
	Index  int
	NoZone bool
	Err    error
}

// GroupRecords places each declared record in its zone, the one it names
// or else the closest of zoneTypes that contains it, and groups records by
// zone, name and type. It reports records no zone contains or that name a
// zone that does not exist, groups whose records resolve to different
// policies, single-value types declared with several values, and FWD
// records outside Forwarder zones. A run calls it with the server's and the
// declared zones before changing anything.
//
// With nil zoneTypes the zones are unknown, as during validation: records
// are grouped by name and type, and only what holds wherever they land is
// reported, namely several values for a single-value type and different
// explicit record policies.
func (c *Config) GroupRecords(zoneTypes map[string]ZoneType) ([]*RecordGroup, []RecordIssue) {
	known := zoneTypes != nil
	zones := make([]string, 0, len(zoneTypes))
	for z := range zoneTypes {
		zones = append(zones, z)
	}
	// Longest first, so the closest enclosing zone wins, as on the server.
	sort.Slice(zones, func(i, j int) bool { return zoneDepth(zones[i]) > zoneDepth(zones[j]) })

	type key struct {
		zone, name string
		typ        RecordType
	}
	var (
		groups  []*RecordGroup
		issues  []RecordIssue
		byKey   = map[key]*RecordGroup{}
		values  = map[key]map[string]bool{}
		reports = map[key]bool{}
	)
	for i, r := range c.Records {
		name, typ := CanonicalName(r.Domain), r.Type.Canonical()
		zone := ""
		if r.Zone != nil {
			zone = ZoneKey(*r.Zone)
		} else {
			for _, z := range zones {
				if InZone(name, z) {
					zone = z
					break
				}
			}
		}
		_, exists := zoneTypes[zone]
		switch {
		case !known:
		case zone == "":
			issues = append(issues, RecordIssue{i, true, errors.New("no zone contains this name; declare the zone or set zone on the record")})
		case !exists:
			issues = append(issues, RecordIssue{i, true, fmt.Errorf("zone %s does not exist and is not declared", *r.Zone)})
		default:
			r.Zone = &zone
		}
		if zt, known := zoneTypes[zone]; known && typ == RT_FWD && zt != ZoneForwarder {
			issues = append(issues, RecordIssue{Index: i, Err: fmt.Errorf("FWD records belong in Forwarder zones; zone %q is %s", zone, zt)})
		}
		policy := c.PolicyFor(r, zone)
		if !known {
			// The zone's own policy depends on where the record lands.
			policy = ""
			if r.RecordPolicy != nil {
				policy = *r.RecordPolicy
			}
		}
		k := key{zone, name, typ}
		g := byKey[k]
		if g == nil {
			g = &RecordGroup{Zone: zone, Name: name, Type: typ, Policy: policy}
			byKey[k] = g
			values[k] = map[string]bool{}
			groups = append(groups, g)
		}
		switch {
		case !known && (g.Policy == "" || policy == ""):
			if g.Policy == "" {
				g.Policy = policy
			}
		case g.Policy != policy:
			issues = append(issues, RecordIssue{Index: i, Err: fmt.Errorf("records for this name and type use both %q and %q record policies", g.Policy, policy)})
			continue
		}
		values[k][r.ValueKey()] = true
		if SingleValueTypes[typ] && len(values[k]) > 1 && !reports[k] {
			reports[k] = true
			issues = append(issues, RecordIssue{Index: i, Err: fmt.Errorf("a name can have only one %s record; another value is declared for it", typ)})
		}
		g.Records = append(g.Records, r)
	}
	return groups, issues
}

// PlanRecords decides what to do for g given the records at its name and
// type. g comes from GroupRecords without issues.
func PlanRecords(g RecordGroup, existing []RecordEntry) RecordPlan {
	var plan RecordPlan
	declared := dedupeRecords(g.Records)

	existingKeys := map[string]RecordEntry{}
	for _, e := range existing {
		existingKeys[ValueKeyOf(e)] = e
	}
	declaredKeys := map[string]bool{}
	for _, d := range declared {
		declaredKeys[d.ValueKey()] = true
	}

	if g.Policy == PolicyReplace {
		if sameRecordSet(declared, existing, existingKeys) {
			plan.Unchanged = len(declared)
			return plan
		}
		plan.Replace = true
		plan.Add = declared
		return plan
	}

	for _, d := range declared {
		if _, ok := existingKeys[d.ValueKey()]; ok {
			plan.Unchanged++
			continue
		}
		if SingleValueTypes[g.Type] && len(existing) > 0 {
			plan.Conflicts = append(plan.Conflicts, fmt.Sprintf("a %s exists with a different value (%s); left unchanged (use recordPolicy: replace to replace it)", g.Type, DescribeValue(existing[0])))
			continue
		}
		plan.Add = append(plan.Add, d)
	}
	for _, e := range existing {
		if !declaredKeys[ValueKeyOf(e)] && !SingleValueTypes[g.Type] {
			plan.Stale = append(plan.Stale, e)
		}
	}
	return plan
}

// sameRecordSet reports whether existing holds exactly the declared values,
// with the declared TTL, comments, expiry TTL and NS glue where the file
// gives them.
func sameRecordSet(declared []AddRecordRequest, existing []RecordEntry, existingKeys map[string]RecordEntry) bool {
	if len(declared) != len(existing) {
		return false
	}
	for _, d := range declared {
		e, ok := existingKeys[d.ValueKey()]
		switch {
		case !ok:
			return false
		case d.TTL != nil && *d.TTL != e.TTL:
			return false
		case d.Comments != nil && *d.Comments != e.Comments:
			return false
		case d.ExpiryTTL != nil && *d.ExpiryTTL != e.ExpiryTTL:
			return false
		case d.Glue != "" && !SameGlue(d.Glue, e.GlueRecords):
			return false
		}
	}
	return true
}

func dedupeRecords(records []AddRecordRequest) []AddRecordRequest {
	seen := map[string]bool{}
	var out []AddRecordRequest
	for _, r := range records {
		k := r.ValueKey()
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, r)
	}
	return out
}
