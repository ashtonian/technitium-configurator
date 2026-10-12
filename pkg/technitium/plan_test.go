package technitium

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func ptr[T any](v T) *T { return &v }

const clusterCatalog = "cluster-catalog.dns.example.test"

func zoneConfig(name string, typ ZoneType, catalog *string) ZoneConfig {
	return ZoneConfig{ZoneCreateRequest: ZoneCreateRequest{Zone: name, Type: typ, Catalog: catalog}}
}

func TestCreateRequestCatalog(t *testing.T) {
	tests := []struct {
		name           string
		zone           ZoneConfig
		clusterCatalog string
		want           *string
	}{
		{"primary joins the cluster catalog by default", zoneConfig("example.test", ZonePrimary, nil), clusterCatalog, ptr(clusterCatalog)},
		{"no cluster, no catalog", zoneConfig("example.test", ZonePrimary, nil), "", nil},
		{"explicit catalog wins", zoneConfig("example.test", ZoneForwarder, ptr("mine.example.test")), clusterCatalog, ptr("mine.example.test")},
		{"explicit empty opts out and is not sent on create", zoneConfig("example.test", ZonePrimary, ptr("")), clusterCatalog, nil},
		{"catalog zones are never members", zoneConfig("catalog.example.test", ZoneCatalog, nil), clusterCatalog, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.zone.CreateRequest(tt.clusterCatalog).Catalog)
		})
	}
}

func TestOptionsUpdate(t *testing.T) {
	t.Run("zone in another catalog stays there", func(t *testing.T) {
		assert.Nil(t, zoneConfig("example.test", ZonePrimary, nil).OptionsUpdate("other.example.test", clusterCatalog).Catalog)
	})

	t.Run("explicit empty values are sent so they clear the option", func(t *testing.T) {
		z := zoneConfig("example.test", ZonePrimary, ptr(""))
		z.ACLSettings = &ACLSettings{UpdateNetworkACL: []string{}, QueryAccessNetworkACL: nil}
		form, err := jsonToFormValues(z.OptionsUpdate(clusterCatalog, clusterCatalog))
		require.NoError(t, err)
		assert.True(t, form.Has("catalog"))
		assert.Equal(t, "", form.Get("catalog"))
		assert.True(t, form.Has("updateNetworkACL"), "an explicit [] must be sent")
		assert.Equal(t, "", form.Get("updateNetworkACL"))
		assert.False(t, form.Has("queryAccessNetworkACL"), "an omitted list must not be sent")
	})

	t.Run("overrides are passed through, never turned on implicitly", func(t *testing.T) {
		z := zoneConfig("example.test", ZonePrimary, nil)
		z.ACLSettings = &ACLSettings{QueryAccess: ptr(AccessAllowOnlyPrivateNetworks)}
		z.OverrideCatalogZoneTransfer = ptr(false)
		opts := z.OptionsUpdate("", clusterCatalog)
		assert.Nil(t, opts.OverrideCatalogQueryAccess)
		assert.Equal(t, ptr(false), opts.OverrideCatalogZoneXfr)
	})
}

func TestInheritedACLGroups(t *testing.T) {
	acl := &ACLSettings{
		QueryAccess:          ptr(AccessAllowOnlyPrivateNetworks),
		ZoneTransferTsigKeys: []string{"external-dns"},
		Update:               ptr(UpdateUseSpecifiedNetworkACL),
	}
	withACL := func(catalog *string) ZoneConfig {
		z := zoneConfig("example.test", ZonePrimary, catalog)
		z.ACLSettings = acl
		return z
	}

	t.Run("cluster member without overrides", func(t *testing.T) {
		assert.Equal(t, []string{
			"query access (set overrideCatalogQueryAccess)",
			"zone transfer (set overrideCatalogZoneTransfer)",
		}, withACL(nil).InheritedACLGroups("", clusterCatalog, CatalogOverrides{}))
	})

	t.Run("override already on on the server", func(t *testing.T) {
		groups := withACL(nil).InheritedACLGroups(clusterCatalog, clusterCatalog, CatalogOverrides{QueryAccess: true})
		assert.Equal(t, []string{"zone transfer (set overrideCatalogZoneTransfer)"}, groups)
	})

	t.Run("declared overrides win over the server's", func(t *testing.T) {
		z := withACL(nil)
		z.OverrideCatalogQueryAccess = ptr(true)
		z.OverrideCatalogZoneTransfer = ptr(false)
		assert.Empty(t, z.InheritedACLGroups("", clusterCatalog, CatalogOverrides{}), "false is an explicit choice to inherit")
		assert.False(t, z.NeedsOverrideCheck() && z.OverrideCatalogNotify != nil)
	})

	t.Run("not a member", func(t *testing.T) {
		assert.Empty(t, withACL(nil).InheritedACLGroups("", "", CatalogOverrides{}))
		assert.Empty(t, withACL(ptr("")).InheritedACLGroups(clusterCatalog, clusterCatalog, CatalogOverrides{}))
	})
}

func TestOrderZones(t *testing.T) {
	zones := []ZoneConfig{
		zoneConfig("member.test", ZonePrimary, ptr("catalog.test")),
		zoneConfig("catalog.test", ZoneCatalog, nil),
		zoneConfig("other.test", ZoneForwarder, nil),
	}
	var names []string
	for _, z := range OrderZones(zones) {
		names = append(names, z.Zone)
	}
	assert.Equal(t, []string{"catalog.test", "member.test", "other.test"}, names)
}

func TestMergeTsigKeys(t *testing.T) {
	existing := []TsigKey{
		{KeyName: "cluster-catalog.dns.example.test", AlgorithmName: "hmac-sha256", SharedSecret: "server"},
		{KeyName: "dotted.test", AlgorithmName: "hmac-sha256", SharedSecret: "old"},
	}
	configured := []TsigKey{{KeyName: "Dotted.Test.", AlgorithmName: "hmac-sha512", SharedSecret: "new"}}
	assert.Equal(t, []TsigKey{
		{KeyName: "Dotted.Test.", AlgorithmName: "hmac-sha512", SharedSecret: "new"},
		{KeyName: "cluster-catalog.dns.example.test", AlgorithmName: "hmac-sha256", SharedSecret: "server"},
	}, MergeTsigKeys(existing, configured), "a trailing dot or case difference names the same key")
}

func entry(typ RecordType, ttl int, rdata string) RecordEntry {
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(rdata), &m); err != nil {
		panic(err)
	}
	return RecordEntry{Name: "www.example.test", Type: typ, TTL: ttl, RData: m}
}

func aRecord(ip string, ttl *int) AddRecordRequest {
	return AddRecordRequest{Domain: "www.example.test", Type: RT_A, IPAddress: ip, RecordMeta: RecordMeta{TTL: ttl}}
}

func TestPlanRecordsMerge(t *testing.T) {
	existing := []RecordEntry{
		entry(RT_A, 300, `{"ipAddress":"192.0.2.1"}`),
		entry(RT_A, 300, `{"ipAddress":"192.0.2.9"}`),
	}
	g := RecordGroup{Type: RT_A, Policy: PolicyMerge, Records: []AddRecordRequest{aRecord("192.0.2.1", nil), aRecord("192.0.2.2", nil)}}
	plan := PlanRecords(g, existing)
	assert.Equal(t, 1, plan.Unchanged, "an existing value is not sent again")
	require.Len(t, plan.Add, 1)
	assert.Equal(t, "192.0.2.2", plan.Add[0].IPAddress)
	require.Len(t, plan.Stale, 1)
	assert.Equal(t, "192.0.2.9", DescribeValue(plan.Stale[0]))
	assert.False(t, plan.Replace)
}

func TestPlanRecordsMergeSingleValue(t *testing.T) {
	existing := []RecordEntry{entry(RT_CNAME, 300, `{"cname":"WWW.target.test"}`)}

	same := RecordGroup{Type: RT_CNAME, Policy: PolicyMerge, Records: []AddRecordRequest{{Domain: "www.example.test", Type: RT_CNAME, CName: "www.target.test."}}}
	plan := PlanRecords(same, existing)
	assert.Equal(t, 1, plan.Unchanged)
	assert.Empty(t, plan.Conflicts)

	other := RecordGroup{Type: RT_CNAME, Policy: PolicyMerge, Records: []AddRecordRequest{{Domain: "www.example.test", Type: RT_CNAME, CName: "elsewhere.test"}}}
	plan = PlanRecords(other, existing)
	assert.Empty(t, plan.Add)
	require.Len(t, plan.Conflicts, 1)

	app := RecordGroup{Type: RT_APP, Policy: PolicyMerge, Records: []AddRecordRequest{{Domain: "www.example.test", Type: RT_APP, AppName: "NO DATA", ClassPath: "NoData.App", RecordData: `{"blockedTypes": ["AAAA"]}`}}}
	plan = PlanRecords(app, []RecordEntry{entry(RT_APP, 60, `{"appName":"NO DATA","classPath":"NoData.App","data":"{\n  \"blockedTypes\": [ \"AAAA\" ] // ipv6\n}"}`)})
	assert.Equal(t, 1, plan.Unchanged, "an identical APP record is recognised, comments and formatting aside")

}

func TestGroupRecords(t *testing.T) {
	cfg, err := load(`
recordPolicy: merge
zones:
  - {zone: example.test, type: Primary, recordPolicy: replace}
records:
  - {domain: www.example.test, type: A, ipAddress: 192.0.2.1}
  - {domain: WWW.example.test., type: a, ipAddress: 192.0.2.2}
  - {domain: www.sub.example.test, type: A, ipAddress: 192.0.2.3}
  - {domain: host.other.test, type: A, ipAddress: 192.0.2.4}
`)
	require.NoError(t, err, "validation has no server zones, so an undeclared zone is not an error yet")

	// The server also has sub.example.test, so that record belongs there.
	groups, issues := cfg.GroupRecords(map[string]ZoneType{"example.test": ZonePrimary, "sub.example.test": ZonePrimary})
	require.Len(t, issues, 1)
	assert.True(t, issues[0].NoZone)
	assert.Equal(t, 3, issues[0].Index)
	require.Len(t, groups, 3)
	assert.Equal(t, "example.test", groups[0].Zone)
	assert.Len(t, groups[0].Records, 2, "names and types are compared canonically")
	assert.Equal(t, PolicyReplace, groups[0].Policy, "the zone's policy applies")
	assert.Equal(t, "sub.example.test", groups[1].Zone, "the closest zone wins")
	assert.Equal(t, PolicyMerge, groups[1].Policy, "a zone without its own policy takes the file's")
	require.NotNil(t, groups[0].Records[0].Zone)
	assert.Equal(t, "example.test", *groups[0].Records[0].Zone, "records are sent with their zone")
}

func TestGroupRecordsServerOnlyZone(t *testing.T) {
	_, err := load("zones:\n  - {zone: r4.test, type: Primary}\nrecords:\n  - {domain: nested.r4.test, type: FWD, forwarder: 192.0.2.53}\n" +
		"  - {domain: a.r4.test, zone: missing.test, type: A, ipAddress: 192.0.2.1}\n")
	require.Error(t, err, "a record outside the zone it names is caught offline")
	cfg, err := load("zones:\n  - {zone: r4.test, type: Primary}\nrecords:\n  - {domain: nested.r4.test, type: FWD, forwarder: 192.0.2.53}\n" +
		"  - {domain: a.missing.test, zone: missing.test, type: A, ipAddress: 192.0.2.1}\n")
	require.NoError(t, err)

	groups, issues := cfg.GroupRecords(map[string]ZoneType{"r4.test": ZonePrimary, "nested.r4.test": ZoneForwarder})
	require.Len(t, issues, 1)
	assert.ErrorContains(t, issues[0].Err, "zone missing.test does not exist")
	assert.Equal(t, "nested.r4.test", groups[0].Zone, "the FWD record lands in the server's closer Forwarder zone")
}

func TestGroupRecordsIssues(t *testing.T) {
	cfg := &Config{Records: []AddRecordRequest{
		{Domain: "x.example.test", Type: RT_CNAME, CName: "a.test"},
		{Domain: "x.example.test", Type: RT_CNAME, CName: "b.test"},
		{Domain: "f.example.test", Type: RT_FWD, Forwarder: "192.0.2.53"},
	}}
	_, issues := cfg.GroupRecords(map[string]ZoneType{"example.test": ZonePrimary})
	require.Len(t, issues, 2)
	assert.ErrorContains(t, issues[0].Err, "only one CNAME record")
	assert.ErrorContains(t, issues[1].Err, `zone "example.test" is Primary`)
}

func TestPlanRecordsReplace(t *testing.T) {
	existing := []RecordEntry{
		entry(RT_A, 300, `{"ipAddress":"192.0.2.1"}`),
		entry(RT_A, 300, `{"ipAddress":"192.0.2.9"}`),
	}
	g := RecordGroup{Type: RT_A, Policy: PolicyReplace, Records: []AddRecordRequest{aRecord("192.0.2.1", nil), aRecord("192.0.2.2", nil)}}
	plan := PlanRecords(g, existing)
	assert.True(t, plan.Replace)
	assert.Len(t, plan.Add, 2)

	same := RecordGroup{Type: RT_A, Policy: PolicyReplace, Records: []AddRecordRequest{aRecord("192.0.2.9", ptr(300)), aRecord("192.0.2.1", nil)}}
	plan = PlanRecords(same, existing)
	assert.False(t, plan.Replace, "the same set in any order is unchanged")
	assert.Equal(t, 2, plan.Unchanged)

	ttl := RecordGroup{Type: RT_A, Policy: PolicyReplace, Records: []AddRecordRequest{aRecord("192.0.2.9", ptr(60)), aRecord("192.0.2.1", nil)}}
	plan = PlanRecords(ttl, existing)
	assert.True(t, plan.Replace, "a declared TTL that differs rewrites the set")
}

func TestGroupRecordsRootZone(t *testing.T) {
	cfg, err := load(`
zones:
  - {zone: ".", type: Primary}
  - {zone: a, type: Primary}
records:
  - {domain: x.a, type: A, ipAddress: 192.0.2.1}
  - {domain: example, type: A, ipAddress: 192.0.2.2}
`)
	require.NoError(t, err, "the root zone is a zone, not a missing name")
	groups, issues := cfg.GroupRecords(map[string]ZoneType{".": ZonePrimary, "a": ZonePrimary})
	require.Empty(t, issues)
	require.Len(t, groups, 2)
	assert.Equal(t, "a", groups[0].Zone, "a top-level zone is closer than the root")
	assert.Equal(t, ".", groups[1].Zone)
	assert.Equal(t, ".", *groups[1].Records[0].Zone, "the root is sent as \".\"")
}
