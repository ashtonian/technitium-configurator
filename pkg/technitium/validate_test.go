package technitium

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadConfigMergesDocumentsAndFiles(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(p, []byte(body), 0o600))
		return p
	}
	write("10-base.yaml", "dnsSettings:\n  enableBlocking: false\nzones:\n  - {zone: a.test, type: Primary}\n---\nrecords:\n  - {domain: www.a.test, type: A, ipAddress: 192.0.2.1}\n")
	write("20-b.yml", "dnsSettings:\n  dnssecValidation: true\nzones:\n  - {zone: b.test, type: Primary}\n")
	write("notes.txt", "not yaml")

	cfg, err := LoadConfigPaths([]string{dir})
	require.NoError(t, err)
	assert.Len(t, cfg.Zones, 2)
	assert.Len(t, cfg.Records, 1)
	require.NotNil(t, cfg.DNSSettings.EnableBlocking)
	require.NotNil(t, cfg.DNSSettings.DnssecValidation)
	assert.False(t, *cfg.DNSSettings.EnableBlocking)
	assert.True(t, *cfg.DNSSettings.DnssecValidation)
}

func TestLoadConfigMergeConflicts(t *testing.T) {
	tests := []struct {
		name string
		docs []Source
		want string
	}{
		{"same setting twice", []Source{
			{"a.yaml", []byte("dnsSettings:\n  enableBlocking: false\n")},
			{"b.yaml", []byte("dnsSettings:\n  enableBlocking: true\n")},
		}, "dnsSettings.enableBlocking is set in both a.yaml and b.yaml"},
		{"cluster twice in one file", []Source{
			{"a.yaml", []byte("cluster: {mode: primary, domain: c.test, nodeIPs: 10.0.0.1}\n---\ncluster: {mode: primary, domain: c.test, nodeIPs: 10.0.0.1}\n")},
		}, "cluster is set in both a.yaml and a.yaml (document 2)"},
		{"duplicate zone across files", []Source{
			{"a.yaml", []byte("zones:\n  - {zone: a.test, type: Primary}\n")},
			{"b.yaml", []byte("zones:\n  - {zone: A.test., type: Primary}\n")},
		}, "b.yaml: zones[0] (A.test.): duplicate zone; first declared at a.yaml: zones[0] (a.test)"},
		{"duplicate user in a later document", []Source{
			{"a.yaml", []byte("administration:\n  users: [{username: ops}]\n---\nadministration:\n  users: [{username: OPS}]\n")},
		}, "a.yaml (document 2): administration.users[0] (OPS): duplicate user; first declared at a.yaml: administration.users[0] (ops)"},
		{"invalid setting names its document", []Source{
			{"a.yaml", []byte("zones: []\n")},
			{"b.yaml", []byte("zones: []\n---\ndnsSettings:\n  udpPayloadSize: 1\n")},
		}, "b.yaml (document 2): dnsSettings.udpPayloadSize 1 must be between 512 and 4096"},
		{"invalid cluster names its document", []Source{
			{"c.yaml", []byte("cluster: {mode: leader}\n")},
		}, `c.yaml: cluster.mode "leader"`},
		{"unknown key in a later document", []Source{
			{"a.yaml", []byte("zones: []\n---\nrecrods: []\n")},
		}, "a.yaml (document 2)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := LoadConfig(tt.docs...)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.want)
		})
	}
}

func TestSettingsValidation(t *testing.T) {
	tests := []struct {
		yaml string
		want string
	}{
		{"recursion: Allowed", `dnsSettings.recursion "Allowed" must be one of`},
		{"udpPayloadSize: 300", "udpPayloadSize 300 must be between 512 and 4096"},
		{"defaultRecordTtl: -1", "defaultRecordTtl -1 must be between 0"},
		{"eDnsClientSubnetIPv4PrefixLength: 300", "between 0 and 32"},
		{"resolverConcurrency: 8", "resolverConcurrency 8 must be between 1 and 4"},
		{"cachePrefetchEligibility: 1", "cachePrefetchEligibility 1 must be at least 2"},
		{"dnsOverHttpsPort: 853", "reserved for DNS-over-TLS"},
		{"enableCachePrefetch: true\n  cachePrefetchTrigger: 0", "contradictory"},
		{"forwarders: [9.9.9.9]", "dnsSettings.forwarders needs forwarderProtocol"},
		{"proxyType: Http", "dnsSettings.proxyType Http needs proxyAddress"},
		{"recursionNetworkACL: ['!10.0.0.0/8', 'bogus']", `recursionNetworkACL[1] "bogus"`},
		{"webServiceLocalAddresses: ['::', 'host']", `webServiceLocalAddresses[1] "host" is not an IP address`},
		{"qpmPrefixLimitsIPv4: [{prefix: 40, udpLimit: 1, tcpLimit: 1}]", "prefix 40 must be between 0 and 32"},
		{"dnsServerLocalEndPoints: ['0.0.0.0:53', 'bad-endpoint']", `dnsServerLocalEndPoints[1] "bad-endpoint" is not an address`},
		{"dnsServerLocalEndPoints: ['127.0.0.1:99999']", "invalid port"},
		{"defaultResponsiblePerson: hostmaster", `defaultResponsiblePerson "hostmaster" must be an email address`},
		{"forwarders: ['dns quad9']\n  forwarderProtocol: Udp", `forwarders[0] "dns quad9" is not a name server address`},
		{"forwarders: ['9.9.9.9:dns']\n  forwarderProtocol: Udp", `forwarders[0] "9.9.9.9:dns"`},
		{"tsigKeys: [{keyName: k, algorithmName: hmac-sha3, sharedSecret: c2VjcmV0}]", `algorithmName "hmac-sha3" must be one of`},
		{"forwarders: ['https://example.com:99999/dns-query']\n  forwarderProtocol: Https", "port 99999 is out of range"},
		{"forwarders: ['dns.example (not-an-ip)']\n  forwarderProtocol: Udp", "must be an IP address"},
		{"forwarders: ['[not-an-ip]']\n  forwarderProtocol: Udp", "must be an IP address"},
		{"forwarders: ['dns.example:53 (192.0.2.1:54)']\n  forwarderProtocol: Udp", "the ports disagree"},
		{"forwarders: ['https://dns.example/dns-query (dns.example)']\n  forwarderProtocol: Https", "must be an IP address"},
		{"dnsServerLocalEndPoints: ['[127.0.0.1:53']", "unbalanced bracket"},
		{"forwarders: ['bad domain (192.0.2.1)']\n  forwarderProtocol: Udp", `"bad domain" is not a host name`},
		{"forwarders: ['192.0.2.1 (192.0.2.2)']\n  forwarderProtocol: Udp", "must be a host name, not an address"},
		{"forwarders: ['bad..name (192.0.2.1)']\n  forwarderProtocol: Udp", `"bad..name" is not a host name`},
		{"forwarders: ['127.1 (192.0.2.1)']\n  forwarderProtocol: Udp", "must be a host name, not an address"},
		{"forwarders: ['2130706433 (192.0.2.1)']\n  forwarderProtocol: Udp", "must be a host name, not an address"},
		{"forwarders: ['0x7f000001 (192.0.2.1)']\n  forwarderProtocol: Udp", "must be a host name, not an address"},
		{"forwarders: ['127.000.000.001 (192.0.2.1)']\n  forwarderProtocol: Udp", "must be a host name, not an address"},
		{"tsigKeys: [{keyName: k, algorithmName: hmac-sha256, sharedSecret: 'not base64!'}]", "sharedSecret must be base64"},
	}
	for _, tt := range tests {
		t.Run(tt.yaml, func(t *testing.T) {
			_, err := load("dnsSettings:\n  " + tt.yaml + "\n")
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.want)
		})
	}

	_, err := load("dnsSettings:\n  recursion: allowOnlyForPrivateNetworks\n  forwarders: []\n  enableCachePrefetch: true\n  cachePrefetchTrigger: 9\n" +
		"  dnsServerLocalEndPoints: ['0.0.0.0:53', '[::]:53', '::', '192.168.10.2%eth0:53', '[fe80::1%eth1]:53']\n" +
		"  defaultResponsiblePerson: hostmaster@example.test\n" +
		"  tsigKeys: [{keyName: k, algorithmName: HMAC-SHA256, sharedSecret: c2VjcmV0}]\n")
	assert.NoError(t, err, "enum case is not significant, and an empty forwarder list needs no protocol")

	_, err = load("dnsSettings:\n  forwarderProtocol: Https\n" +
		"  forwarders: ['https://dns.quad9.net/dns-query (9.9.9.9)', 'tls://dns.google', '[2620:fe::fe]:53', 'dns.google:853', 'one.one.one.one', '1.1.1.1'," +
		" 'dns.quad9.net (9.9.9.9)', 'dns.google:853 (8.8.8.8:853)', 'tls://dns.google (8.8.8.8)', 'h3://dns.example/dns-query'," +
		" '-dns.example (192.0.2.1)', 'dns-.example (192.0.2.1)', 'ab--cd.example (192.0.2.1)', 'xn--.example (192.0.2.1)', 'dns.example (127.1)']\n")
	assert.NoError(t, err, "every name server address form the server parses")
}

func TestClusterDomainValidation(t *testing.T) {
	_, err := load("cluster: {mode: primary, domain: cluster.test, nodeIPs: 10.0.0.1}\ndnsSettings:\n  dnsServerDomain: dns.example.com\n")
	require.Error(t, err)
	assert.Contains(t, err.Error(), `must end with the cluster domain, for example "dns.cluster.test"`)

	_, err = load("cluster: {mode: primary, domain: cluster.test, nodeIPs: 10.0.0.1}\ndnsSettings:\n  dnsServerDomain: dns.cluster.test\n")
	assert.NoError(t, err)

	_, err = load("cluster: {mode: secondary, nodeIPs: 10.0.0.2, primaryURL: 'http://10.0.0.1:5380', primaryUsername: admin, primaryPassword: x}\n")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must use a host name")

	_, err = load("cluster: {mode: primary, domain: c.test, nodeIPs: 10.0.0.1, heartbeatRefreshIntervalSeconds: 5, configRefreshIntervalSeconds: 4000}\n")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "heartbeatRefreshIntervalSeconds 5 must be between 10 and 300")
	assert.Contains(t, err.Error(), "configRefreshIntervalSeconds 4000 must be between 30 and 3600")
	_, err = load("cluster: {mode: primary, domain: c.test, nodeIPs: 10.0.0.1, heartbeatRefreshIntervalSeconds: 60, configRefreshIntervalSeconds: 60}\n")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must be greater than heartbeatRefreshIntervalSeconds")
}

func TestRecordValidation(t *testing.T) {
	tests := []struct {
		record string
		want   string
	}{
		{"{domain: a.test, type: A, ipAddress: 2001:db8::1}", "must be an IPv4 address"},
		{"{domain: a.test, type: AAAA, ipAddress: 192.0.2.1}", "must be an IPv6 address"},
		{"{domain: a.test, type: MX, exchange: mail.a.test}", "preference is required"},
		{"{domain: a.test, type: SRV, priority: 1, weight: 1, target: x.a.test}", "port is required"},
		{"{domain: a.test, type: TXT}", "text or characterStringsBase64 is required"},
		{"{domain: a.test, type: TXT, characterStringsBase64: ['!!']}", "not valid base64"},
		{"{domain: a.test, type: FWD, forwarder: 192.0.2.53, ttl: 60}", "FWD records always have TTL 0"},
		{"{domain: a.test, type: SOA}", "SOA records cannot be declared"},
		{"{domain: a.test, type: TYPE65200}", "rdata (hex) is required"},
		{"{domain: a.test, type: CNAME, cname: b.test, ptr: true}", "ptr applies only to A and AAAA"},
		{"{domain: a.test, type: A, ipAddress: 192.0.2.1, ttl: -5}", "ttl -5 must be between"},
		{"{domain: a.test, type: A, ipAddress: 192.0.2.1, overwrite: true}", "overwrite was replaced by recordPolicy: replace"},
		{"{domain: a.test, type: A, ipAddress: 192.0.2.1, recordPolicy: sync}", `recordPolicy "sync" must be`},
		{"{domain: a.test, type: A, ipAddress: '', value: 192.0.2.1}", "both ipAddress and its alias value"},
		{"{domain: a.test, type: BOGUS, rdata: '00'}", `unknown record type "BOGUS"`},
		{"{domain: a.test, type: A, ipAddress: request-ip-address, ptr: true}", "ptr cannot be used with request-ip-address"},
		{"{domain: a.test, type: TXT, characterStringsBase64: ['YQ==', '', 'Yg==']}", "characterStringsBase64[1] is empty"},
		{"{domain: a.test, type: DS, keyTag: 1, algorithm: RSASHA256, digestType: SHA256, digest: abab}", "digest is 2 bytes; DS SHA256 needs 32"},
		{"{domain: a.test, type: DS, keyTag: 1, algorithm: 8, digestType: '+2', digest: abab}", "digest is 2 bytes"},
		{"{domain: a.test, type: DS, keyTag: 1, algorithm: 8, digestType: SHA512, digest: abab}", `"SHA512" is not a type the server supports`},
		{"{domain: a.test, type: DS, keyTag: 1, algorithm: RSASHA9, digestType: 2, digest: abababababababababababababababababababababababababababababababab}", `algorithm "RSASHA9" must be one of`},
		{"{domain: a.test, type: SSHFP, sshfpAlgorithm: Ed25519, sshfpFingerprintType: SHA256, sshfpFingerprint: 'ab:cd'}", "must be hex digits without separators"},
		{"{domain: a.test, type: TLSA, tlsaCertificateUsage: DANE-EE, tlsaSelector: SPKI, tlsaMatchingType: SHA2-256, tlsaCertificateAssociationData: abab}", "is 2 bytes; TLSA SHA2-256 needs 32"},
		{"{domain: a.test, type: TYPE65200, rdata: '0a 0b'}", "rdata must be hex digits"},
		{"{domain: a.test, type: TYPE65200, rdata: '0a::0b'}", "rdata must be hex digits"},
		{"{domain: a.test, type: ANY, rdata: '00'}", "ANY records cannot be declared"},
		{"{domain: a.test, type: NAPTR, naptrOrder: 1, naptrPreference: 1}", "naptrRegexp or naptrReplacement is required"},
		{"{domain: a.test, type: NAPTR, naptrOrder: 1, naptrPreference: 1, naptrFlags: 'u!', naptrReplacement: x.test}", "naptrFlags may hold only letters and digits"},
		{"{domain: a.test, type: SVCB, svcPriority: 1, svcTargetName: ., svcParams: 'port|https'}", `port "https" must be a number`},
		{"{domain: a.test, type: SVCB, svcPriority: 1, svcTargetName: ., svcParams: 'colour|blue'}", `unknown key "colour"`},
		{"{domain: a.test, type: SVCB, svcPriority: 1, svcTargetName: ., svcParams: 'ipv4hint|2001:db8::1'}", "must be an IPv4 address"},
		{"{domain: a.test, type: SVCB, svcPriority: 1, svcTargetName: ., svcParams: 'alpn'}", "key|value pairs"},
		{"{domain: a.test, type: TXT, splitText: true, text: '" + strings.Repeat("x", 256) + "'}", "line 1 of text is 256 bytes"},
	}
	for _, tt := range tests {
		t.Run(tt.record, func(t *testing.T) {
			_, err := load("records:\n  - " + tt.record + "\n")
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.want)
		})
	}
}

func TestAppConfigValidatedBeforeAnyCall(t *testing.T) {
	_, err := load("apps:\n  - name: X\n    url: https://example.test/x.zip\n    config: {ratio: .nan}\n")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "apps[0] (X)")
}

func TestAdministrationValidation(t *testing.T) {
	t.Setenv("TC_TEST_PASSWORD", "secret")
	_, err := load(`
administration:
  groups:
    - {name: readers}
  users:
    - {username: alice, passwordEnv: TC_TEST_PASSWORD, groups: [readers]}
  permissions:
    - section: zones
      groups: {readers: [view]}
`)
	require.NoError(t, err)

	tests := []struct {
		yaml string
		want string
	}{
		{"users: [{username: bob, password: a, passwordEnv: B}]", "give only one of"},
		{"permissions: [{section: Reports, groups: {x: [view]}}]", "section must be one of"},
		{"permissions: [{section: Zones, groups: {x: [read]}}]", `access "read" must be view, modify or delete`},
		{"groups: [{name: a}, {name: A}]", "duplicate group"},
		{"groups: [{name: Everyone, description: x}, {name: everyone}]", "duplicate group"},
	}
	for _, tt := range tests {
		t.Run(tt.yaml, func(t *testing.T) {
			_, err := load("administration:\n  " + tt.yaml + "\n")
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.want)
		})
	}

	// A password source is read only to create the user, so a source that
	// is gone on a later run is not a config error.
	cfg, err := load("administration:\n  users: [{username: bob, passwordEnv: TC_MISSING_VAR}]\n")
	require.NoError(t, err)
	_, err = cfg.Administration.Users[0].InitialPassword()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "TC_MISSING_VAR is not set")
}

func TestMergePermissions(t *testing.T) {
	current := []PermissionEntry{
		{Name: "Administrators", Access: Access{true, true, true}},
		{Name: "readers", Access: Access{View: true}},
	}
	merged, changed := MergePermissions(current, map[string][]string{"Readers": {"view"}})
	assert.False(t, changed, "a grant that already matches changes nothing")
	assert.Equal(t, current, merged)

	merged, changed = MergePermissions(current, map[string][]string{"auditors": {"view"}, "readers": {"view", "modify"}})
	assert.True(t, changed)
	assert.Equal(t, []PermissionEntry{
		{Name: "Administrators", Access: Access{true, true, true}},
		{Name: "readers", Access: Access{View: true, Modify: true}},
		{Name: "auditors", Access: Access{View: true}},
	}, merged, "grants the file does not name are kept")
}

func TestDigestAndRDataAccepted(t *testing.T) {
	_, err := load("records:\n" +
		"  - {domain: a.test, type: DS, keyTag: 1, algorithm: '013', digestType: '+2', digest: abababababababababababababababababababababababababababababababab}\n" +
		"  - {domain: b.test, type: DS, keyTag: 1, algorithm: 99, digestType: SHA1, digest: abababababababababababababababababababab}\n" +
		"  - {domain: c.test, type: SSHFP, sshfpAlgorithm: 4, sshfpFingerprintType: 2, sshfpFingerprint: abababababababababababababababababababababababababababababababab}\n" +
		"  - {domain: d.test, type: TLSA, tlsaCertificateUsage: 3, tlsaSelector: 1, tlsaMatchingType: Full, tlsaCertificateAssociationData: 3082}\n" +
		"  - {domain: e.test, type: TLSA, tlsaCertificateUsage: DANE-EE, tlsaSelector: Cert, tlsaMatchingType: SHA2-512, tlsaCertificateAssociationData: '-----BEGIN CERTIFICATE-----'}\n" +
		"  - {domain: f.test, type: TYPE65200, rdata: '0a:b:ff'}\n  - {domain: g.test, type: TYPE65200, rdata: 0A0B}\n")
	assert.NoError(t, err, "numbers and names, PEM input, and both rdata forms")
}

func TestZoneValidation(t *testing.T) {
	tests := []struct {
		zone string
		want string
	}{
		{"aclSettings: {queryAccess: DefinitelyNotAnEnum}", `aclSettings.queryAccess "DefinitelyNotAnEnum" must be one of`},
		{"aclSettings: {zoneTransfer: Sometimes}", `aclSettings.zoneTransfer "Sometimes" must be one of`},
		{"aclSettings: {notify: All}", `aclSettings.notify "All" must be one of`},
		{"aclSettings: {update: Yes}", `aclSettings.update "Yes" must be one of`},
		{"aclSettings: {updateNetworkACL: [10.0.0.0/8, nope]}", `updateNetworkACL[1] "nope"`},
		{"aclSettings: {notifyNameServers: [ns1.z.test]}", `notifyNameServers[0] "ns1.z.test" is not an IP address`},
		{"aclSettings: {updateSecurityPolicies: 'key|z.test'}", "triples"},
		{"aclSettings: {updateSecurityPolicies: 'key|other.test|A'}", `domain "other.test" is outside the zone "z.test"`},
		{"aclSettings: {updateSecurityPolicies: 'key|*.z.test|A,TYPE65200'}", `"TYPE65200" is not a record type name or number`},
		{"zoneTransferProtocol: Udp", `zoneTransferProtocol "Udp" must be one of`},
	}
	for _, tt := range tests {
		t.Run(tt.zone, func(t *testing.T) {
			_, err := load("zones:\n  - {zone: z.test, type: Primary, " + tt.zone + "}\n")
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.want)
		})
	}

	_, err := load("zones:\n  - zone: z.test\n    type: Primary\n    aclSettings:\n      queryAccess: allowOnlyPrivateNetworks\n" +
		"      updateSecurityPolicies: 'key|*.z.test|A,AAAA TXT|key|z.test|65200|other|sub.z.test|ANY'\n")
	assert.NoError(t, err, "enum case is not significant; types may be names or numbers, separated by commas or spaces")
}

func TestRecordSetValidation(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{"two CNAME values", "records:\n  - {domain: a.z.test, type: CNAME, cname: b.test}\n  - {domain: A.z.test., type: cname, cname: c.test}\n",
			"a name can have only one CNAME record"},
		{"conflicting policies", "records:\n  - {domain: a.z.test, type: A, ipAddress: 192.0.2.1, recordPolicy: replace}\n  - {domain: a.z.test, type: A, ipAddress: 192.0.2.2, recordPolicy: merge}\n",
			`use both "replace" and "merge" record policies`},
		{"record outside its zone", "records:\n  - {domain: a.other.test, zone: z.test, type: A, ipAddress: 192.0.2.1}\n", "a.other.test is not inside zone z.test"},
		{"empty record zone", "records:\n  - {domain: a.z.test, zone: '', type: A, ipAddress: 192.0.2.1}\n", "zone must not be empty"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := load(tt.yaml)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.want)
		})
	}

	_, err := load("zones:\n  - {zone: z.test, type: Primary}\n  - {zone: f.z.test, type: Forwarder, forwarder: 192.0.2.53}\nrecords:\n" +
		"  - {domain: a.z.test, type: CNAME, cname: b.test}\n  - {domain: a.z.test, type: CNAME, cname: B.test.}\n" +
		"  - {domain: x.f.z.test, type: FWD, forwarder: 192.0.2.54}\n")
	assert.NoError(t, err, "the same CNAME value twice is one value, and an FWD record in a nested Forwarder zone is valid")

	// The closer zone may exist only on the server, so where a record lands
	// and that zone's policy are judged during the run, not here.
	_, err = load("zones:\n  - {zone: r4.test, type: Primary, recordPolicy: replace}\nrecords:\n" +
		"  - {domain: nested.r4.test, type: FWD, forwarder: 192.0.2.53}\n" +
		"  - {domain: x.r4.test, type: A, ipAddress: 192.0.2.1}\n  - {domain: x.r4.test, type: A, ipAddress: 192.0.2.2, recordPolicy: replace}\n")
	assert.NoError(t, err)
}
