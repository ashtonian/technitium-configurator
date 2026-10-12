package technitium

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/mail"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// Validate checks everything that can be checked without the server and
// reports every problem found. Ranges and enums mirror the setters in
// DnsServerCore (v15.6), so a value the server would reject or ignore fails
// here instead, before anything is changed.
func (c *Config) Validate() error {
	v := &validator{}

	v.policy("recordPolicy", c.RecordPolicy)
	if c.Cluster != nil {
		c.Cluster.validate(v)
	}
	if c.DNSSettings != nil {
		c.DNSSettings.validate(v)
		if c.Cluster != nil && c.Cluster.Mode == "primary" && c.Cluster.Domain != "" && c.DNSSettings.DnsServerDomain != nil {
			if !InClusterDomain(*c.DNSSettings.DnsServerDomain, c.Cluster.Domain) {
				v.addf("dnsSettings.dnsServerDomain %q must end with the cluster domain, for example %q",
					*c.DNSSettings.DnsServerDomain, firstLabel(CanonicalName(*c.DNSSettings.DnsServerDomain))+"."+CanonicalName(c.Cluster.Domain))
			}
		}
	}
	if c.Administration != nil {
		c.Administration.validate(v, c.origins)
	}

	seenZones := map[string]string{}
	for i, z := range c.Zones {
		at := fmt.Sprintf("%s (%s)", c.origins.at("zones", i), z.Zone)
		name := ZoneKey(z.Zone)
		switch first, dup := seenZones[name]; {
		case strings.TrimSpace(z.Zone) == "":
			v.addf("%s: zone is required; the root zone is \".\"", c.origins.at("zones", i))
		case dup:
			v.addf("%s: duplicate zone; first declared at %s", at, first)
		default:
			seenZones[name] = at
		}
		if !zoneTypes[z.Type] {
			v.addf("%s: type %q must be one of Primary, Secondary, Stub, Forwarder, SecondaryForwarder, Catalog, SecondaryCatalog", at, z.Type)
		}
		if z.Catalog != nil && *z.Catalog != "" && !CatalogMemberTypes[z.Type] {
			v.addf("%s: a %s zone cannot be a catalog member", at, z.Type)
		}
		v.policy(at+".recordPolicy", z.RecordPolicy)
		z.validate(v, at)
	}

	for i, r := range c.Records {
		validateRecord(v, fmt.Sprintf("%s (%s %s)", c.origins.at("records", i), r.Domain, r.Type), r)
	}
	c.validateRecordSets(v)

	seenApps := map[string]string{}
	for i, a := range c.Apps {
		at := fmt.Sprintf("%s (%s)", c.origins.at("apps", i), a.Name)
		switch first, dup := seenApps[a.Name]; {
		case a.Name == "":
			v.addf("%s: name is required", c.origins.at("apps", i))
		case dup:
			v.addf("%s: duplicate app; first declared at %s", at, first)
		default:
			seenApps[a.Name] = at
		}
		// url is needed only to install the app, which the run decides.
		if a.Url != "" {
			if u, err := url.Parse(a.Url); err != nil || (u.Scheme != "http" && u.Scheme != "https") {
				v.addf("%s: url must be an http or https URL", at)
			}
		}
		if _, _, err := a.ConfigJSON(); err != nil {
			v.addf("%s: %v", at, err)
		}
	}

	c.labelKeyErrors(v)
	return errors.Join(v.errs...)
}

var zoneTypes = map[ZoneType]bool{
	ZonePrimary:            true,
	ZoneSecondary:          true,
	ZoneStub:               true,
	ZoneForwarder:          true,
	ZoneSecondaryForwarder: true,
	ZoneCatalog:            true,
	ZoneSecondaryCatalog:   true,
}

type validator struct{ errs []error }

// labelKeyErrors prefixes an error about recordPolicy, cluster or a
// dnsSettings key with the document that set it. Those messages start with
// the key's path, for example "dnsSettings.udpPayloadSize 1 must be...".
func (c *Config) labelKeyErrors(v *validator) {
	for i, err := range v.errs {
		msg := err.Error()
		key := ""
		switch {
		case strings.HasPrefix(msg, "dnsSettings."):
			end := len("dnsSettings.")
			for end < len(msg) && (msg[end] >= 'a' && msg[end] <= 'z' || msg[end] >= 'A' && msg[end] <= 'Z' || msg[end] >= '0' && msg[end] <= '9') {
				end++
			}
			key = msg[:end]
		case strings.HasPrefix(msg, "cluster"):
			key = "cluster"
		case strings.HasPrefix(msg, "recordPolicy"):
			key = "recordPolicy"
		}
		if where, ok := c.keyOrigins[key]; ok {
			v.errs[i] = fmt.Errorf("%s: %w", where, err)
		}
	}
}

func (v *validator) addf(format string, args ...any) {
	v.errs = append(v.errs, fmt.Errorf(format, args...))
}

func (v *validator) policy(field string, p *string) {
	if p != nil && *p != PolicyMerge && *p != PolicyReplace {
		v.addf("%s %q must be %q or %q", field, *p, PolicyMerge, PolicyReplace)
	}
}

func (v *validator) rangeInt(field string, n *int, lo, hi int) {
	if n != nil && (*n < lo || *n > hi) {
		v.addf("%s %d must be between %d and %d", field, *n, lo, hi)
	}
}

func (v *validator) min(field string, n *int, lo int) {
	if n != nil && *n < lo {
		v.addf("%s %d must be at least %d", field, *n, lo)
	}
}

func (v *validator) enum(field string, s *string, allowed ...string) {
	if s == nil {
		return
	}
	for _, a := range allowed {
		if strings.EqualFold(*s, a) {
			return
		}
	}
	v.addf("%s %q must be one of %s", field, *s, strings.Join(allowed, ", "))
}

func (v *validator) maxLen(field string, s *string, n int) {
	if s != nil && len(*s) > n {
		v.addf("%s must be at most %d characters", field, n)
	}
}

func (v *validator) maxEntries(field string, n, max int) {
	if n > max {
		v.addf("%s has %d entries; the server allows at most %d", field, n, max)
	}
}

func (v *validator) ip(field, s string, want4, want6 bool) {
	a, err := ParseIP(s)
	switch {
	case err != nil:
		v.addf("%s %q is not an IP address", field, s)
	case want4 && !a.Is4():
		v.addf("%s %q must be an IPv4 address", field, s)
	case want6 && !a.Is6():
		v.addf("%s %q must be an IPv6 address", field, s)
	}
}

// network accepts an address or a prefix, as NetworkAddress.Parse does.
func (v *validator) network(field, s string) {
	if _, err := netip.ParsePrefix(s); err == nil {
		return
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return
	}
	v.addf("%s %q is not an IP address or network", field, s)
}

// acl accepts an optional "!" before an address or prefix, as
// NetworkAccessControl.Parse does.
func (v *validator) acl(field, s string) {
	v.network(field, strings.TrimPrefix(strings.TrimSpace(s), "!"))
}

func (v *validator) networks(field string, list *[]string, max int, check func(string, string)) {
	if list == nil {
		return
	}
	v.maxEntries(field, len(*list), max)
	for i, s := range *list {
		check(fmt.Sprintf("%s[%d]", field, i), s)
	}
}

// maxTTL is the largest TTL RFC 2181 allows. The server stores up to
// 2^32-1, but resolvers treat a TTL above this as 0.
const maxTTL = 2147483647

func (v *validator) ttl(field string, n *int) {
	if n != nil && (*n < 0 || *n > maxTTL) {
		v.addf("%s %d must be between 0 and %d (RFC 2181; resolvers treat larger TTLs as 0)", field, *n, maxTTL)
	}
}

func (s *DnsSettings) validate(v *validator) {
	const f = "dnsSettings."
	for name, ttl := range map[string]*int{
		"defaultRecordTtl": s.DefaultRecordTtl, "defaultNsRecordTtl": s.DefaultNsRecordTtl, "defaultSoaRecordTtl": s.DefaultSoaRecordTtl,
		"minSoaRefresh": s.MinSoaRefresh, "minSoaRetry": s.MinSoaRetry, "blockingAnswerTtl": s.BlockingAnswerTtl,
		"cacheMinimumRecordTtl": s.CacheMinimumRecordTtl, "cacheMaximumRecordTtl": s.CacheMaximumRecordTtl,
		"cacheNegativeRecordTtl": s.CacheNegativeRecordTtl, "cacheFailureRecordTtl": s.CacheFailureRecordTtl,
		"serveStaleTtl": s.ServeStaleTtl, "serveStaleAnswerTtl": s.ServeStaleAnswerTtl,
	} {
		v.ttl(f+name, ttl)
	}
	v.rangeInt(f+"serveStaleResetTtl", s.ServeStaleResetTtl, 10, 900)
	v.rangeInt(f+"serveStaleMaxWaitTime", s.ServeStaleMaxWaitTime, 0, 1800)
	v.rangeInt(f+"udpPayloadSize", s.UdpPayloadSize, 512, 4096)
	v.rangeInt(f+"eDnsClientSubnetIPv4PrefixLength", s.EDnsClientSubnetIPv4PrefixLength, 0, 32)
	v.rangeInt(f+"eDnsClientSubnetIPv6PrefixLength", s.EDnsClientSubnetIPv6PrefixLength, 0, 64)
	v.rangeInt(f+"qpmLimitSampleMinutes", s.QpmLimitSampleMinutes, 1, 60)
	v.rangeInt(f+"qpmLimitUdpTruncationPercentage", s.QpmLimitUdpTruncationPercentage, 0, 100)
	v.rangeInt(f+"clientTimeout", s.ClientTimeout, 1000, 10000)
	v.rangeInt(f+"tcpSendTimeout", s.TcpSendTimeout, 1000, 90000)
	v.rangeInt(f+"tcpReceiveTimeout", s.TcpReceiveTimeout, 1000, 90000)
	v.rangeInt(f+"quicIdleTimeout", s.QuicIdleTimeout, 1000, 90000)
	v.rangeInt(f+"quicMaxInboundStreams", s.QuicMaxInboundStreams, 1, 1000)
	v.rangeInt(f+"udpSendBufferSizeKB", s.UdpSendBufferSizeKB, 8, 65536)
	v.rangeInt(f+"udpReceiveBufferSizeKB", s.UdpReceiveBufferSizeKB, 8, 65536)
	v.rangeInt(f+"maxConcurrentResolutionsPerCore", s.MaxConcurrentResolutionsPerCore, 1, 65535)
	v.min(f+"listenBacklog", s.ListenBacklog, 1)
	v.rangeInt(f+"resolverRetries", s.ResolverRetries, 1, 10)
	v.rangeInt(f+"resolverTimeout", s.ResolverTimeout, 1000, 10000)
	v.rangeInt(f+"resolverConcurrency", s.ResolverConcurrency, 1, 4)
	v.rangeInt(f+"resolverMaxStackCount", s.ResolverMaxStackCount, 10, 30)
	v.min(f+"cachePrefetchEligibility", s.CachePrefetchEligibility, 2)
	v.min(f+"cachePrefetchTrigger", s.CachePrefetchTrigger, 0)
	if s.CacheMaximumEntries != nil && *s.CacheMaximumEntries < 0 {
		v.addf("%scacheMaximumEntries must be 0 (unlimited) or more", f)
	}
	v.rangeInt(f+"forwarderRetries", s.ForwarderRetries, 1, 10)
	v.rangeInt(f+"forwarderTimeout", s.ForwarderTimeout, 1000, 10000)
	v.rangeInt(f+"forwarderConcurrency", s.ForwarderConcurrency, 1, 10)
	v.min(f+"blockListUpdateIntervalHours", s.BlockListUpdateIntervalHours, 0)
	v.min(f+"maxLogFileDays", s.MaxLogFileDays, 0)
	v.min(f+"maxStatFileDays", s.MaxStatFileDays, 0)

	v.rangeInt(f+"webServiceHttpPort", s.WebServiceHttpPort, 1, 65535)
	v.rangeInt(f+"webServiceTlsPort", s.WebServiceTlsPort, 1, 65535)
	for name, port := range map[string]*int{
		"dnsOverUdpProxyPort": s.DnsOverUdpProxyPort, "dnsOverTcpProxyPort": s.DnsOverTcpProxyPort,
		"dnsOverHttpPort": s.DnsOverHttpPort, "dnsOverTlsPort": s.DnsOverTlsPort,
		"dnsOverHttpsPort": s.DnsOverHttpsPort, "dnsOverQuicPort": s.DnsOverQuicPort,
	} {
		v.rangeInt(f+name, port, 0, 65535)
		if port != nil && *port == 53 && name != "dnsOverUdpProxyPort" && name != "dnsOverTcpProxyPort" {
			v.addf("%s%s cannot be 53", f, name)
		}
	}
	for name, port := range map[string]*int{"dnsOverHttpPort": s.DnsOverHttpPort, "dnsOverHttpsPort": s.DnsOverHttpsPort} {
		if port != nil && *port == 853 {
			v.addf("%s%s cannot be 853, which is reserved for DNS-over-TLS", f, name)
		}
	}
	if s.SocketPoolExcludedPorts != nil {
		for i, p := range *s.SocketPoolExcludedPorts {
			v.rangeInt(fmt.Sprintf("%ssocketPoolExcludedPorts[%d]", f, i), &p, 1, 65535)
		}
	}

	v.enum(f+"ipv6Mode", s.IPv6Mode, "Disabled", "Enabled", "Preferred")
	v.enum(f+"recursion", s.Recursion, "Deny", "Allow", "AllowOnlyForPrivateNetworks", "UseSpecifiedNetworkACL")
	v.enum(f+"blockingType", s.BlockingType, "AnyAddress", "NxDomain", "CustomAddress")
	v.enum(f+"loggingType", s.LoggingType, "None", "File", "Console", "FileAndConsole")
	v.enum(f+"forwarderProtocol", s.ForwarderProtocol, "Udp", "Tcp", "Tls", "Https", "Quic")
	v.enum(f+"proxyType", s.ProxyType, "None", "Http", "Socks5")

	for name, str := range map[string]*string{
		"defaultResponsiblePerson": s.DefaultResponsiblePerson, "webServiceRealIpHeader": s.WebServiceRealIpHeader,
		"webServiceCspFrameAncestorsHeader": s.WebServiceCspFrameAncestorsHeader, "dnsOverHttpRealIpHeader": s.DnsOverHttpRealIpHeader,
		"dnsTlsCertificatePath": s.DnsTlsCertificatePath, "dnsTlsCertificatePassword": s.DnsTlsCertificatePassword,
		"proxyUsername": s.ProxyUsername, "proxyPassword": s.ProxyPassword,
	} {
		v.maxLen(f+name, str, 255)
	}

	v.networks(f+"zoneTransferAllowedNetworks", s.ZoneTransferAllowedNetworks, 255, v.network)
	v.networks(f+"notifyAllowedNetworks", s.NotifyAllowedNetworks, 255, v.network)
	v.networks(f+"qpmLimitBypassList", s.QpmLimitBypassList, 255, v.network)
	v.networks(f+"blockingBypassList", s.BlockingBypassList, 255, v.network)
	v.networks(f+"dnsServerIPv4SourceAddresses", s.DnsServerIPv4SourceAddresses, 255, v.network)
	v.networks(f+"dnsServerIPv6SourceAddresses", s.DnsServerIPv6SourceAddresses, 255, v.network)
	v.networks(f+"recursionNetworkACL", s.RecursionNetworkACL, 255, v.acl)
	v.networks(f+"dnsReverseProxyNetworkACL", s.DnsReverseProxyNetworkACL, 255, v.acl)
	v.networks(f+"webServiceReverseProxyAddresses", s.WebServiceReverseProxyAddresses, 255, v.acl)
	v.networks(f+"dnsServerLocalEndPoints", s.DnsServerLocalEndPoints, 255, v.endpoint)
	v.networks(f+"forwarders", s.Forwarders, 255, v.nameServer)
	if p := s.DefaultResponsiblePerson; p != nil && *p != "" {
		// The server parses it with MailAddress.
		if a, err := mail.ParseAddress(*p); err != nil || !strings.Contains(a.Address, "@") {
			v.addf("%sdefaultResponsiblePerson %q must be an email address", f, *p)
		}
	}
	v.networks(f+"webServiceLocalAddresses", s.WebServiceLocalAddresses, 255, func(field, a string) { v.ip(field, a, false, false) })
	v.networks(f+"customBlockingAddresses", s.CustomBlockingAddresses, 255, func(field, a string) { v.ip(field, a, false, false) })
	if s.EDnsClientSubnetIpv4Override != nil && *s.EDnsClientSubnetIpv4Override != "" {
		v.network(f+"eDnsClientSubnetIpv4Override", *s.EDnsClientSubnetIpv4Override)
	}
	if s.EDnsClientSubnetIpv6Override != nil && *s.EDnsClientSubnetIpv6Override != "" {
		v.network(f+"eDnsClientSubnetIpv6Override", *s.EDnsClientSubnetIpv6Override)
	}
	for _, lim := range []struct {
		name  string
		list  *[]QpmPrefixLimit
		maxPf int
	}{{"qpmPrefixLimitsIPv4", s.QpmPrefixLimitsIPv4, 32}, {"qpmPrefixLimitsIPv6", s.QpmPrefixLimitsIPv6, 128}} {
		if lim.list == nil {
			continue
		}
		v.maxEntries(f+lim.name, len(*lim.list), 255)
		for i, l := range *lim.list {
			at := fmt.Sprintf("%s%s[%d]", f, lim.name, i)
			v.rangeInt(at+".prefix", &l.Prefix, 0, lim.maxPf)
			v.min(at+".udpLimit", &l.UdpLimit, 0)
			v.min(at+".tcpLimit", &l.TcpLimit, 0)
		}
	}

	if s.TsigKeys != nil {
		v.maxEntries(f+"tsigKeys", len(*s.TsigKeys), 255)
		seen := map[string]bool{}
		for i, k := range *s.TsigKeys {
			at := fmt.Sprintf("%stsigKeys[%d] (%s)", f, i, k.KeyName)
			name := CanonicalName(k.KeyName)
			switch {
			case name == "":
				v.addf("%stsigKeys[%d]: keyName is required", f, i)
			case seen[name]:
				v.addf("%s: duplicate keyName", at)
			}
			seen[name] = true
			if k.AlgorithmName == "" {
				v.addf("%s: algorithmName is required", at)
			} else {
				v.enum(at+".algorithmName", &k.AlgorithmName, tsigAlgorithms...)
			}
			// An empty secret makes the server generate a new one on every
			// run, which would rotate the key out from under its clients.
			if k.SharedSecret == "" {
				v.addf("%s: sharedSecret is required", at)
			} else if _, err := base64.StdEncoding.DecodeString(k.SharedSecret); err != nil {
				v.addf("%s: sharedSecret must be base64", at)
			}
		}
	}

	// Combinations the server resolves silently in a way the file does not say.
	if s.EnableCachePrefetch != nil && *s.EnableCachePrefetch && s.CachePrefetchTrigger != nil && *s.CachePrefetchTrigger == 0 {
		v.addf("%senableCachePrefetch: true with cachePrefetchTrigger: 0 is contradictory; the server would reset the trigger to 9", f)
	}
	if s.Forwarders != nil && len(*s.Forwarders) > 0 && s.ForwarderProtocol == nil {
		v.addf("%sforwarders needs forwarderProtocol; otherwise the server resets the protocol to Udp", f)
	}
	if s.ProxyType != nil && !strings.EqualFold(*s.ProxyType, "None") {
		if s.ProxyAddress == nil || *s.ProxyAddress == "" {
			v.addf("%sproxyType %s needs proxyAddress", f, *s.ProxyType)
		}
		if s.ProxyPort == nil {
			v.addf("%sproxyType %s needs proxyPort", f, *s.ProxyType)
		}
		v.rangeInt(f+"proxyPort", s.ProxyPort, 1, 65535)
	}
}

func (cc *ClusterConfig) validate(v *validator) {
	require := func(field, value string) {
		if value == "" {
			v.addf("cluster.%s is required for %s mode", field, cc.Mode)
		}
	}
	switch cc.Mode {
	case "primary":
		require("domain", cc.Domain)
		require("nodeIPs", cc.NodeIPs)
	case "secondary":
		require("nodeIPs", cc.NodeIPs)
		require("primaryURL", cc.PrimaryURL)
		require("primaryUsername", cc.PrimaryUsername)
		require("primaryPassword", cc.PrimaryPassword)
		if cc.PrimaryURL != "" {
			if u, err := url.Parse(cc.PrimaryURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
				v.addf("cluster.primaryURL must be an http or https URL")
			} else if _, err := netip.ParseAddr(u.Hostname()); err == nil {
				v.addf("cluster.primaryURL must use a host name, not an IP address; put the address in primaryIP")
			}
		}
		if cc.PrimaryIP != "" {
			v.ip("cluster.primaryIP", cc.PrimaryIP, false, false)
		}
	default:
		v.addf("cluster.mode %q must be \"primary\" or \"secondary\"", cc.Mode)
	}
	for i, ip := range cc.NodeIPList() {
		v.ip(fmt.Sprintf("cluster.nodeIPs[%d]", i), ip, false, false)
	}
	// Ranges from ClusterManager.UpdateClusterOptions.
	for _, t := range []struct {
		name   string
		n      int
		lo, hi int
	}{
		{"heartbeatRefreshIntervalSeconds", cc.HeartbeatRefreshIntervalSecs, 10, 300},
		{"heartbeatRetryIntervalSeconds", cc.HeartbeatRetryIntervalSecs, 10, 300},
		{"configRefreshIntervalSeconds", cc.ConfigRefreshIntervalSecs, 30, 3600},
		{"configRetryIntervalSeconds", cc.ConfigRetryIntervalSecs, 30, 3600},
	} {
		if t.n != 0 {
			v.rangeInt("cluster."+t.name, &t.n, t.lo, t.hi)
		}
	}
	if cc.ConfigRefreshIntervalSecs != 0 && cc.HeartbeatRefreshIntervalSecs != 0 && cc.ConfigRefreshIntervalSecs <= cc.HeartbeatRefreshIntervalSecs {
		v.addf("cluster.configRefreshIntervalSeconds %d must be greater than heartbeatRefreshIntervalSeconds %d", cc.ConfigRefreshIntervalSecs, cc.HeartbeatRefreshIntervalSecs)
	}
}

// recordRequired lists the API parameters each type needs.
var recordRequired = map[RecordType][]string{
	RT_A: {"ipAddress"}, RT_AAAA: {"ipAddress"}, RT_NS: {"nameServer"}, RT_CNAME: {"cname"}, RT_PTR: {"ptrName"},
	RT_MX: {"exchange", "preference"}, RT_RP: {"mailbox", "txtDomain"}, RT_SRV: {"priority", "weight", "port", "target"},
	RT_NAPTR: {"naptrOrder", "naptrPreference"}, RT_DNAME: {"dname"},
	RT_DS:    {"keyTag", "algorithm", "digestType", "digest"},
	RT_SSHFP: {"sshfpAlgorithm", "sshfpFingerprintType", "sshfpFingerprint"},
	RT_TLSA:  {"tlsaCertificateUsage", "tlsaSelector", "tlsaMatchingType", "tlsaCertificateAssociationData"},
	RT_SVCB:  {"svcPriority", "svcTargetName"}, RT_HTTPS: {"svcPriority", "svcTargetName"},
	RT_URI: {"uriPriority", "uriWeight", "uri"}, RT_CAA: {"flags", "tag", "value"}, RT_ANAME: {"aname"},
	RT_FWD: {"forwarder"}, RT_APP: {"appName", "classPath"},
}

func validateRecord(v *validator, at string, r AddRecordRequest) {
	if r.Domain == "" {
		v.addf("%s: domain (or name) is required", at)
	}
	if r.Type == "" {
		v.addf("%s: type is required", at)
		return
	}
	typ := r.Type.Canonical()
	switch {
	case !typ.Known():
		v.addf("%s: unknown record type %q; use a type name or TYPE<number>", at, r.Type)
		return
	case NonAddableTypes[typ]:
		v.addf("%s: %s records cannot be declared; the server maintains them or they are not record data", at, typ)
		return
	}
	v.policy(at+".recordPolicy", r.RecordPolicy)
	if r.Zone != nil {
		switch zone := ZoneKey(*r.Zone); {
		case strings.TrimSpace(*r.Zone) == "":
			v.addf("%s: zone must not be empty; leave it out, or use \".\" for the root zone", at)
		case r.Domain != "" && !InZone(CanonicalName(r.Domain), zone):
			v.addf("%s: %s is not inside zone %s", at, r.Domain, *r.Zone)
		}
	}
	if r.TTL != nil {
		v.ttl(at+".ttl", r.TTL)
		if typ == RT_FWD && *r.TTL != 0 {
			v.addf("%s: FWD records always have TTL 0; remove ttl", at)
		}
	}
	if r.ExpiryTTL != nil {
		v.ttl(at+".expiryTtl", r.ExpiryTTL)
	}

	params := r.params()
	has := func(p string) bool {
		raw, ok := params[p]
		return ok && string(raw) != "null" && string(raw) != `""`
	}
	if typ == RT_TXT {
		switch {
		case r.Text == nil && r.CharacterStringsBase64 == nil:
			v.addf("%s: text or characterStringsBase64 is required; use text: \"\" for an empty record", at)
		case r.Text != nil && r.CharacterStringsBase64 != nil:
			v.addf("%s: set text or characterStringsBase64, not both", at)
		}
		if r.SplitText != nil && *r.SplitText && r.Text != nil {
			for i, cs := range decodeCharacterStrings(*r.Text) {
				if len(cs) > 255 {
					v.addf("%s: line %d of text is %d bytes; with splitText each line is one character string of at most 255 bytes", at, i+1, len(cs))
				}
			}
		}
		for i, s := range r.CharacterStringsBase64 {
			if b, err := base64.StdEncoding.DecodeString(s); err != nil {
				v.addf("%s.characterStringsBase64[%d] is not valid base64", at, i)
			} else if len(b) == 0 {
				// The API takes the list comma-joined and drops empty entries.
				v.addf("%s.characterStringsBase64[%d] is empty; the API cannot write an empty character string (use text: \"\" for a record without strings)", at, i)
			} else if len(b) > 255 {
				v.addf("%s.characterStringsBase64[%d] is %d bytes; a character string holds at most 255", at, i, len(b))
			}
		}
	}
	required, known := recordRequired[typ]
	if !known && typ != RT_TXT {
		// Any other type is sent as raw RDATA.
		if r.RData == "" {
			v.addf("%s: rdata (hex) is required for %s records", at, typ)
		} else if _, err := hex.DecodeString(strings.NewReplacer(":", "", " ", "").Replace(r.RData)); err != nil {
			v.addf("%s: rdata must be hex", at)
		}
	}
	for _, p := range required {
		if !has(p) {
			v.addf("%s: %s is required", at, p)
		}
	}
	switch typ {
	case RT_A:
		if r.IPAddress != "" && r.IPAddress != "request-ip-address" {
			v.ip(at+".ipAddress", r.IPAddress, true, false)
		}
	case RT_AAAA:
		if r.IPAddress != "" && r.IPAddress != "request-ip-address" {
			v.ip(at+".ipAddress", r.IPAddress, false, true)
		}
	}
	if r.Ptr != nil && *r.Ptr && typ != RT_A && typ != RT_AAAA {
		v.addf("%s: ptr applies only to A and AAAA records", at)
	}
	if r.Ptr != nil && *r.Ptr && r.IPAddress == "request-ip-address" {
		// The address is known only on the server, so the existing PTR
		// cannot be checked before the server overwrites it.
		v.addf("%s: ptr cannot be used with request-ip-address", at)
	}
	switch typ {
	case RT_NAPTR:
		if r.NaptrRegexp == "" && r.NaptrReplacement == "" {
			v.addf("%s: naptrRegexp or naptrReplacement is required", at)
		}
		for _, c := range r.NaptrFlags {
			if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') {
				v.addf("%s.naptrFlags may hold only letters and digits", at)
				break
			}
		}
	case RT_SVCB, RT_HTTPS:
		validateSvcParams(v, at+".svcParams", r.SvcParams)
	case RT_FWD:
		v.enum(at+".protocol", nonEmpty(string(r.Protocol)), "Udp", "Tcp", "Tls", "Https", "Quic")
		if r.Forwarder != "" && r.Forwarder != "this-server" {
			v.nameServer(at+".forwarder", r.Forwarder)
		}
	}
	for name, n := range map[string]*int{"preference": r.Preference, "priority": r.Priority, "weight": r.Weight, "port": r.Port,
		"naptrOrder": r.NaptrOrder, "naptrPreference": r.NaptrPreference, "uriPriority": r.URIPriority, "uriWeight": r.URIWeight, "svcPriority": r.SvcPriority} {
		v.rangeInt(at+"."+name, n, 0, 65535)
	}
	v.rangeInt(at+".flags", r.Flags, 0, 255)
}

func firstLabel(name string) string {
	if i := strings.IndexByte(name, '.'); i >= 0 {
		return name[:i]
	}
	if name == "" {
		return "dns"
	}
	return name
}

func nonEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// validate checks a zone's create options and ACLs. The server ignores an
// ACL option whose value it cannot parse (TryGetQueryOrFormEnum), so a typo
// would otherwise pass silently.
func (z ZoneConfig) validate(v *validator, at string) {
	if z.ProxyPort != nil {
		v.rangeInt(at+".proxyPort", z.ProxyPort, 1, 65535)
	}
	v.enum(at+".zoneTransferProtocol", (*string)(z.ZoneTransferProtocol), "Tcp", "Tls", "Quic")
	v.enum(at+".protocol", (*string)(z.Protocol), "Udp", "Tcp", "Tls", "Https", "Quic")
	v.enum(at+".proxyType", (*string)(z.ProxyType), "DefaultProxy", "None", "Http", "Socks5", "NoProxy")
	if z.TsigKeyName != nil && strings.TrimSpace(*z.TsigKeyName) == "" {
		v.addf("%s.tsigKeyName must not be empty; leave it out for none", at)
	}
	if z.Forwarder != nil && *z.Forwarder != "this-server" {
		v.nameServer(at+".forwarder", *z.Forwarder)
	}
	for i, a := range z.PrimaryNameServerAddresses {
		v.nameServer(fmt.Sprintf("%s.primaryNameServerAddresses[%d]", at, i), a)
	}
	a := z.ACLSettings
	if a == nil {
		return
	}
	at += ".aclSettings"
	v.enum(at+".queryAccess", (*string)(a.QueryAccess), "Deny", "Allow", "AllowOnlyPrivateNetworks", "AllowOnlyZoneNameServers",
		"UseSpecifiedNetworkACL", "AllowZoneNameServersAndUseSpecifiedNetworkACL")
	v.enum(at+".zoneTransfer", (*string)(a.ZoneTransfer), "Deny", "Allow", "AllowOnlyZoneNameServers",
		"UseSpecifiedNetworkACL", "AllowZoneNameServersAndUseSpecifiedNetworkACL")
	v.enum(at+".notify", (*string)(a.Notify), "None", "ZoneNameServers", "SpecifiedNameServers",
		"BothZoneAndSpecifiedNameServers", "SeparateNameServersForCatalogAndMemberZones")
	v.enum(at+".update", (*string)(a.Update), "Deny", "Allow", "AllowOnlyZoneNameServers",
		"UseSpecifiedNetworkACL", "AllowZoneNameServersAndUseSpecifiedNetworkACL")
	for field, list := range map[string][]string{"queryAccessNetworkACL": a.QueryAccessNetworkACL,
		"zoneTransferNetworkACL": a.ZoneTransferNetworkACL, "updateNetworkACL": a.UpdateNetworkACL} {
		for i, e := range list {
			v.acl(fmt.Sprintf("%s.%s[%d]", at, field, i), e)
		}
	}
	for field, list := range map[string][]string{"notifyNameServers": a.NotifyNameServers,
		"notifySecondaryCatalogsNameServers": a.NotifySecondaryCatalogNameSrvrs} {
		for i, e := range list {
			v.ip(fmt.Sprintf("%s.%s[%d]", at, field, i), e, false, false)
		}
	}
	for i, k := range a.ZoneTransferTsigKeys {
		if strings.Trim(strings.TrimSpace(k), ".") == "" {
			v.addf("%s.zoneTransferTsigKeyNames[%d] is empty", at, i)
		}
	}
	if a.UpdateSecPolicies != nil {
		validateUpdatePolicies(v, at+".updateSecurityPolicies", *a.UpdateSecPolicies, ZoneKey(z.Zone))
	}
}

// validateUpdatePolicies mirrors the server's parser: "key|domain|types"
// triples joined by "|", types separated by commas or spaces, each domain
// inside the zone.
func validateUpdatePolicies(v *validator, at, policies, zone string) {
	var parts []string
	for _, p := range strings.Split(policies, "|") {
		if p = strings.TrimSpace(p); p != "" {
			parts = append(parts, p)
		}
	}
	if len(parts)%3 != 0 {
		v.addf("%s must be tsigKeyName|domain|types triples joined by |; found %d fields", at, len(parts))
		return
	}
	for i := 0; i < len(parts); i += 3 {
		if d := CanonicalName(parts[i+1]); zone != "" && !InZone(d, zone) {
			v.addf("%s: domain %q is outside the zone %q", at, parts[i+1], zone)
		}
		types := strings.FieldsFunc(parts[i+2], func(r rune) bool { return r == ',' || r == ' ' })
		if len(types) == 0 {
			v.addf("%s: policy for %q lists no record types", at, parts[i+1])
		}
		for _, t := range types {
			if !serverParsesType(t) {
				v.addf("%s: %q is not a record type name or number", at, t)
			}
		}
	}
}

// serverParsesType reports whether Enum.Parse<DnsResourceRecordType>
// accepts s: a type name or a plain number, not "TYPE<n>".
func serverParsesType(s string) bool {
	if _, err := strconv.ParseUint(s, 10, 16); err == nil {
		return true
	}
	_, ok := recordTypeNumbers[RecordType(strings.ToUpper(s))]
	return ok
}

// validateSvcParams mirrors DnsSvcParamValue.Parse for each key.
func validateSvcParams(v *validator, at, params string) {
	if params == "" || strings.EqualFold(params, "false") {
		return
	}
	parts := strings.Split(params, "|")
	if len(parts)%2 != 0 {
		v.addf("%s must be key|value pairs joined by |", at)
		return
	}
	isKey := func(k string) bool {
		k = normalizeSvcParamKey(k)
		if _, err := strconv.ParseUint(k, 10, 16); err == nil {
			return true
		}
		for _, name := range svcParamKeys {
			if k == name {
				return true
			}
		}
		return false
	}
	for i := 0; i < len(parts); i += 2 {
		key, value := parts[i], parts[i+1]
		if !isKey(key) {
			v.addf("%s: unknown key %q", at, key)
			continue
		}
		switch normalizeSvcParamKey(key) {
		case "mandatory":
			for _, k := range strings.Split(value, ",") {
				if !isKey(k) {
					v.addf("%s: mandatory lists unknown key %q", at, k)
				}
			}
		case "port":
			if _, err := strconv.ParseUint(value, 10, 16); err != nil {
				v.addf("%s: port %q must be a number from 0 to 65535", at, value)
			}
		case "ipv4hint", "ipv6hint":
			want4 := normalizeSvcParamKey(key) == "ipv4hint"
			for _, a := range strings.Split(value, ",") {
				v.ip(at+"."+normalizeSvcParamKey(key), strings.TrimSpace(a), want4, !want4)
			}
		case "alpn", "no-default-alpn", "dohpath":
		default:
			if _, err := decodeRData(value); err != nil {
				v.addf("%s: %s value must be hex", at, normalizeSvcParamKey(key))
			}
		}
	}
}

// validateRecordSets checks what spans records without knowing the server's
// zones, so only what holds wherever a record lands: two values for a
// single-value name, and records of one name and type with different
// explicit policies. A run places records against the server's zones and
// checks the rest before it changes anything.
func (c *Config) validateRecordSets(v *validator) {
	_, issues := c.GroupRecords(nil)
	for _, is := range issues {
		v.addf("%s: %v", c.RecordLabel(is.Index), is.Err)
	}
}

// RecordLabel names a declared record by its source and identity, such as
// "dns/b.yaml: records[2] (www.example.com A)".
func (c *Config) RecordLabel(i int) string {
	r := c.Records[i]
	return fmt.Sprintf("%s (%s %s)", c.origins.at("records", i), r.Domain, r.Type)
}

// endpoint accepts what InterfaceEndPoint.Parse does: an address with an
// optional port, an IPv6 address in brackets when a port follows, and an
// optional %interface after the address.
func (v *validator) endpoint(field, s string) {
	host, port := s, ""
	if i := strings.LastIndexByte(s, ':'); i >= 0 && (strings.IndexByte(s, ':') == i || (i > 0 && s[i-1] == ']')) {
		host, port = s[:i], s[i+1:]
	}
	if strings.HasPrefix(host, "[") {
		if !strings.HasSuffix(host, "]") {
			v.addf("%s %q has an unbalanced bracket", field, s)
			return
		}
		host = host[1 : len(host)-1]
	}
	if i := strings.LastIndexByte(host, '%'); i >= 0 {
		host = host[:i]
	}
	if _, err := netip.ParseAddr(host); err != nil {
		v.addf("%s %q is not an address or address:port", field, s)
		return
	}
	if port != "" {
		if _, err := strconv.ParseUint(port, 10, 16); err != nil {
			v.addf("%s %q has an invalid port", field, s)
		}
	}
}

// tsigAlgorithms are the names TsigKey accepts.
var tsigAlgorithms = []string{"hmac-md5", "hmac-md5.sig-alg.reg.int", "hmac-sha1", "hmac-sha224", "hmac-sha256",
	"hmac-sha256-128", "hmac-sha384", "hmac-sha384-192", "hmac-sha512", "hmac-sha512-256"}

// nameServer checks an address the way NameServerAddress.Parse does: an
// address or host with an optional port; a udp://, tcp://, tls://, quic://,
// https://, h3:// or http:// URL; or either followed by "(address)", where
// the parenthesized part must be an IP address and any ports must agree.
func (v *validator) nameServer(field, s string) {
	if err := parseNameServer(s); err != nil {
		v.addf("%s %q is not a name server address: %v", field, s, err)
	}
}

func parseNameServer(address string) error {
	address = strings.TrimSpace(address)
	domainName, domainPort := "", 0
	var doh *url.URL
	if i := strings.IndexByte(address, '('); i >= 0 {
		j := strings.IndexByte(address[i+1:], ')')
		if j < 0 {
			return errors.New("missing )")
		}
		part := strings.TrimSpace(address[:i])
		switch scheme := nameServerScheme(part); scheme {
		case "https", "h3", "http":
			u, err := parseServerURL(part)
			if err != nil {
				return err
			}
			doh = u
		case "udp", "tcp", "tls", "quic":
			u, err := parseServerURL(part)
			if err != nil {
				return err
			}
			domainName, domainPort = u.Hostname(), urlPort(u, scheme)
		default:
			parts := strings.Split(part, ":")
			domainName = strings.TrimRight(parts[0], ".")
			if len(parts) > 1 {
				p, err := strconv.Atoi(parts[1])
				if err != nil {
					return fmt.Errorf("port %q is not a number", parts[1])
				}
				domainPort = p
			}
		}
		address = address[i+1 : i+1+j]
	}

	host, port, ipv6Host := "", 0, false
	switch scheme := nameServerScheme(address); {
	case scheme == "https" || scheme == "h3" || scheme == "http":
		u, err := parseServerURL(address)
		if err != nil {
			return err
		}
		doh = u
	case scheme != "":
		u, err := parseServerURL(address)
		if err != nil {
			return err
		}
		host, port = u.Hostname(), urlPort(u, scheme)
	case strings.HasPrefix(address, "["):
		end := strings.LastIndexByte(address, ']')
		if end < 0 {
			return errors.New("unbalanced bracket")
		}
		host = address[1:end]
		if rest := address[end+1:]; rest != "" {
			if !strings.HasPrefix(rest, ":") {
				return errors.New("unexpected text after ]")
			}
			p, err := strconv.Atoi(rest[1:])
			if err != nil {
				return fmt.Errorf("port %q is not a number", rest[1:])
			}
			port = p
		}
		ipv6Host = true
	default:
		if parts := strings.Split(address, ":"); len(parts) == 2 {
			host = strings.TrimSpace(parts[0])
			p, err := strconv.Atoi(parts[1])
			if err != nil {
				return fmt.Errorf("port %q is not a number", parts[1])
			}
			port = p
		} else {
			host = strings.TrimRight(address, ".")
		}
	}

	for _, p := range []int{domainPort, port} {
		if p < 0 || p > 65535 {
			return fmt.Errorf("port %d is out of range", p)
		}
	}
	// DomainEndPoint is built first and rejects an address or a malformed
	// name before the part in parentheses is looked at.
	if domainName != "" {
		if _, err := netip.ParseAddr(domainName); err == nil {
			return fmt.Errorf("%q before the parentheses must be a host name, not an address", domainName)
		}
		if !validDomainName(domainName) {
			return fmt.Errorf("%q is not a host name", domainName)
		}
	}
	_, ipErr := netip.ParseAddr(host)
	if doh != nil {
		if host == "" {
			return nil
		}
		if dohPort := urlPort(doh, nameServerScheme(doh.String())); port != 0 && port != dohPort {
			return errors.New("the ports disagree")
		}
		if ipErr != nil {
			return errors.New("the address in parentheses must be an IP address")
		}
		return nil
	}
	if domainPort != 0 && port != 0 && domainPort != port {
		return errors.New("the ports disagree")
	}
	switch {
	case ipErr == nil:
		return nil
	case domainName != "" || ipv6Host:
		return errors.New("the address must be an IP address")
	case host == "" || !validDomainName(host):
		return fmt.Errorf("%q is not a host name", host)
	}
	return nil
}

func nameServerScheme(s string) string {
	lower := strings.ToLower(s)
	for _, scheme := range []string{"https", "h3", "http", "udp", "tcp", "tls", "quic"} {
		if strings.HasPrefix(lower, scheme+"://") {
			return scheme
		}
	}
	return ""
}

// parseServerURL parses a URL as .NET's Uri would accept it for a name
// server: a host, and a port that fits in 16 bits.
func parseServerURL(s string) (*url.URL, error) {
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return nil, errors.New("not a URL with a host")
	}
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err != nil || n < 0 || n > 65535 {
			return nil, fmt.Errorf("port %s is out of range", p)
		}
	}
	return u, nil
}

// urlPort is the URL's port, or the default for its scheme.
func urlPort(u *url.URL, scheme string) int {
	if p, err := strconv.Atoi(u.Port()); err == nil {
		return p
	}
	switch scheme {
	case "udp", "tcp":
		return 53
	case "tls", "quic":
		return 853
	case "http":
		return 80
	default:
		return 443
	}
}

// validDomainName mirrors DnsClient.IsDomainNameValid after IDN
// conversion: at most 255 characters, and labels of 1 to 63 characters from
// letters, digits, "-", "_" and "/", or a lone "*".
func validDomainName(s string) bool {
	ascii, err := idnaProfile.ToASCII(s)
	if err != nil || len(ascii) > 255 {
		return false
	}
	for _, label := range strings.Split(ascii, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		if label == "*" {
			continue
		}
		for i := 0; i < len(label); i++ {
			if !domainLabelChar(label[i]) {
				return false
			}
		}
	}
	return true
}

func domainLabelChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '/'
}
