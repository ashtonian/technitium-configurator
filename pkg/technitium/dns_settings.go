package technitium

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// TsigKey is an entry in the tsigKeys setting.
type TsigKey struct {
	KeyName       string `json:"keyName" yaml:"keyName,omitempty"`
	SharedSecret  string `json:"sharedSecret" yaml:"sharedSecret,omitempty"`
	AlgorithmName string `json:"algorithmName" yaml:"algorithmName,omitempty"`
}

// QpmPrefixLimit is a queries-per-minute limit for one IP prefix length.
type QpmPrefixLimit struct {
	Prefix   int `json:"prefix" yaml:"prefix,omitempty"`
	UdpLimit int `json:"udpLimit" yaml:"udpLimit,omitempty"`
	TcpLimit int `json:"tcpLimit" yaml:"tcpLimit,omitempty"`
}

// DnsSettings is the desired-state body for /api/settings/set. Every field is
// a pointer: nil leaves the server value untouched, while an explicit false,
// 0, "" or [] is sent and applied. The JSON keys match the setter in
// DnsServerCore/WebServiceSettingsApi.cs (v15.6); legacy aliases the server
// still accepts (preferIPv6, enableLogging, reverseProxyNetworkACL) are
// replaced by ipv6Mode, loggingType and dnsReverseProxyNetworkACL.
type DnsSettings struct {
	// General
	DnsServerDomain                     *string           `json:"dnsServerDomain,omitempty" yaml:"dnsServerDomain,omitempty"`
	DnsServerLocalEndPoints             *[]string         `json:"dnsServerLocalEndPoints,omitempty" yaml:"dnsServerLocalEndPoints,omitempty"`
	DnsServerIPv4SourceAddresses        *[]string         `json:"dnsServerIPv4SourceAddresses,omitempty" yaml:"dnsServerIPv4SourceAddresses,omitempty"`
	DnsServerIPv6SourceAddresses        *[]string         `json:"dnsServerIPv6SourceAddresses,omitempty" yaml:"dnsServerIPv6SourceAddresses,omitempty"`
	DefaultRecordTtl                    *int              `json:"defaultRecordTtl,omitempty" yaml:"defaultRecordTtl,omitempty"`
	DefaultNsRecordTtl                  *int              `json:"defaultNsRecordTtl,omitempty" yaml:"defaultNsRecordTtl,omitempty"`
	DefaultSoaRecordTtl                 *int              `json:"defaultSoaRecordTtl,omitempty" yaml:"defaultSoaRecordTtl,omitempty"`
	DefaultResponsiblePerson            *string           `json:"defaultResponsiblePerson,omitempty" yaml:"defaultResponsiblePerson,omitempty"`
	UseSoaSerialDateScheme              *bool             `json:"useSoaSerialDateScheme,omitempty" yaml:"useSoaSerialDateScheme,omitempty"`
	MinSoaRefresh                       *int              `json:"minSoaRefresh,omitempty" yaml:"minSoaRefresh,omitempty"`
	MinSoaRetry                         *int              `json:"minSoaRetry,omitempty" yaml:"minSoaRetry,omitempty"`
	ZoneTransferAllowedNetworks         *[]string         `json:"zoneTransferAllowedNetworks,omitempty" yaml:"zoneTransferAllowedNetworks,omitempty"`
	NotifyAllowedNetworks               *[]string         `json:"notifyAllowedNetworks,omitempty" yaml:"notifyAllowedNetworks,omitempty"`
	DnsAppsEnableAutomaticUpdate        *bool             `json:"dnsAppsEnableAutomaticUpdate,omitempty" yaml:"dnsAppsEnableAutomaticUpdate,omitempty"`
	DnsServerEnableCheckForUpdate       *bool             `json:"dnsServerEnableCheckForUpdate,omitempty" yaml:"dnsServerEnableCheckForUpdate,omitempty"`
	IPv6Mode                            *string           `json:"ipv6Mode,omitempty" yaml:"ipv6Mode,omitempty"`
	EnableUdpSocketPool                 *bool             `json:"enableUdpSocketPool,omitempty" yaml:"enableUdpSocketPool,omitempty"`
	SocketPoolExcludedPorts             *[]int            `json:"socketPoolExcludedPorts,omitempty" yaml:"socketPoolExcludedPorts,omitempty"`
	UdpPayloadSize                      *int              `json:"udpPayloadSize,omitempty" yaml:"udpPayloadSize,omitempty"`
	DnssecValidation                    *bool             `json:"dnssecValidation,omitempty" yaml:"dnssecValidation,omitempty"`
	EDnsClientSubnet                    *bool             `json:"eDnsClientSubnet,omitempty" yaml:"eDnsClientSubnet,omitempty"`
	EDnsClientSubnetIPv4PrefixLength    *int              `json:"eDnsClientSubnetIPv4PrefixLength,omitempty" yaml:"eDnsClientSubnetIPv4PrefixLength,omitempty"`
	EDnsClientSubnetIPv6PrefixLength    *int              `json:"eDnsClientSubnetIPv6PrefixLength,omitempty" yaml:"eDnsClientSubnetIPv6PrefixLength,omitempty"`
	EDnsClientSubnetIpv4Override        *string           `json:"eDnsClientSubnetIpv4Override,omitempty" yaml:"eDnsClientSubnetIpv4Override,omitempty"`
	EDnsClientSubnetIpv6Override        *string           `json:"eDnsClientSubnetIpv6Override,omitempty" yaml:"eDnsClientSubnetIpv6Override,omitempty"`
	EnableEDnsClientSubnetSourceAddress *bool             `json:"enableEDnsClientSubnetSourceAddress,omitempty" yaml:"enableEDnsClientSubnetSourceAddress,omitempty"`
	QpmPrefixLimitsIPv4                 *[]QpmPrefixLimit `json:"qpmPrefixLimitsIPv4,omitempty" yaml:"qpmPrefixLimitsIPv4,omitempty"`
	QpmPrefixLimitsIPv6                 *[]QpmPrefixLimit `json:"qpmPrefixLimitsIPv6,omitempty" yaml:"qpmPrefixLimitsIPv6,omitempty"`
	QpmLimitSampleMinutes               *int              `json:"qpmLimitSampleMinutes,omitempty" yaml:"qpmLimitSampleMinutes,omitempty"`
	QpmLimitUdpTruncationPercentage     *int              `json:"qpmLimitUdpTruncationPercentage,omitempty" yaml:"qpmLimitUdpTruncationPercentage,omitempty"`
	QpmLimitBypassList                  *[]string         `json:"qpmLimitBypassList,omitempty" yaml:"qpmLimitBypassList,omitempty"`
	ClientTimeout                       *int              `json:"clientTimeout,omitempty" yaml:"clientTimeout,omitempty"`
	TcpSendTimeout                      *int              `json:"tcpSendTimeout,omitempty" yaml:"tcpSendTimeout,omitempty"`
	TcpReceiveTimeout                   *int              `json:"tcpReceiveTimeout,omitempty" yaml:"tcpReceiveTimeout,omitempty"`
	QuicIdleTimeout                     *int              `json:"quicIdleTimeout,omitempty" yaml:"quicIdleTimeout,omitempty"`
	QuicMaxInboundStreams               *int              `json:"quicMaxInboundStreams,omitempty" yaml:"quicMaxInboundStreams,omitempty"`
	ListenBacklog                       *int              `json:"listenBacklog,omitempty" yaml:"listenBacklog,omitempty"`
	MaxConcurrentResolutionsPerCore     *int              `json:"maxConcurrentResolutionsPerCore,omitempty" yaml:"maxConcurrentResolutionsPerCore,omitempty"`
	UdpSendBufferSizeKB                 *int              `json:"udpSendBufferSizeKB,omitempty" yaml:"udpSendBufferSizeKB,omitempty"`
	UdpReceiveBufferSizeKB              *int              `json:"udpReceiveBufferSizeKB,omitempty" yaml:"udpReceiveBufferSizeKB,omitempty"`
	LocallyServedDnsZones               *bool             `json:"locallyServedDnsZones,omitempty" yaml:"locallyServedDnsZones,omitempty"`

	// Web service
	WebServiceLocalAddresses              *[]string `json:"webServiceLocalAddresses,omitempty" yaml:"webServiceLocalAddresses,omitempty"`
	WebServiceHttpPort                    *int      `json:"webServiceHttpPort,omitempty" yaml:"webServiceHttpPort,omitempty"`
	WebServiceEnableTls                   *bool     `json:"webServiceEnableTls,omitempty" yaml:"webServiceEnableTls,omitempty"`
	WebServiceEnableHttp3                 *bool     `json:"webServiceEnableHttp3,omitempty" yaml:"webServiceEnableHttp3,omitempty"`
	WebServiceHttpToTlsRedirect           *bool     `json:"webServiceHttpToTlsRedirect,omitempty" yaml:"webServiceHttpToTlsRedirect,omitempty"`
	WebServiceUseSelfSignedTlsCertificate *bool     `json:"webServiceUseSelfSignedTlsCertificate,omitempty" yaml:"webServiceUseSelfSignedTlsCertificate,omitempty"`
	WebServiceTlsPort                     *int      `json:"webServiceTlsPort,omitempty" yaml:"webServiceTlsPort,omitempty"`
	WebServiceTlsCertificatePath          *string   `json:"webServiceTlsCertificatePath,omitempty" yaml:"webServiceTlsCertificatePath,omitempty"`
	WebServiceTlsCertificatePassword      *string   `json:"webServiceTlsCertificatePassword,omitempty" yaml:"webServiceTlsCertificatePassword,omitempty"`
	WebServiceRealIpHeader                *string   `json:"webServiceRealIpHeader,omitempty" yaml:"webServiceRealIpHeader,omitempty"`
	WebServiceReverseProxyAddresses       *[]string `json:"webServiceReverseProxyAddresses,omitempty" yaml:"webServiceReverseProxyAddresses,omitempty"`
	WebServiceEnableHttpUnixSocket        *bool     `json:"webServiceEnableHttpUnixSocket,omitempty" yaml:"webServiceEnableHttpUnixSocket,omitempty"`
	WebServiceHttpUnixSocket              *string   `json:"webServiceHttpUnixSocket,omitempty" yaml:"webServiceHttpUnixSocket,omitempty"`
	WebServiceEnableTlsUnixSocket         *bool     `json:"webServiceEnableTlsUnixSocket,omitempty" yaml:"webServiceEnableTlsUnixSocket,omitempty"`
	WebServiceTlsUnixSocket               *string   `json:"webServiceTlsUnixSocket,omitempty" yaml:"webServiceTlsUnixSocket,omitempty"`
	WebServiceCspFrameAncestorsHeader     *string   `json:"webServiceCspFrameAncestorsHeader,omitempty" yaml:"webServiceCspFrameAncestorsHeader,omitempty"`

	// Optional protocols
	EnableDnsOverUdpProxy         *bool     `json:"enableDnsOverUdpProxy,omitempty" yaml:"enableDnsOverUdpProxy,omitempty"`
	EnableDnsOverTcpProxy         *bool     `json:"enableDnsOverTcpProxy,omitempty" yaml:"enableDnsOverTcpProxy,omitempty"`
	EnableDnsOverHttp             *bool     `json:"enableDnsOverHttp,omitempty" yaml:"enableDnsOverHttp,omitempty"`
	EnableDnsOverTls              *bool     `json:"enableDnsOverTls,omitempty" yaml:"enableDnsOverTls,omitempty"`
	EnableDnsOverHttps            *bool     `json:"enableDnsOverHttps,omitempty" yaml:"enableDnsOverHttps,omitempty"`
	EnableDnsOverHttp3            *bool     `json:"enableDnsOverHttp3,omitempty" yaml:"enableDnsOverHttp3,omitempty"`
	EnableDnsOverQuic             *bool     `json:"enableDnsOverQuic,omitempty" yaml:"enableDnsOverQuic,omitempty"`
	EnableDnsOverHttpUnixSocket   *bool     `json:"enableDnsOverHttpUnixSocket,omitempty" yaml:"enableDnsOverHttpUnixSocket,omitempty"`
	EnableDnsOverHttpsUnixSocket  *bool     `json:"enableDnsOverHttpsUnixSocket,omitempty" yaml:"enableDnsOverHttpsUnixSocket,omitempty"`
	EnableDnsOverHttpHelpRedirect *bool     `json:"enableDnsOverHttpHelpRedirect,omitempty" yaml:"enableDnsOverHttpHelpRedirect,omitempty"`
	DnsOverUdpProxyPort           *int      `json:"dnsOverUdpProxyPort,omitempty" yaml:"dnsOverUdpProxyPort,omitempty"`
	DnsOverTcpProxyPort           *int      `json:"dnsOverTcpProxyPort,omitempty" yaml:"dnsOverTcpProxyPort,omitempty"`
	DnsOverHttpPort               *int      `json:"dnsOverHttpPort,omitempty" yaml:"dnsOverHttpPort,omitempty"`
	DnsOverTlsPort                *int      `json:"dnsOverTlsPort,omitempty" yaml:"dnsOverTlsPort,omitempty"`
	DnsOverHttpsPort              *int      `json:"dnsOverHttpsPort,omitempty" yaml:"dnsOverHttpsPort,omitempty"`
	DnsOverQuicPort               *int      `json:"dnsOverQuicPort,omitempty" yaml:"dnsOverQuicPort,omitempty"`
	DnsOverHttpUnixSocket         *string   `json:"dnsOverHttpUnixSocket,omitempty" yaml:"dnsOverHttpUnixSocket,omitempty"`
	DnsOverHttpsUnixSocket        *string   `json:"dnsOverHttpsUnixSocket,omitempty" yaml:"dnsOverHttpsUnixSocket,omitempty"`
	DnsReverseProxyNetworkACL     *[]string `json:"dnsReverseProxyNetworkACL,omitempty" yaml:"dnsReverseProxyNetworkACL,omitempty"`
	DnsTlsCertificatePath         *string   `json:"dnsTlsCertificatePath,omitempty" yaml:"dnsTlsCertificatePath,omitempty"`
	DnsTlsCertificatePassword     *string   `json:"dnsTlsCertificatePassword,omitempty" yaml:"dnsTlsCertificatePassword,omitempty"`
	DnsOverHttpRealIpHeader       *string   `json:"dnsOverHttpRealIpHeader,omitempty" yaml:"dnsOverHttpRealIpHeader,omitempty"`

	// TSIG
	TsigKeys *[]TsigKey `json:"tsigKeys,omitempty" yaml:"tsigKeys,omitempty"`

	// Recursion
	Recursion             *string   `json:"recursion,omitempty" yaml:"recursion,omitempty"`
	RecursionNetworkACL   *[]string `json:"recursionNetworkACL,omitempty" yaml:"recursionNetworkACL,omitempty"`
	RandomizeName         *bool     `json:"randomizeName,omitempty" yaml:"randomizeName,omitempty"`
	QnameMinimization     *bool     `json:"qnameMinimization,omitempty" yaml:"qnameMinimization,omitempty"`
	ResolverRetries       *int      `json:"resolverRetries,omitempty" yaml:"resolverRetries,omitempty"`
	ResolverTimeout       *int      `json:"resolverTimeout,omitempty" yaml:"resolverTimeout,omitempty"`
	ResolverConcurrency   *int      `json:"resolverConcurrency,omitempty" yaml:"resolverConcurrency,omitempty"`
	ResolverMaxStackCount *int      `json:"resolverMaxStackCount,omitempty" yaml:"resolverMaxStackCount,omitempty"`

	// Cache
	SaveCache                *bool  `json:"saveCache,omitempty" yaml:"saveCache,omitempty"`
	ServeStale               *bool  `json:"serveStale,omitempty" yaml:"serveStale,omitempty"`
	ServeStaleTtl            *int   `json:"serveStaleTtl,omitempty" yaml:"serveStaleTtl,omitempty"`
	ServeStaleAnswerTtl      *int   `json:"serveStaleAnswerTtl,omitempty" yaml:"serveStaleAnswerTtl,omitempty"`
	ServeStaleResetTtl       *int   `json:"serveStaleResetTtl,omitempty" yaml:"serveStaleResetTtl,omitempty"`
	ServeStaleMaxWaitTime    *int   `json:"serveStaleMaxWaitTime,omitempty" yaml:"serveStaleMaxWaitTime,omitempty"`
	CacheMaximumEntries      *int64 `json:"cacheMaximumEntries,omitempty" yaml:"cacheMaximumEntries,omitempty"`
	CacheMinimumRecordTtl    *int   `json:"cacheMinimumRecordTtl,omitempty" yaml:"cacheMinimumRecordTtl,omitempty"`
	CacheMaximumRecordTtl    *int   `json:"cacheMaximumRecordTtl,omitempty" yaml:"cacheMaximumRecordTtl,omitempty"`
	CacheNegativeRecordTtl   *int   `json:"cacheNegativeRecordTtl,omitempty" yaml:"cacheNegativeRecordTtl,omitempty"`
	CacheFailureRecordTtl    *int   `json:"cacheFailureRecordTtl,omitempty" yaml:"cacheFailureRecordTtl,omitempty"`
	EnableCachePrefetch      *bool  `json:"enableCachePrefetch,omitempty" yaml:"enableCachePrefetch,omitempty"`
	CachePrefetchEligibility *int   `json:"cachePrefetchEligibility,omitempty" yaml:"cachePrefetchEligibility,omitempty"`
	CachePrefetchTrigger     *int   `json:"cachePrefetchTrigger,omitempty" yaml:"cachePrefetchTrigger,omitempty"`

	// Blocking
	EnableBlocking               *bool     `json:"enableBlocking,omitempty" yaml:"enableBlocking,omitempty"`
	AllowTxtBlockingReport       *bool     `json:"allowTxtBlockingReport,omitempty" yaml:"allowTxtBlockingReport,omitempty"`
	BlockingBypassList           *[]string `json:"blockingBypassList,omitempty" yaml:"blockingBypassList,omitempty"`
	BlockingType                 *string   `json:"blockingType,omitempty" yaml:"blockingType,omitempty"`
	BlockingAnswerTtl            *int      `json:"blockingAnswerTtl,omitempty" yaml:"blockingAnswerTtl,omitempty"`
	CustomBlockingAddresses      *[]string `json:"customBlockingAddresses,omitempty" yaml:"customBlockingAddresses,omitempty"`
	BlockListUrls                *[]string `json:"blockListUrls,omitempty" yaml:"blockListUrls,omitempty"`
	BlockListUpdateIntervalHours *int      `json:"blockListUpdateIntervalHours,omitempty" yaml:"blockListUpdateIntervalHours,omitempty"`

	// Proxy and forwarders. A non-None proxyType replaces the whole proxy, so
	// address, port and any credentials must be given together. The server
	// reads forwarderProtocol only when forwarders is also set.
	ProxyType            *string   `json:"proxyType,omitempty" yaml:"proxyType,omitempty"`
	ProxyAddress         *string   `json:"proxyAddress,omitempty" yaml:"proxyAddress,omitempty"`
	ProxyPort            *int      `json:"proxyPort,omitempty" yaml:"proxyPort,omitempty"`
	ProxyUsername        *string   `json:"proxyUsername,omitempty" yaml:"proxyUsername,omitempty"`
	ProxyPassword        *string   `json:"proxyPassword,omitempty" yaml:"proxyPassword,omitempty"`
	ProxyBypass          *[]string `json:"proxyBypass,omitempty" yaml:"proxyBypass,omitempty"`
	Forwarders           *[]string `json:"forwarders,omitempty" yaml:"forwarders,omitempty"`
	ForwarderProtocol    *string   `json:"forwarderProtocol,omitempty" yaml:"forwarderProtocol,omitempty"`
	ConcurrentForwarding *bool     `json:"concurrentForwarding,omitempty" yaml:"concurrentForwarding,omitempty"`
	ForwarderRetries     *int      `json:"forwarderRetries,omitempty" yaml:"forwarderRetries,omitempty"`
	ForwarderTimeout     *int      `json:"forwarderTimeout,omitempty" yaml:"forwarderTimeout,omitempty"`
	ForwarderConcurrency *int      `json:"forwarderConcurrency,omitempty" yaml:"forwarderConcurrency,omitempty"`

	// Logging
	LoggingType         *string `json:"loggingType,omitempty" yaml:"loggingType,omitempty"`
	IgnoreResolverLogs  *bool   `json:"ignoreResolverLogs,omitempty" yaml:"ignoreResolverLogs,omitempty"`
	LogQueries          *bool   `json:"logQueries,omitempty" yaml:"logQueries,omitempty"`
	UseLocalTime        *bool   `json:"useLocalTime,omitempty" yaml:"useLocalTime,omitempty"`
	LogFolder           *string `json:"logFolder,omitempty" yaml:"logFolder,omitempty"`
	MaxLogFileDays      *int    `json:"maxLogFileDays,omitempty" yaml:"maxLogFileDays,omitempty"`
	EnableInMemoryStats *bool   `json:"enableInMemoryStats,omitempty" yaml:"enableInMemoryStats,omitempty"`
	MaxStatFileDays     *int    `json:"maxStatFileDays,omitempty" yaml:"maxStatFileDays,omitempty"`
	NoStackTrace        *bool   `json:"noStackTrace,omitempty" yaml:"noStackTrace,omitempty"`
}

// ServerSettings is the subset of /api/settings/get the configurator reads.
type ServerSettings struct {
	Version  string    `json:"version"`
	TsigKeys []TsigKey `json:"tsigKeys"`
}

func (c *Client) GetServerSettings(ctx context.Context) (*ServerSettings, error) {
	const path = "/api/settings/get"
	raw, err := c.get(ctx, path, nil)
	if err != nil {
		return nil, fmt.Errorf("get DNS settings: %w", err)
	}
	return decodeResponse[ServerSettings](path, raw)
}

// GetSettingsRaw returns /api/settings/get keyed by setting name.
func (c *Client) GetSettingsRaw(ctx context.Context) (map[string]json.RawMessage, error) {
	const path = "/api/settings/get"
	raw, err := c.get(ctx, path, nil)
	if err != nil {
		return nil, fmt.Errorf("get DNS settings: %w", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("%s: decode response: %w", path, err)
	}
	return m, nil
}

// webRestartKeys are the settings whose change makes the server restart its
// web service (SetDnsSettingsAsync, WebServiceSettingsApi.cs).
var webRestartKeys = []string{
	"webServiceLocalAddresses", "webServiceHttpPort", "webServiceEnableTls", "webServiceHttpToTlsRedirect",
	"webServiceTlsPort", "webServiceUseSelfSignedTlsCertificate", "webServiceTlsCertificatePath",
	"webServiceEnableHttpUnixSocket", "webServiceHttpUnixSocket", "webServiceEnableTlsUnixSocket", "webServiceTlsUnixSocket",
	"webServiceEnableHttp3",
}

// SetsWebServiceKeys reports whether s sets any setting that can restart
// the web service.
func (s *DnsSettings) SetsWebServiceKeys() bool {
	b, err := json.Marshal(s)
	if err != nil {
		return false
	}
	var desired map[string]json.RawMessage
	if json.Unmarshal(b, &desired) != nil {
		return false
	}
	for _, k := range webRestartKeys {
		if _, ok := desired[k]; ok {
			return true
		}
	}
	return false
}

// RestartsWebService reports whether applying s changes a setting that
// restarts the web service, given the current settings.
func (s *DnsSettings) RestartsWebService(current map[string]json.RawMessage) bool {
	b, err := json.Marshal(s)
	if err != nil {
		return true
	}
	var desired map[string]json.RawMessage
	if err := json.Unmarshal(b, &desired); err != nil {
		return true
	}
	for _, k := range webRestartKeys {
		want, ok := desired[k]
		if !ok {
			continue
		}
		if !sameSettingValue(want, current[k]) {
			return true
		}
	}
	return false
}

// sameSettingValue compares two JSON values; string lists compare as sets.
func sameSettingValue(a, b json.RawMessage) bool {
	var la, lb []string
	if json.Unmarshal(a, &la) == nil && json.Unmarshal(b, &lb) == nil {
		sort.Strings(la)
		sort.Strings(lb)
		return strings.Join(la, ",") == strings.Join(lb, ",")
	}
	ca, okA := canonicalJSON(string(a))
	cb, okB := canonicalJSON(string(b))
	return okA && okB && string(ca) == string(cb)
}

// SetDNSSettings applies the non-nil fields of s. The server applies fields
// in order and keeps earlier changes when a later field fails.
func (c *Client) SetDNSSettings(ctx context.Context, s *DnsSettings) error {
	if _, err := c.postJSON(ctx, "/api/settings/set", s); err != nil {
		return fmt.Errorf("set DNS settings: %w", err)
	}
	return nil
}
