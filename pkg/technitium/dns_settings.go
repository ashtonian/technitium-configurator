package technitium

import (
	"context"
	"fmt"
)

// GetDNSSettingsResponse wraps the server reply.
type GetDNSSettingsResponse struct {
	Response DnsSettings `json:"response" yaml:"response"`
	Status   string      `json:"status,omitempty" yaml:"status,omitempty"`
}

// TsigKey represents an entry in the tsigKeys array.
type TsigKey struct {
	KeyName       string `json:"keyName,omitempty" yaml:"keyName,omitempty"`
	SharedSecret  string `json:"sharedSecret,omitempty" yaml:"sharedSecret,omitempty"`
	AlgorithmName string `json:"algorithmName,omitempty" yaml:"algorithmName,omitempty"`
}

// DnsSettings mirrors request/response object from /api/settings/.
type DnsSettings struct {
	// Proxy                                     string    `json:"proxy,omitempty"`
	Version                                   string    `json:"version,omitempty" yaml:"version,omitempty"`
	Uptimestamp                               string    `json:"uptimestamp,omitempty" yaml:"uptimestamp,omitempty"`
	DnsServerDomain                           string    `json:"dnsServerDomain,omitempty" yaml:"dnsServerDomain,omitempty"`
	DnsServerLocalEndPoints                   []string  `json:"dnsServerLocalEndPoints,omitempty" yaml:"dnsServerLocalEndPoints,omitempty"`
	DnsServerIPv4SourceAddresses              []string  `json:"dnsServerIPv4SourceAddresses,omitempty" yaml:"dnsServerIPv4SourceAddresses,omitempty"`
	DnsServerIPv6SourceAddresses              []string  `json:"dnsServerIPv6SourceAddresses,omitempty" yaml:"dnsServerIPv6SourceAddresses,omitempty"`
	DefaultRecordTtl                          int       `json:"defaultRecordTtl,omitempty" yaml:"defaultRecordTtl,omitempty"`
	DefaultResponsiblePerson                  string    `json:"defaultResponsiblePerson,omitempty" yaml:"defaultResponsiblePerson,omitempty"`
	UseSoaSerialDateScheme                    bool      `json:"useSoaSerialDateScheme,omitempty" yaml:"useSoaSerialDateScheme,omitempty"`
	MinSoaRefresh                             int       `json:"minSoaRefresh,omitempty" yaml:"minSoaRefresh,omitempty"`
	MinSoaRetry                               int       `json:"minSoaRetry,omitempty" yaml:"minSoaRetry,omitempty"`
	ZoneTransferAllowedNetworks               []string  `json:"zoneTransferAllowedNetworks,omitempty" yaml:"zoneTransferAllowedNetworks,omitempty"`
	NotifyAllowedNetworks                     []string  `json:"notifyAllowedNetworks,omitempty" yaml:"notifyAllowedNetworks,omitempty"`
	DnsAppsEnableAutomaticUpdate              bool      `json:"dnsAppsEnableAutomaticUpdate,omitempty" yaml:"dnsAppsEnableAutomaticUpdate,omitempty"`
	PreferIPv6                                bool      `json:"preferIPv6,omitempty" yaml:"preferIPv6,omitempty"`
	UdpPayloadSize                            int       `json:"udpPayloadSize,omitempty" yaml:"udpPayloadSize,omitempty"`
	DnssecValidation                          bool      `json:"dnssecValidation,omitempty" yaml:"dnssecValidation,omitempty"`
	EDnsClientSubnet                          bool      `json:"eDnsClientSubnet,omitempty" yaml:"eDnsClientSubnet,omitempty"`
	EDnsClientSubnetIPv4PrefixLength          int       `json:"eDnsClientSubnetIPv4PrefixLength,omitempty" yaml:"eDnsClientSubnetIPv4PrefixLength,omitempty"`
	EDnsClientSubnetIPv6PrefixLength          int       `json:"eDnsClientSubnetIPv6PrefixLength,omitempty" yaml:"eDnsClientSubnetIPv6PrefixLength,omitempty"`
	EDnsClientSubnetIpv4Override              string    `json:"eDnsClientSubnetIpv4Override,omitempty" yaml:"eDnsClientSubnetIpv4Override,omitempty"`
	EDnsClientSubnetIpv6Override              string    `json:"eDnsClientSubnetIpv6Override,omitempty" yaml:"eDnsClientSubnetIpv6Override,omitempty"`
	QpmLimitRequests                          int       `json:"qpmLimitRequests,omitempty" yaml:"qpmLimitRequests,omitempty"`
	QpmLimitErrors                            int       `json:"qpmLimitErrors,omitempty" yaml:"qpmLimitErrors,omitempty"`
	QpmLimitSampleMinutes                     int       `json:"qpmLimitSampleMinutes,omitempty" yaml:"qpmLimitSampleMinutes,omitempty"`
	QpmLimitIPv4PrefixLength                  int       `json:"qpmLimitIPv4PrefixLength,omitempty" yaml:"qpmLimitIPv4PrefixLength,omitempty"`
	QpmLimitIPv6PrefixLength                  int       `json:"qpmLimitIPv6PrefixLength,omitempty" yaml:"qpmLimitIPv6PrefixLength,omitempty"`
	QpmLimitBypassList                        []string  `json:"qpmLimitBypassList,omitempty" yaml:"qpmLimitBypassList,omitempty"`
	ClientTimeout                             int       `json:"clientTimeout,omitempty" yaml:"clientTimeout,omitempty"`
	TcpSendTimeout                            int       `json:"tcpSendTimeout,omitempty" yaml:"tcpSendTimeout,omitempty"`
	TcpReceiveTimeout                         int       `json:"tcpReceiveTimeout,omitempty" yaml:"tcpReceiveTimeout,omitempty"`
	QuicIdleTimeout                           int       `json:"quicIdleTimeout,omitempty" yaml:"quicIdleTimeout,omitempty"`
	QuicMaxInboundStreams                     int       `json:"quicMaxInboundStreams,omitempty" yaml:"quicMaxInboundStreams,omitempty"`
	ListenBacklog                             int       `json:"listenBacklog,omitempty" yaml:"listenBacklog,omitempty"`
	MaxConcurrentResolutionsPerCore           int       `json:"maxConcurrentResolutionsPerCore,omitempty" yaml:"maxConcurrentResolutionsPerCore,omitempty"`
	WebServiceLocalAddresses                  []string  `json:"webServiceLocalAddresses,omitempty" yaml:"webServiceLocalAddresses,omitempty"`
	WebServiceHttpPort                        int       `json:"webServiceHttpPort,omitempty" yaml:"webServiceHttpPort,omitempty"`
	WebServiceEnableTls                       bool      `json:"webServiceEnableTls,omitempty" yaml:"webServiceEnableTls,omitempty"`
	WebServiceEnableHttp3                     bool      `json:"webServiceEnableHttp3,omitempty" yaml:"webServiceEnableHttp3,omitempty"`
	WebServiceHttpToTlsRedirect               bool      `json:"webServiceHttpToTlsRedirect,omitempty" yaml:"webServiceHttpToTlsRedirect,omitempty"`
	WebServiceUseSelfSignedTlsCertificate     bool      `json:"webServiceUseSelfSignedTlsCertificate,omitempty" yaml:"webServiceUseSelfSignedTlsCertificate,omitempty"`
	WebServiceTlsPort                         int       `json:"webServiceTlsPort,omitempty" yaml:"webServiceTlsPort,omitempty"`
	WebServiceTlsCertificatePath              string    `json:"webServiceTlsCertificatePath,omitempty" yaml:"webServiceTlsCertificatePath,omitempty"`
	WebServiceTlsCertificatePassword          string    `json:"webServiceTlsCertificatePassword,omitempty" yaml:"webServiceTlsCertificatePassword,omitempty"`
	WebServiceRealIpHeader                    string    `json:"webServiceRealIpHeader,omitempty" yaml:"webServiceRealIpHeader,omitempty"`
	EnableDnsOverUdpProxy                     bool      `json:"enableDnsOverUdpProxy,omitempty" yaml:"enableDnsOverUdpProxy,omitempty"`
	EnableDnsOverTcpProxy                     bool      `json:"enableDnsOverTcpProxy,omitempty" yaml:"enableDnsOverTcpProxy,omitempty"`
	EnableDnsOverHttp                         bool      `json:"enableDnsOverHttp,omitempty" yaml:"enableDnsOverHttp,omitempty"`
	EnableDnsOverTls                          bool      `json:"enableDnsOverTls,omitempty" yaml:"enableDnsOverTls,omitempty"`
	EnableDnsOverHttps                        bool      `json:"enableDnsOverHttps,omitempty" yaml:"enableDnsOverHttps,omitempty"`
	EnableDnsOverHttp3                        bool      `json:"enableDnsOverHttp3,omitempty" yaml:"enableDnsOverHttp3,omitempty"`
	EnableDnsOverQuic                         bool      `json:"enableDnsOverQuic,omitempty" yaml:"enableDnsOverQuic,omitempty"`
	DnsOverUdpProxyPort                       int       `json:"dnsOverUdpProxyPort,omitempty" yaml:"dnsOverUdpProxyPort,omitempty"`
	DnsOverTcpProxyPort                       int       `json:"dnsOverTcpProxyPort,omitempty" yaml:"dnsOverTcpProxyPort,omitempty"`
	DnsOverHttpPort                           int       `json:"dnsOverHttpPort,omitempty" yaml:"dnsOverHttpPort,omitempty"`
	DnsOverTlsPort                            int       `json:"dnsOverTlsPort,omitempty" yaml:"dnsOverTlsPort,omitempty"`
	DnsOverHttpsPort                          int       `json:"dnsOverHttpsPort,omitempty" yaml:"dnsOverHttpsPort,omitempty"`
	DnsOverQuicPort                           int       `json:"dnsOverQuicPort,omitempty" yaml:"dnsOverQuicPort,omitempty"`
	ReverseProxyNetworkACL                    []string  `json:"reverseProxyNetworkACL,omitempty" yaml:"reverseProxyNetworkACL,omitempty"`
	DnsTlsCertificatePath                     string    `json:"dnsTlsCertificatePath,omitempty" yaml:"dnsTlsCertificatePath,omitempty"`
	DnsTlsCertificatePassword                 string    `json:"dnsTlsCertificatePassword,omitempty" yaml:"dnsTlsCertificatePassword,omitempty"`
	DnsOverHttpRealIpHeader                   string    `json:"dnsOverHttpRealIpHeader,omitempty" yaml:"dnsOverHttpRealIpHeader,omitempty"`
	TsigKeys                                  []TsigKey `json:"tsigKeys,omitempty" yaml:"tsigKeys,omitempty"`
	Recursion                                 string    `json:"recursion,omitempty" yaml:"recursion,omitempty"`
	RecursionNetworkACL                       []string  `json:"recursionNetworkACL,omitempty" yaml:"recursionNetworkACL,omitempty"`
	RandomizeName                             bool      `json:"randomizeName,omitempty" yaml:"randomizeName,omitempty"`
	QnameMinimization                         bool      `json:"qnameMinimization,omitempty" yaml:"qnameMinimization,omitempty"`
	ResolverRetries                           int       `json:"resolverRetries,omitempty" yaml:"resolverRetries,omitempty"`
	ResolverTimeout                           int       `json:"resolverTimeout,omitempty" yaml:"resolverTimeout,omitempty"`
	ResolverConcurrency                       int       `json:"resolverConcurrency,omitempty" yaml:"resolverConcurrency,omitempty"`
	ResolverMaxStackCount                     int       `json:"resolverMaxStackCount,omitempty" yaml:"resolverMaxStackCount,omitempty"`
	SaveCache                                 bool      `json:"saveCache,omitempty" yaml:"saveCache,omitempty"`
	ServeStale                                bool      `json:"serveStale,omitempty" yaml:"serveStale,omitempty"`
	ServeStaleTtl                             int       `json:"serveStaleTtl,omitempty" yaml:"serveStaleTtl,omitempty"`
	ServeStaleAnswerTtl                       int       `json:"serveStaleAnswerTtl,omitempty" yaml:"serveStaleAnswerTtl,omitempty"`
	ServeStaleResetTtl                        int       `json:"serveStaleResetTtl,omitempty" yaml:"serveStaleResetTtl,omitempty"`
	ServeStaleMaxWaitTime                     int       `json:"serveStaleMaxWaitTime,omitempty" yaml:"serveStaleMaxWaitTime,omitempty"`
	CacheMaximumEntries                       int       `json:"cacheMaximumEntries,omitempty" yaml:"cacheMaximumEntries,omitempty"`
	CacheMinimumRecordTtl                     int       `json:"cacheMinimumRecordTtl,omitempty" yaml:"cacheMinimumRecordTtl,omitempty"`
	CacheMaximumRecordTtl                     int       `json:"cacheMaximumRecordTtl,omitempty" yaml:"cacheMaximumRecordTtl,omitempty"`
	CacheNegativeRecordTtl                    int       `json:"cacheNegativeRecordTtl,omitempty" yaml:"cacheNegativeRecordTtl,omitempty"`
	CacheFailureRecordTtl                     int       `json:"cacheFailureRecordTtl,omitempty" yaml:"cacheFailureRecordTtl,omitempty"`
	CachePrefetchEligibility                  int       `json:"cachePrefetchEligibility,omitempty" yaml:"cachePrefetchEligibility,omitempty"`
	CachePrefetchTrigger                      int       `json:"cachePrefetchTrigger,omitempty" yaml:"cachePrefetchTrigger,omitempty"`
	CachePrefetchSampleIntervalInMinutes      int       `json:"cachePrefetchSampleIntervalInMinutes,omitempty" yaml:"cachePrefetchSampleIntervalInMinutes,omitempty"`
	CachePrefetchSampleEligibilityHitsPerHour int       `json:"cachePrefetchSampleEligibilityHitsPerHour,omitempty" yaml:"cachePrefetchSampleEligibilityHitsPerHour,omitempty"`
	EnableBlocking                            bool      `json:"enableBlocking,omitempty" yaml:"enableBlocking,omitempty"`
	AllowTxtBlockingReport                    bool      `json:"allowTxtBlockingReport,omitempty" yaml:"allowTxtBlockingReport,omitempty"`
	BlockingBypassList                        []string  `json:"blockingBypassList,omitempty" yaml:"blockingBypassList,omitempty"`
	BlockingType                              string    `json:"blockingType,omitempty" yaml:"blockingType,omitempty"`
	BlockingAnswerTtl                         int       `json:"blockingAnswerTtl,omitempty" yaml:"blockingAnswerTtl,omitempty"`
	CustomBlockingAddresses                   []string  `json:"customBlockingAddresses,omitempty" yaml:"customBlockingAddresses,omitempty"`
	BlockListUrls                             []string  `json:"blockListUrls,omitempty" yaml:"blockListUrls,omitempty"`
	BlockListUpdateIntervalHours              int       `json:"blockListUpdateIntervalHours,omitempty" yaml:"blockListUpdateIntervalHours,omitempty"`
	BlockListNextUpdatedOn                    string    `json:"blockListNextUpdatedOn,omitempty" yaml:"blockListNextUpdatedOn,omitempty"`
	Forwarders                                []string  `json:"forwarders,omitempty" yaml:"forwarders,omitempty"`
	ForwarderProtocol                         string    `json:"forwarderProtocol,omitempty" yaml:"forwarderProtocol,omitempty"`
	ConcurrentForwarding                      bool      `json:"concurrentForwarding,omitempty" yaml:"concurrentForwarding,omitempty"`
	ForwarderRetries                          int       `json:"forwarderRetries,omitempty" yaml:"forwarderRetries,omitempty"`
	ForwarderTimeout                          int       `json:"forwarderTimeout,omitempty" yaml:"forwarderTimeout,omitempty"`
	ForwarderConcurrency                      int       `json:"forwarderConcurrency,omitempty" yaml:"forwarderConcurrency,omitempty"`
	EnableLogging                             bool      `json:"enableLogging,omitempty" yaml:"enableLogging,omitempty"`
	IgnoreResolverLogs                        bool      `json:"ignoreResolverLogs,omitempty" yaml:"ignoreResolverLogs,omitempty"`
	LogQueries                                bool      `json:"logQueries,omitempty" yaml:"logQueries,omitempty"`
	UseLocalTime                              bool      `json:"useLocalTime,omitempty" yaml:"useLocalTime,omitempty"`
	LogFolder                                 string    `json:"logFolder,omitempty" yaml:"logFolder,omitempty"`
	MaxLogFileDays                            int       `json:"maxLogFileDays,omitempty" yaml:"maxLogFileDays,omitempty"`
	EnableInMemoryStats                       bool      `json:"enableInMemoryStats,omitempty" yaml:"enableInMemoryStats,omitempty"`
	MaxStatFileDays                           int       `json:"maxStatFileDays,omitempty" yaml:"maxStatFileDays,omitempty"`
}

func (c *Client) SetDNSSettings(ctx context.Context, opts DnsSettings) error {
	_, err := c.callPOST(ctx, "/api/settings/set", opts)
	if err != nil {
		return fmt.Errorf("set DNS settings: %w", err)
	}

	return nil
}
