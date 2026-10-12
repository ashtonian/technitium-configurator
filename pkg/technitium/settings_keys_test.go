package technitium

import (
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// settingsSetterKeys are the keys DnsServerCore/WebServiceSettingsApi.cs
// SetDnsSettingsAsync reads in v15.6, minus the legacy aliases preferIPv6,
// enableLogging and reverseProxyNetworkACL. Update it together with
// DnsSettings when the server adds or removes a setting.
var settingsSetterKeys = []string{
	"allowTxtBlockingReport", "blockListUpdateIntervalHours", "blockListUrls", "blockingAnswerTtl",
	"blockingBypassList", "blockingType", "cacheFailureRecordTtl", "cacheMaximumEntries",
	"cacheMaximumRecordTtl", "cacheMinimumRecordTtl", "cacheNegativeRecordTtl", "cachePrefetchEligibility",
	"cachePrefetchTrigger", "clientTimeout", "concurrentForwarding", "customBlockingAddresses",
	"defaultNsRecordTtl", "defaultRecordTtl", "defaultResponsiblePerson", "defaultSoaRecordTtl",
	"dnsAppsEnableAutomaticUpdate", "dnsOverHttpPort", "dnsOverHttpRealIpHeader", "dnsOverHttpUnixSocket",
	"dnsOverHttpsPort", "dnsOverHttpsUnixSocket", "dnsOverQuicPort", "dnsOverTcpProxyPort",
	"dnsOverTlsPort", "dnsOverUdpProxyPort", "dnsReverseProxyNetworkACL", "dnsServerDomain",
	"dnsServerEnableCheckForUpdate", "dnsServerIPv4SourceAddresses", "dnsServerIPv6SourceAddresses", "dnsServerLocalEndPoints",
	"dnsTlsCertificatePassword", "dnsTlsCertificatePath", "dnssecValidation", "eDnsClientSubnet",
	"eDnsClientSubnetIPv4PrefixLength", "eDnsClientSubnetIPv6PrefixLength", "eDnsClientSubnetIpv4Override", "eDnsClientSubnetIpv6Override",
	"enableBlocking", "enableCachePrefetch", "enableDnsOverHttp", "enableDnsOverHttp3",
	"enableDnsOverHttpHelpRedirect", "enableDnsOverHttpUnixSocket", "enableDnsOverHttps", "enableDnsOverHttpsUnixSocket",
	"enableDnsOverQuic", "enableDnsOverTcpProxy", "enableDnsOverTls", "enableDnsOverUdpProxy",
	"enableEDnsClientSubnetSourceAddress", "enableInMemoryStats", "enableUdpSocketPool", "forwarderConcurrency",
	"forwarderProtocol", "forwarderRetries", "forwarderTimeout", "forwarders",
	"ignoreResolverLogs", "ipv6Mode", "listenBacklog", "locallyServedDnsZones",
	"logFolder", "logQueries", "loggingType", "maxConcurrentResolutionsPerCore",
	"maxLogFileDays", "maxStatFileDays", "minSoaRefresh", "minSoaRetry",
	"noStackTrace", "notifyAllowedNetworks", "proxyAddress", "proxyBypass",
	"proxyPassword", "proxyPort", "proxyType", "proxyUsername",
	"qnameMinimization", "qpmLimitBypassList", "qpmLimitSampleMinutes", "qpmLimitUdpTruncationPercentage",
	"qpmPrefixLimitsIPv4", "qpmPrefixLimitsIPv6", "quicIdleTimeout", "quicMaxInboundStreams",
	"randomizeName", "recursion", "recursionNetworkACL", "resolverConcurrency",
	"resolverMaxStackCount", "resolverRetries", "resolverTimeout", "saveCache",
	"serveStale", "serveStaleAnswerTtl", "serveStaleMaxWaitTime", "serveStaleResetTtl",
	"serveStaleTtl", "socketPoolExcludedPorts", "tcpReceiveTimeout", "tcpSendTimeout",
	"tsigKeys", "udpPayloadSize", "udpReceiveBufferSizeKB", "udpSendBufferSizeKB",
	"useLocalTime", "useSoaSerialDateScheme", "webServiceCspFrameAncestorsHeader", "webServiceEnableHttp3",
	"webServiceEnableHttpUnixSocket", "webServiceEnableTls", "webServiceEnableTlsUnixSocket", "webServiceHttpPort",
	"webServiceHttpToTlsRedirect", "webServiceHttpUnixSocket", "webServiceLocalAddresses", "webServiceRealIpHeader",
	"webServiceReverseProxyAddresses", "webServiceTlsCertificatePassword", "webServiceTlsCertificatePath", "webServiceTlsPort",
	"webServiceTlsUnixSocket", "webServiceUseSelfSignedTlsCertificate", "zoneTransferAllowedNetworks",
}

func TestDnsSettingsCoversSetterKeys(t *testing.T) {
	typ := reflect.TypeOf(DnsSettings{})
	var jsonKeys []string
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		assert.Equal(t, reflect.Pointer, f.Type.Kind(), "field %s must be a pointer so explicit zero values are sent", f.Name)
		jsonName, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		yamlName, _, _ := strings.Cut(f.Tag.Get("yaml"), ",")
		assert.Equal(t, jsonName, yamlName, "field %s json and yaml names differ", f.Name)
		jsonKeys = append(jsonKeys, jsonName)
	}

	want := append([]string(nil), settingsSetterKeys...)
	sort.Strings(want)
	sort.Strings(jsonKeys)
	assert.Equal(t, want, jsonKeys)
}
