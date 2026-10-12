package technitium

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCanonicalName(t *testing.T) {
	tests := map[string]string{
		"Example.Test.":     "example.test",
		"bücher.example":    "xn--bcher-kva.example",
		"*.Wild.example":    "*.wild.example",
		"_sip._tcp.example": "_sip._tcp.example",
		".":                 "",
		// The server maps case and Unicode normalization before Punycode.
		"BÜCHER.example.":      "xn--bcher-kva.example",
		"bu\u0308cher.example": "xn--bcher-kva.example",
	}
	for in, want := range tests {
		assert.Equal(t, want, CanonicalName(in), in)
	}
}

func TestReverseName(t *testing.T) {
	assert.Equal(t, "4.3.2.1.in-addr.arpa", ReverseName(netip.MustParseAddr("1.2.3.4")))
	assert.Equal(t, "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa",
		ReverseName(netip.MustParseAddr("2001:db8::1")))
}

// Each declared record must match the rData the server returns for it, as
// written by WriteRecordAsJson in WebServiceZonesApi.cs. The rData strings
// are what a v15.6.1 server returned for the declared value.
func TestValueKeysMatchServerRData(t *testing.T) {
	tests := []struct {
		name     string
		declared AddRecordRequest
		rdata    string
	}{
		{"A", AddRecordRequest{Type: RT_A, IPAddress: "192.0.2.1"}, `{"ipAddress":"192.0.2.1"}`},
		{"AAAA compressed", AddRecordRequest{Type: RT_AAAA, IPAddress: "2001:0db8:0000::0001"}, `{"ipAddress":"2001:db8::1"}`},
		{"MX", AddRecordRequest{Type: RT_MX, Exchange: "Mail.Example.Test.", Preference: ptr(10)}, `{"preference":10,"exchange":"mail.example.test"}`},
		{"TXT", AddRecordRequest{Type: RT_TXT, Text: ptr("v=spf1 -all")}, `{"text":"v=spf1 -all","splitText":false,"characterStrings":["v=spf1 -all"],"characterStringsBase64":["dj1zcGYxIC1hbGw="]}`},
		{"TXT base64", AddRecordRequest{Type: RT_TXT, CharacterStringsBase64: []string{"YQ==", "Yg=="}}, `{"text":"ab","characterStrings":["a","b"],"characterStringsBase64":["YQ==","Yg=="]}`},
		{"SRV", AddRecordRequest{Type: RT_SRV, Priority: ptr(1), Weight: ptr(2), Port: ptr(5060), Target: "sip.example.test"}, `{"priority":1,"weight":2,"port":5060,"target":"sip.example.test"}`},
		{"NAPTR", AddRecordRequest{Type: RT_NAPTR, NaptrOrder: ptr(1), NaptrPreference: ptr(2), NaptrFlags: "U", NaptrServices: "E2U+sip", NaptrRegexp: "!^.*$!sip:x@y!", NaptrReplacement: "."},
			`{"order":1,"preference":2,"flags":"u","services":"e2u+sip","regexp":"!^.*$!sip:x@y!","replacement":"."}`},
		{"DS", AddRecordRequest{Type: RT_DS, KeyTag: ptr(123), Algorithm: DSAlgoRSASHA256, DigestType: DSDigestSHA256, Digest: "abcd"}, `{"keyTag":123,"algorithm":"RSASHA256","algorithmNumber":8,"digestType":"SHA256","digestTypeNumber":2,"digest":"ABCD"}`},
		{"SSHFP", AddRecordRequest{Type: RT_SSHFP, SSHFPAlgorithm: SSHFPAlgoEd25519, SSHFPFingerprintType: SSHFPFP_SHA256, SSHFPFingerprint: "ab:cd"}, `{"algorithm":"Ed25519","fingerprintType":"SHA256","fingerprint":"ABCD"}`},
		{"TLSA", AddRecordRequest{Type: RT_TLSA, TLSACertificateUsage: TLSAUsageDANEEE, TLSASelector: TLSASelSPKI, TLSAMatchingType: TLSAMatchSHA256, TLSACertificateAssociationData: "00ff"},
			`{"certificateUsage":"DANE-EE","selector":"SPKI","matchingType":"SHA2-256","certificateAssociationData":"00FF"}`},
		{"HTTPS", AddRecordRequest{Type: RT_HTTPS, SvcPriority: ptr(1), SvcTargetName: ".", SvcParams: "port|443|alpn|h2"}, `{"svcPriority":1,"svcTargetName":"","svcParams":{"alpn":"h2","port":"443"}}`},
		{"URI", AddRecordRequest{Type: RT_URI, URIPriority: ptr(1), URIWeight: ptr(1), URI: "HTTPS://Example.Test"}, `{"priority":1,"weight":1,"uri":"https://example.test/"}`},
		{"CAA", AddRecordRequest{Type: RT_CAA, Flags: ptr(0), Tag: "ISSUE", Value: "letsencrypt.org"}, `{"flags":0,"tag":"issue","value":"letsencrypt.org"}`},
		{"FWD", AddRecordRequest{Type: RT_FWD, Protocol: FwdHTTPS, Forwarder: "https://dns.quad9.net/dns-query"}, `{"protocol":"Https","forwarder":"https://dns.quad9.net/dns-query","priority":0,"dnssecValidation":false,"proxyType":"DefaultProxy"}`},
		{"generic", AddRecordRequest{Type: "TYPE65200", RData: "0a0b"}, `{"value":"0A:0B"}`},
		{"AAAA in brackets", AddRecordRequest{Type: RT_AAAA, IPAddress: "[2001:db8::20]"}, `{"ipAddress":"2001:db8::20"}`},
		{"CNAME upper-case IDN", AddRecordRequest{Type: RT_CNAME, CName: "BÜCHER.example."}, `{"cname":"xn--bcher-kva.example","cnameIdn":"bücher.example"}`},
		{"CNAME decomposed IDN", AddRecordRequest{Type: RT_CNAME, CName: "bu\u0308cher.example."}, `{"cname":"xn--bcher-kva.example"}`},
		{"TXT splitText", AddRecordRequest{Type: RT_TXT, Text: ptr("hello\nworld"), SplitText: ptr(true)},
			`{"text":"helloworld","splitText":true,"characterStrings":["hello","world"],"characterStringsBase64":["aGVsbG8=","d29ybGQ="]}`},
		{"TXT splitText escapes", AddRecordRequest{Type: RT_TXT, Text: ptr("a\\tb\r\n\r\nc"), SplitText: ptr(true)},
			`{"characterStringsBase64":["YQli","Yw=="]}`},
		{"TXT longer than one string", AddRecordRequest{Type: RT_TXT, Text: ptr(strings.Repeat("x", 300))},
			`{"characterStringsBase64":["` + base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", 255))) + `","` + base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", 45))) + `"]}`},
		{"TXT binary", AddRecordRequest{Type: RT_TXT, CharacterStringsBase64: []string{"/wA="}}, `{"text":"\ufffd\u0000","characterStringsBase64":["/wA="]}`},
		{"RP domain form", AddRecordRequest{Type: RT_RP, Mailbox: "a.example.", TxtDomain: "b.example."}, `{"mailbox":"a@example","txtDomain":"b.example"}`},
		{"RP email form", AddRecordRequest{Type: RT_RP, Mailbox: "Hostmaster@Example.Test", TxtDomain: "."}, `{"mailbox":"hostmaster@example.test","txtDomain":""}`},
		{"RP escaped dot", AddRecordRequest{Type: RT_RP, Mailbox: `john\.doe.example.test`, TxtDomain: "t.example.test"}, `{"mailbox":"john.doe@example.test","txtDomain":"t.example.test"}`},
		{"SVCB params", AddRecordRequest{Type: RT_SVCB, SvcPriority: ptr(1), SvcTargetName: ".", SvcParams: "port|0443|ipv6hint|2001:0DB8:0::1"},
			`{"svcPriority":1,"svcTargetName":"","svcParams":{"port":"443","ipv6hint":"2001:db8::1"},"autoIpv4Hint":false,"autoIpv6Hint":false}`},
		{"SVCB keys", AddRecordRequest{Type: RT_SVCB, SvcPriority: ptr(1), SvcTargetName: "t.example", SvcParams: "No_Default_ALPN||alpn| h2 ,h3|mandatory|ALPN,3|5|ab:cd|65000|0102"},
			`{"svcPriority":1,"svcTargetName":"t.example","svcParams":{"no-default-alpn":null,"alpn":"h2,h3","mandatory":"alpn,port","ech":"AB:CD","65000":"01:02"}}`},
		{"SVCB no params", AddRecordRequest{Type: RT_SVCB, SvcPriority: ptr(0), SvcTargetName: "t.example"}, `{"svcPriority":0,"svcTargetName":"t.example","svcParams":{}}`},
		{"HTTPS auto hints", AddRecordRequest{Type: RT_HTTPS, SvcPriority: ptr(1), SvcTargetName: ".", SvcParams: "alpn|h2", AutoIpv4Hint: ptr(true)},
			`{"svcPriority":1,"svcTargetName":"","svcParams":{"alpn":"h2","ipv4hint":"192.0.2.1,192.0.2.2"},"autoIpv4Hint":true,"autoIpv6Hint":false}`},
		{"URI canonical", AddRecordRequest{Type: RT_URI, URIPriority: ptr(1), URIWeight: ptr(2), URI: "HTTPS://EXAMPLE.COM:443/a/../b"}, `{"priority":1,"weight":2,"uri":"https://example.com/b"}`},
		{"URI non-default port", AddRecordRequest{Type: RT_URI, URIPriority: ptr(1), URIWeight: ptr(2), URI: "http://Example.com:8080/./x/"}, `{"priority":1,"weight":2,"uri":"http://example.com:8080/x/"}`},
		{"numbered type", AddRecordRequest{Type: "type65200", RData: "0A:0B"}, `{"value":"0A:0B"}`},
		{"URI escapes", AddRecordRequest{Type: RT_URI, URIPriority: ptr(1), URIWeight: ptr(1), URI: "HTTPS://Example.COM:443/a%2Fb/./c/%41"}, `{"priority":1,"weight":1,"uri":"https://example.com/a%2Fb/c/A"}`},
		{"URI unreserved escapes", AddRecordRequest{Type: RT_URI, URIPriority: ptr(1), URIWeight: ptr(1), URI: "https://example.com/x%2fy/%7euser/%20sp?q=%41#f"}, `{"priority":1,"weight":1,"uri":"https://example.com/x%2fy/~user/%20sp?q=A#f"}`},
		{"empty TXT", AddRecordRequest{Type: RT_TXT, Text: ptr("")}, `{"text":"","splitText":false,"characterStrings":[],"characterStringsBase64":[]}`},
		{"empty TXT as base64", AddRecordRequest{Type: RT_TXT, CharacterStringsBase64: []string{}}, `{"text":"","characterStringsBase64":[]}`},
		{"DS by number", AddRecordRequest{Type: RT_DS, KeyTag: ptr(1), Algorithm: "8", DigestType: "2", Digest: "abab"}, `{"keyTag":1,"algorithm":"RSASHA256","algorithmNumber":8,"digestType":"SHA256","digestTypeNumber":2,"digest":"ABAB"}`},
		{"DS by padded and signed numbers", AddRecordRequest{Type: RT_DS, KeyTag: ptr(1), Algorithm: "013", DigestType: "+2", Digest: "abab"}, `{"keyTag":1,"algorithm":"ECDSAP256SHA256","algorithmNumber":13,"digestType":"SHA256","digestTypeNumber":2,"digest":"ABAB"}`},
		{"DS algorithm 0", AddRecordRequest{Type: RT_DS, KeyTag: ptr(1), Algorithm: "0", DigestType: "SHA256", Digest: "abab"}, `{"keyTag":1,"algorithm":"Unknown","algorithmNumber":0,"digestType":"SHA256","digestTypeNumber":2,"digest":"ABAB"}`},
		{"DS algorithm without a name", AddRecordRequest{Type: RT_DS, KeyTag: ptr(1), Algorithm: "99", DigestType: "2", Digest: "abab"}, `{"keyTag":1,"algorithm":"99","algorithmNumber":99,"digestType":"SHA256","digestTypeNumber":2,"digest":"ABAB"}`},
		{"TLSA by number", AddRecordRequest{Type: RT_TLSA, TLSACertificateUsage: "3", TLSASelector: "1", TLSAMatchingType: "1", TLSACertificateAssociationData: "00ff"},
			`{"certificateUsage":"DANE-EE","selector":"SPKI","matchingType":"SHA2-256","certificateAssociationData":"00FF"}`},
		{"HINFO", AddRecordRequest{Type: "HINFO", RData: hex.EncodeToString([]byte("\x03x86\x05Linux"))}, `{"dataType":"DnsHINFORecordData","data":"\"x86\" \"Linux\""}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var m map[string]json.RawMessage
			require.NoError(t, json.Unmarshal([]byte(tt.rdata), &m))
			assert.Equal(t, ValueKeyOf(RecordEntry{Type: tt.declared.Type.Canonical(), RData: m}), tt.declared.ValueKey())
		})
	}
}

func TestRecordFromEntryRoundTrip(t *testing.T) {
	var m map[string]json.RawMessage
	require.NoError(t, json.Unmarshal([]byte(`{"preference":10,"exchange":"mail.example.test"}`), &m))
	e := RecordEntry{Name: "example.test", Type: RT_MX, TTL: 3600, Comments: "primary mail", RData: m}
	r, ok := RecordFromEntry("example.test", e)
	require.True(t, ok)
	assert.Equal(t, "mail.example.test", r.Exchange)
	require.NotNil(t, r.Preference)
	assert.Equal(t, 10, *r.Preference)
	require.NotNil(t, r.TTL)
	assert.Equal(t, 3600, *r.TTL)
	assert.Equal(t, "primary mail", *r.Comments)
	assert.Equal(t, ValueKeyOf(e), r.ValueKey(), "an exported record matches the record it came from")

	_, ok = RecordFromEntry("example.test", RecordEntry{Type: "SOA"})
	assert.False(t, ok)
}

// Export writes TXT as text only when that reproduces the same character
// strings, and HINFO as rdata.
func TestRecordFromEntryRoundTripsByteExactValues(t *testing.T) {
	tests := []struct {
		name  string
		entry string
	}{
		{"TXT one string", `{"name":"t.example","type":"TXT","rData":{"text":"hello","characterStringsBase64":["aGVsbG8="]}}`},
		{"TXT binary", `{"name":"t.example","type":"TXT","rData":{"text":"\ufffd\u0000","characterStringsBase64":["/wA="]}}`},
		{"TXT split", `{"name":"t.example","type":"TXT","rData":{"text":"helloworld","characterStringsBase64":["aGVsbG8=","d29ybGQ="]}}`},
		{"RP", `{"name":"t.example","type":"RP","rData":{"mailbox":"john.doe@example.test","txtDomain":"t.example"}}`},
		{"HINFO", `{"name":"t.example","type":"HINFO","rData":{"dataType":"DnsHINFORecordData","data":"\"x\\\"86\" \"Linux\""}}`},
		{"unknown type", `{"name":"t.example","type":"65200","rData":{"value":"0A:0B"}}`},
		{"SVCB", `{"name":"t.example","type":"SVCB","rData":{"svcPriority":1,"svcTargetName":"","svcParams":{"no-default-alpn":null,"alpn":"h2","port":"8443"}}}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var e RecordEntry
			require.NoError(t, json.Unmarshal([]byte(tt.entry), &e))
			r, ok := RecordFromEntry("t.example", e)
			require.True(t, ok)
			assert.Equal(t, ValueKeyOf(e), r.ValueKey())
		})
	}
}

// Values the server keeps apart must not compare equal.
func TestValueKeysKeepDistinctValues(t *testing.T) {
	uri := func(u string) string {
		return AddRecordRequest{Type: RT_URI, URIPriority: ptr(1), URIWeight: ptr(1), URI: u}.ValueKey()
	}
	assert.NotEqual(t, uri("https://example.test/a%2Fb"), uri("https://example.test/a/b"))
	assert.NotEqual(t, uri("https://example.test/a%20b"), uri("https://example.test/a+b"))
	txt := func(r AddRecordRequest) string { r.Type = RT_TXT; return r.ValueKey() }
	assert.NotEqual(t, txt(AddRecordRequest{Text: ptr("")}), txt(AddRecordRequest{CharacterStringsBase64: []string{""}}), "no strings differs from one empty string")
	assert.NotEqual(t, txt(AddRecordRequest{Text: ptr("ab")}), txt(AddRecordRequest{CharacterStringsBase64: []string{"YQ==", "Yg=="}}))
}

func TestRecordTypeCanonical(t *testing.T) {
	tests := []struct {
		in        RecordType
		canonical RecordType
		api       string
		known     bool
	}{
		{"a", "A", "A", true},
		{"TYPE1", "A", "A", true},
		{"65", "HTTPS", "HTTPS", true},
		{"type65200", "TYPE65200", "65200", true},
		{"65200", "TYPE65200", "65200", true},
		{"TYPE065200", "TYPE65200", "65200", true},
		{"nsap_ptr", "NSAP_PTR", "NSAP_PTR", true},
		{"BOGUS", "BOGUS", "BOGUS", false},
		{"TYPE70000", "TYPE70000", "TYPE70000", false},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.canonical, tt.in.Canonical(), tt.in)
		assert.Equal(t, tt.api, tt.in.APIValue(), tt.in)
		assert.Equal(t, tt.known, tt.in.Known(), tt.in)
	}
}

func TestZoneKey(t *testing.T) {
	assert.Equal(t, ".", ZoneKey("."))
	assert.Equal(t, "example.test", ZoneKey("Example.Test."))
	assert.Equal(t, ".", ZoneKey(""), "the server lists the root zone as \"\"")
	assert.Equal(t, ".", ZoneName(""))
	assert.Equal(t, "Example.Test", ZoneName("Example.Test"))
	assert.True(t, InZone("example.test", "."))
	assert.True(t, InZone("www.example.test", "example.test"))
	assert.False(t, InZone("badexample.test", "example.test"))
}

func TestUnexportable(t *testing.T) {
	entry := func(typ RecordType, rdata string) RecordEntry {
		var m map[string]json.RawMessage
		require.NoError(t, json.Unmarshal([]byte(rdata), &m))
		return RecordEntry{Type: typ, RData: m}
	}
	assert.Empty(t, Unexportable(entry(RT_TXT, `{"characterStringsBase64":[]}`)), "no strings is text: \"\"")
	assert.Empty(t, Unexportable(entry(RT_TXT, `{"characterStringsBase64":["YQ=="]}`)))
	assert.NotEmpty(t, Unexportable(entry(RT_TXT, `{"characterStringsBase64":[""]}`)))
	assert.NotEmpty(t, Unexportable(entry(RT_TXT, `{"characterStringsBase64":["YQ==","","Yg=="]}`)))
	assert.NotEmpty(t, Unexportable(entry("RRSIG", `{}`)))
}
