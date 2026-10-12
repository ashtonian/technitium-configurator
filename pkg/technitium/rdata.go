package technitium

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// fieldKind says how a record data field is normalized for comparison.
type fieldKind int

const (
	kindText      fieldKind = iota // exact string
	kindTextFold                   // case-insensitive string
	kindName                       // DNS name
	kindMailbox                    // RP mailbox: "user@domain" or "user.domain"
	kindIP                         // IP address
	kindInt                        // integer
	kindHex                        // hex bytes, separators ignored
	kindEnum                       // enum name, case and '-'/'_' ignored
	kindSvcParams                  // SVCB parameters: "k|v|k|v" or {"k":"v"}
	kindURI                        // absolute URI
	kindJSON                       // JSON document
)

// rdataField maps a field of /api/zones/records/get rData to the add and
// delete parameter of the same value. enum maps the numbers the server also
// accepts for a kindEnum field to the names it returns.
type rdataField struct {
	rdata, param string
	kind         fieldKind
	enum         map[string]string
}

// Enum numbers and names from TechnitiumLibrary (DnssecAlgorithm,
// DnssecDigestType, DnsSSHFPAlgorithm, DnsSSHFPFingerprintType,
// DnsTLSACertificateUsage, DnsTLSASelector, DnsTLSAMatchingType,
// DnsTransportProtocol).
var (
	dnssecAlgorithms = map[string]string{"0": "Unknown", "1": "RSAMD5", "3": "DSA", "5": "RSASHA1", "6": "DSA_NSEC3_SHA1", "7": "RSASHA1_NSEC3_SHA1",
		"8": "RSASHA256", "10": "RSASHA512", "12": "ECC_GOST", "13": "ECDSAP256SHA256", "14": "ECDSAP384SHA384", "15": "ED25519",
		"16": "ED448", "253": "PRIVATEDNS", "254": "PRIVATEOID"}
	dnssecDigestTypes = map[string]string{"0": "Unknown", "1": "SHA1", "2": "SHA256", "3": "GOST_R_34_11_94", "4": "SHA384"}
	sshfpAlgorithms   = map[string]string{"0": "Reserved", "1": "RSA", "2": "DSA", "3": "ECDSA", "4": "Ed25519", "6": "Ed448"}
	sshfpTypes        = map[string]string{"0": "Reserved", "1": "SHA1", "2": "SHA256"}
	tlsaUsages        = map[string]string{"0": "PKIX_TA", "1": "PKIX_EE", "2": "DANE_TA", "3": "DANE_EE", "255": "PrivCert"}
	tlsaSelectors     = map[string]string{"0": "Cert", "1": "SPKI", "255": "PrivSel"}
	tlsaMatchingTypes = map[string]string{"0": "Full", "1": "SHA2_256", "2": "SHA2_512", "255": "PrivMatch"}
	transportNames    = map[string]string{"0": "Udp", "1": "Tcp", "2": "Tls", "3": "Https", "4": "HttpsJson", "5": "Quic"}
)

// recordFields lists, per type, the fields that identify a record's value.
// Names follow WriteRecordAsJson and AddRecord in WebServiceZonesApi.cs.
var recordFields = map[RecordType][]rdataField{
	RT_A:     {{"ipAddress", "ipAddress", kindIP, nil}},
	RT_AAAA:  {{"ipAddress", "ipAddress", kindIP, nil}},
	RT_NS:    {{"nameServer", "nameServer", kindName, nil}},
	RT_CNAME: {{"cname", "cname", kindName, nil}},
	RT_PTR:   {{"ptrName", "ptrName", kindName, nil}},
	RT_MX:    {{"preference", "preference", kindInt, nil}, {"exchange", "exchange", kindName, nil}},
	RT_TXT:   {{"characterStringsBase64", "characterStringsBase64", kindText, nil}},
	RT_RP:    {{"mailbox", "mailbox", kindMailbox, nil}, {"txtDomain", "txtDomain", kindName, nil}},
	RT_SRV:   {{"priority", "priority", kindInt, nil}, {"weight", "weight", kindInt, nil}, {"port", "port", kindInt, nil}, {"target", "target", kindName, nil}},
	RT_NAPTR: {{"order", "naptrOrder", kindInt, nil}, {"preference", "naptrPreference", kindInt, nil}, {"flags", "naptrFlags", kindTextFold, nil},
		{"services", "naptrServices", kindTextFold, nil}, {"regexp", "naptrRegexp", kindText, nil}, {"replacement", "naptrReplacement", kindName, nil}},
	RT_DNAME: {{"dname", "dname", kindName, nil}},
	RT_DS: {{"keyTag", "keyTag", kindInt, nil}, {"algorithm", "algorithm", kindEnum, dnssecAlgorithms},
		{"digestType", "digestType", kindEnum, dnssecDigestTypes}, {"digest", "digest", kindHex, nil}},
	RT_SSHFP: {{"algorithm", "sshfpAlgorithm", kindEnum, sshfpAlgorithms}, {"fingerprintType", "sshfpFingerprintType", kindEnum, sshfpTypes},
		{"fingerprint", "sshfpFingerprint", kindHex, nil}},
	RT_TLSA: {{"certificateUsage", "tlsaCertificateUsage", kindEnum, tlsaUsages}, {"selector", "tlsaSelector", kindEnum, tlsaSelectors},
		{"matchingType", "tlsaMatchingType", kindEnum, tlsaMatchingTypes}, {"certificateAssociationData", "tlsaCertificateAssociationData", kindHex, nil}},
	RT_SVCB:  {{"svcPriority", "svcPriority", kindInt, nil}, {"svcTargetName", "svcTargetName", kindName, nil}, {"svcParams", "svcParams", kindSvcParams, nil}},
	RT_HTTPS: {{"svcPriority", "svcPriority", kindInt, nil}, {"svcTargetName", "svcTargetName", kindName, nil}, {"svcParams", "svcParams", kindSvcParams, nil}},
	RT_URI:   {{"priority", "uriPriority", kindInt, nil}, {"weight", "uriWeight", kindInt, nil}, {"uri", "uri", kindURI, nil}},
	RT_CAA:   {{"flags", "flags", kindInt, nil}, {"tag", "tag", kindTextFold, nil}, {"value", "value", kindText, nil}},
	RT_ANAME: {{"aname", "aname", kindName, nil}},
	RT_FWD:   {{"protocol", "protocol", kindEnum, transportNames}, {"forwarder", "forwarder", kindTextFold, nil}},
	RT_APP:   {{"appName", "appName", kindText, nil}, {"classPath", "classPath", kindText, nil}, {"data", "recordData", kindJSON, nil}},
}

// genericField identifies records of types the table does not list: the
// server takes their data as hex rdata and returns it as colon-separated hex,
// except HINFO, which it parses and returns as text (see genericKeyOf).
var genericField = rdataField{"value", "rdata", kindHex, nil}

// SingleValueTypes may have only one record at a name; adding a second
// value replaces nothing and is rejected by the server.
var SingleValueTypes = map[RecordType]bool{RT_CNAME: true, RT_DNAME: true, RT_APP: true}

// NonAddableTypes are maintained by the server and cannot be declared.
var NonAddableTypes = map[RecordType]bool{
	"SOA": true, "RRSIG": true, "NSEC": true, "NSEC3": true, "NSEC3PARAM": true,
	"DNSKEY": true, "ZONEMD": true, "ALIAS": true, "APL": true, "NXNAME": true,
	"OPT": true, "TKEY": true, "TSIG": true, "IXFR": true, "AXFR": true, "MAILB": true, "MAILA": true, "ANY": true,
	"CHILD_NS": true, "PARENT_NS": true,
}

func fieldsFor(t RecordType) []rdataField {
	if f, ok := recordFields[t.Canonical()]; ok {
		return f
	}
	return []rdataField{genericField}
}

// ValueKey identifies the value of a declared record, so it can be compared
// with ValueKeyOf for a record read from the server. Both sides are reduced
// to the form the server stores, so a value written differently in the
// file (case, IDN, IPv6 spelling, TXT splitting) still matches.
func (r AddRecordRequest) ValueKey() string {
	typ := r.Type.Canonical()
	params := r.params()
	switch typ {
	case RT_TXT:
		return txtKey(r.characterStrings())
	case RT_SVCB, RT_HTTPS:
		return svcbKey(params["svcPriority"], params["svcTargetName"], svcParamsFromString(r.SvcParams),
			r.AutoIpv4Hint != nil && *r.AutoIpv4Hint, r.AutoIpv6Hint != nil && *r.AutoIpv6Hint)
	case RT_FWD:
		return fwdKey(params["protocol"], params["forwarder"], params["forwarderPriority"], params["dnssecValidation"],
			params["proxyType"], params["proxyAddress"], params["proxyPort"], params["proxyUsername"], params["proxyPassword"])
	}
	if _, typed := recordFields[typ]; !typed {
		return genericKey(typ, r.RData)
	}
	var parts []string
	for _, f := range fieldsFor(typ) {
		parts = append(parts, f.normalize(params[f.param]))
	}
	return strings.Join(parts, "\x00")
}

// normalize reduces a value of f to its comparison form. An enum given as
// a number, in any spelling Enum.Parse accepts ("13", "013", "+13"), becomes
// its name, or its plain decimal form when the enum has no name for it, as
// the server reports it.
func (f rdataField) normalize(raw json.RawMessage) string {
	if f.kind == kindEnum && f.enum != nil {
		var s string
		if json.Unmarshal(raw, &s) != nil {
			s = string(raw)
		}
		if n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64); err == nil {
			decimal := strconv.FormatInt(n, 10)
			if name, ok := f.enum[decimal]; ok {
				raw, _ = json.Marshal(name)
			} else {
				raw, _ = json.Marshal(decimal)
			}
		}
	}
	return normalize(f.kind, raw)
}

// ValueKeyOf identifies the value of a record read from the server.
func ValueKeyOf(e RecordEntry) string {
	typ := e.Type.Canonical()
	switch typ {
	case RT_TXT:
		var b64 []string
		_ = json.Unmarshal(e.RData["characterStringsBase64"], &b64)
		strs := make([][]byte, 0, len(b64))
		for _, s := range b64 {
			b, err := base64.StdEncoding.DecodeString(s)
			if err != nil {
				b = []byte(s)
			}
			strs = append(strs, b)
		}
		return txtKey(strs)
	case RT_SVCB, RT_HTTPS:
		var params map[string]*string
		_ = json.Unmarshal(e.RData["svcParams"], &params)
		var auto4, auto6 bool
		_ = json.Unmarshal(e.RData["autoIpv4Hint"], &auto4)
		_ = json.Unmarshal(e.RData["autoIpv6Hint"], &auto6)
		return svcbKey(e.RData["svcPriority"], e.RData["svcTargetName"], params, auto4, auto6)
	case RT_FWD:
		d := e.RData
		return fwdKey(d["protocol"], d["forwarder"], d["priority"], d["dnssecValidation"],
			d["proxyType"], d["proxyAddress"], d["proxyPort"], d["proxyUsername"], d["proxyPassword"])
	}
	if _, typed := recordFields[typ]; !typed {
		return genericKeyOf(typ, e.RData)
	}
	var parts []string
	for _, f := range fieldsFor(typ) {
		parts = append(parts, f.normalize(e.RData[f.rdata]))
	}
	return strings.Join(parts, "\x00")
}

// characterStrings returns the TXT character strings the server builds from
// a declared record (AddRecord in WebServiceZonesApi.cs).
func (r AddRecordRequest) characterStrings() [][]byte {
	var out [][]byte
	switch {
	case len(r.CharacterStringsBase64) > 0:
		for _, s := range r.CharacterStringsBase64 {
			b, err := base64.StdEncoding.DecodeString(s)
			if err != nil {
				b = []byte(s)
			}
			out = append(out, b)
		}
	case r.Text == nil:
	case r.SplitText != nil && *r.SplitText:
		for _, s := range decodeCharacterStrings(*r.Text) {
			out = append(out, []byte(s))
		}
	default:
		// DnsTXTRecordData(string) cuts the UTF-8 bytes into 255-byte strings,
		// so "" has none.
		b := []byte(*r.Text)
		for len(b) > 255 {
			out = append(out, b[:255])
			b = b[255:]
		}
		if len(b) > 0 {
			out = append(out, b)
		}
	}
	return out
}

// decodeCharacterStrings mirrors the server's splitText parsing: one
// character string per line, empty lines dropped, then \n, \r, \t and \\
// unescaped.
func decodeCharacterStrings(text string) []string {
	var out []string
	for _, line := range strings.FieldsFunc(text, func(r rune) bool { return r == '\r' || r == '\n' }) {
		var sb strings.Builder
		for i := 0; i < len(line); i++ {
			if line[i] != '\\' || i+1 == len(line) {
				sb.WriteByte(line[i])
				continue
			}
			switch line[i+1] {
			case 'n':
				sb.WriteByte('\n')
			case 'r':
				sb.WriteByte('\r')
			case 't':
				sb.WriteByte('\t')
			case '\\':
				sb.WriteByte('\\')
			default:
				sb.WriteByte(line[i])
				sb.WriteByte(line[i+1])
			}
			i++
		}
		out = append(out, sb.String())
	}
	return out
}

func txtKey(strs [][]byte) string {
	parts := make([]string, len(strs))
	for i, b := range strs {
		parts[i] = base64.StdEncoding.EncodeToString(b)
	}
	// The count keeps no strings apart from one empty string.
	return "txt:" + strconv.Itoa(len(strs)) + ":" + strings.Join(parts, ",")
}

// svcbKey identifies an SVCB or HTTPS value. Hints the server resolves
// itself (autoIpv4Hint, autoIpv6Hint) are left out, since they follow the
// target's addresses rather than the file.
func svcbKey(priority, target json.RawMessage, params map[string]*string, auto4, auto6 bool) string {
	norm := map[string]string{}
	for k, v := range params {
		val := ""
		if v != nil {
			val = *v
		}
		key, value := normalizeSvcParam(k, val)
		norm[key] = value
	}
	if auto4 {
		delete(norm, "ipv4hint")
	}
	if auto6 {
		delete(norm, "ipv6hint")
	}
	keys := make([]string, 0, len(norm))
	for k := range norm {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var sb strings.Builder
	for _, k := range keys {
		sb.WriteString(k + "=" + norm[k] + ";")
	}
	return strings.Join([]string{normalize(kindInt, priority), normalize(kindName, target), sb.String(),
		strconv.FormatBool(auto4), strconv.FormatBool(auto6)}, "\x00")
}

// fwdKey identifies an FWD value by every field DnsForwarderRecordData
// compares, with the server's defaults for fields left out. The proxy
// fields count only for an Http or Socks5 proxy, the only types that keep
// them.
func fwdKey(protocol, forwarder, priority, dnssec, proxyType, proxyAddress, proxyPort, proxyUsername, proxyPassword json.RawMessage) string {
	or := func(raw json.RawMessage, def string) json.RawMessage {
		if len(raw) == 0 || string(raw) == "null" || string(raw) == `""` {
			return json.RawMessage(def)
		}
		return raw
	}
	proxy := normalize(kindEnum, or(proxyType, `"DefaultProxy"`))
	if proxy == "NONE" {
		// None and DefaultProxy are the same enum value.
		proxy = "DEFAULTPROXY"
	}
	parts := []string{recordFields[RT_FWD][0].normalize(or(protocol, `"Udp"`)), normalize(kindTextFold, forwarder),
		normalize(kindInt, or(priority, "0")), normalize(kindText, or(dnssec, "false")), proxy}
	if proxy == "HTTP" || proxy == "SOCKS5" {
		parts = append(parts, normalize(kindText, proxyAddress), normalize(kindInt, or(proxyPort, "0")),
			normalize(kindText, proxyUsername), normalize(kindText, proxyPassword))
	}
	return strings.Join(parts, "\x00")
}

// svcParamsFromString parses the svcParams parameter, "key|value|...";
// "" and "false" mean no parameters.
func svcParamsFromString(s string) map[string]*string {
	params := map[string]*string{}
	if s == "" || strings.EqualFold(s, "false") {
		return params
	}
	parts := strings.Split(s, "|")
	for i := 0; i+1 < len(parts); i += 2 {
		v := parts[i+1]
		params[parts[i]] = &v
	}
	return params
}

// svcParamKeys is the server's DnsSvcParamKey enum.
var svcParamKeys = []string{"mandatory", "alpn", "no-default-alpn", "port", "ipv4hint", "ech", "ipv6hint", "dohpath"}

// normalizeSvcParamKey returns a key as the server writes it: the enum name
// in lower case with "-", or the number for a key without a name.
func normalizeSvcParamKey(k string) string {
	k = strings.ReplaceAll(strings.ToLower(strings.TrimSpace(k)), "_", "-")
	if n, err := strconv.ParseUint(k, 10, 16); err == nil {
		if n < uint64(len(svcParamKeys)) {
			return svcParamKeys[n]
		}
		return strconv.FormatUint(n, 10)
	}
	return k
}

// normalizeSvcParam mirrors DnsSvcParamValue.Parse and ToString.
func normalizeSvcParam(k, v string) (string, string) {
	key := normalizeSvcParamKey(k)
	list := func(each func(string) string) string {
		var out []string
		for _, item := range strings.Split(v, ",") {
			if item = strings.TrimSpace(item); item != "" {
				out = append(out, each(item))
			}
		}
		return strings.Join(out, ",")
	}
	switch key {
	case "mandatory":
		return key, list(normalizeSvcParamKey)
	case "alpn":
		return key, list(func(s string) string { return s })
	case "no-default-alpn":
		return key, ""
	case "port":
		return key, normalize(kindInt, json.RawMessage(strconv.Quote(v)))
	case "ipv4hint", "ipv6hint":
		return key, list(func(s string) string {
			if a, err := ParseIP(s); err == nil {
				return a.String()
			}
			return strings.ToLower(s)
		})
	case "dohpath":
		return key, v
	default:
		// ech and keys without a name are hex.
		return key, normalize(kindHex, json.RawMessage(strconv.Quote(v)))
	}
}

// genericKey identifies a declared record sent as hex rdata.
func genericKey(typ RecordType, rdata string) string {
	b, err := decodeRData(rdata)
	if err != nil {
		return strings.ToUpper(rdata)
	}
	if typ == "HINFO" {
		if text, ok := hinfoText(b); ok {
			return text
		}
	}
	return strings.ToUpper(hex.EncodeToString(b))
}

// genericKeyOf identifies a record of a type without named fields. The
// server returns DnsUnknownRecordData as colon hex in "value"; HINFO, which
// it parses but does not serialize, comes back as text in "data".
func genericKeyOf(typ RecordType, rdata map[string]json.RawMessage) string {
	if raw, ok := rdata["value"]; ok {
		return normalize(kindHex, raw)
	}
	var data string
	_ = json.Unmarshal(rdata["data"], &data)
	if typ == "HINFO" {
		return data
	}
	return strings.ToUpper(data)
}

func decodeRData(s string) ([]byte, error) {
	return hex.DecodeString(strings.NewReplacer(":", "", "-", "", " ", "").Replace(s))
}

// hinfoText renders HINFO rdata as DnsHINFORecordData.ToString does:
// two quoted character strings with \ and " escaped.
func hinfoText(b []byte) (string, bool) {
	var strs []string
	for len(b) > 0 && len(strs) < 2 {
		n := int(b[0])
		if len(b) < 1+n {
			return "", false
		}
		strs = append(strs, string(b[1:1+n]))
		b = b[1+n:]
	}
	if len(strs) != 2 || len(b) != 0 {
		return "", false
	}
	quote := func(s string) string {
		return `"` + strings.ReplaceAll(strings.ReplaceAll(s, `\`, `\\`), `"`, `\"`) + `"`
	}
	return quote(strs[0]) + " " + quote(strs[1]), true
}

// hinfoRData is the inverse of hinfoText, for export.
func hinfoRData(text string) (string, bool) {
	var strs []string
	for i := 0; i < len(text); {
		if text[i] == ' ' {
			i++
			continue
		}
		if text[i] != '"' {
			return "", false
		}
		var sb strings.Builder
		i++
		for ; i < len(text) && text[i] != '"'; i++ {
			if text[i] == '\\' && i+1 < len(text) {
				i++
			}
			sb.WriteByte(text[i])
		}
		if i == len(text) {
			return "", false
		}
		i++
		strs = append(strs, sb.String())
	}
	if len(strs) != 2 {
		return "", false
	}
	var b []byte
	for _, s := range strs {
		if len(s) > 255 {
			return "", false
		}
		b = append(b, byte(len(s)))
		b = append(b, s...)
	}
	return hex.EncodeToString(b), true
}

// params returns r's API parameters as raw JSON values keyed by name.
func (r AddRecordRequest) params() map[string]json.RawMessage {
	b, _ := json.Marshal(r)
	var m map[string]json.RawMessage
	_ = json.Unmarshal(b, &m)
	return m
}

func normalize(kind fieldKind, raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	if kind == kindJSON {
		var s string
		if json.Unmarshal(raw, &s) != nil {
			s = string(raw)
		}
		if c, ok := canonicalJSON(stripJSONComments(s)); ok {
			return string(c)
		}
		return strings.TrimSpace(s)
	}

	var s string
	if json.Unmarshal(raw, &s) != nil {
		// Numbers and booleans arrive unquoted.
		s = string(raw)
	}
	switch kind {
	case kindTextFold:
		return strings.ToLower(s)
	case kindName:
		return CanonicalName(s)
	case kindMailbox:
		return normalizeMailbox(s)
	case kindIP:
		if a, err := ParseIP(s); err == nil {
			return a.String()
		}
		return strings.ToLower(s)
	case kindInt:
		if n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64); err == nil {
			return strconv.FormatInt(n, 10)
		}
		return s
	case kindHex:
		return strings.ToUpper(strings.NewReplacer(":", "", "-", "", " ", "").Replace(s))
	case kindEnum:
		return strings.ToUpper(strings.NewReplacer("-", "", "_", "").Replace(s))
	case kindURI:
		return normalizeURI(s)
	default:
		return s
	}
}

// normalizeMailbox returns an RP mailbox in the email form the server
// stores (DnsSOARecordData.GetResponsiblePersonEmailFormat): the first
// unescaped "." of the domain form becomes "@". The server compares
// mailboxes without regard to case.
func normalizeMailbox(s string) string {
	s = strings.Trim(strings.TrimSpace(s), ".")
	if i := strings.LastIndexByte(s, '@'); i >= 0 {
		return strings.ToLower(s[:i]) + "@" + CanonicalName(s[i+1:])
	}
	for i := 1; i < len(s); i++ {
		if s[i] == '.' && s[i-1] != '\\' {
			return strings.ToLower(strings.ReplaceAll(s[:i], `\.`, ".")) + "@" + CanonicalName(s[i+1:])
		}
	}
	return CanonicalName(s)
}

// uriDefaultPorts are the schemes whose default port .NET's Uri drops.
var uriDefaultPorts = map[string]string{
	"http": "80", "https": "443", "ws": "80", "wss": "443", "ftp": "21",
	"gopher": "70", "nntp": "119", "telnet": "23", "ldap": "389", "net.tcp": "808",
}

// normalizeURI approximates .NET's Uri.AbsoluteUri, which the server
// stores: lower-case scheme and host, no default port, escaped unreserved
// characters decoded, dot segments removed, and "/" for an empty path after
// a host. Escaped reserved characters such as %2F stay escaped, as written.
func normalizeURI(s string) string {
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil || u.Scheme == "" {
		return s
	}
	u.Scheme = strings.ToLower(u.Scheme)
	if u.Host != "" {
		host, port := strings.ToLower(u.Hostname()), u.Port()
		if strings.Contains(host, ":") {
			host = "[" + host + "]"
		}
		if port != "" && port != uriDefaultPorts[u.Scheme] {
			host += ":" + port
		}
		u.Host = host
	}
	if u.Opaque == "" && u.Host != "" {
		// Work on the escaped path, so "/a%2Fb" and "/a/b" stay distinct.
		escaped := removeDotSegments(decodeUnreserved(u.EscapedPath()))
		if escaped == "" {
			escaped = "/"
		}
		path, err := url.PathUnescape(escaped)
		if err != nil {
			return s
		}
		u.Path, u.RawPath = path, escaped
	}
	u.RawQuery = decodeUnreserved(u.RawQuery)
	return u.String()
}

// decodeUnreserved replaces percent-escapes of unreserved characters
// (letters, digits, "-", ".", "_", "~") with the characters and keeps every
// other escape as written.
func decodeUnreserved(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			if b, err := hex.DecodeString(s[i+1 : i+3]); err == nil {
				c := b[0]
				if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == '_' || c == '~' {
					sb.WriteByte(c)
					i += 2
					continue
				}
			}
		}
		sb.WriteByte(s[i])
	}
	return sb.String()
}

// removeDotSegments is RFC 3986 section 5.2.4.
func removeDotSegments(p string) string {
	var out []string
	for in := p; in != ""; {
		switch {
		case strings.HasPrefix(in, "../"):
			in = in[3:]
		case strings.HasPrefix(in, "./"):
			in = in[2:]
		case strings.HasPrefix(in, "/./"):
			in = in[2:]
		case in == "/.":
			in = "/"
		case strings.HasPrefix(in, "/../"):
			in = in[3:]
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
		case in == "/..":
			in = "/"
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
		case in == "." || in == "..":
			in = ""
		default:
			i := strings.IndexByte(in[1:], '/')
			if i < 0 {
				out = append(out, in)
				in = ""
			} else {
				out = append(out, in[:i+1])
				in = in[i+1:]
			}
		}
	}
	return strings.Join(out, "")
}

// Unexportable says why a record read from the server cannot be written
// back through the API, or returns "" when it can.
func Unexportable(e RecordEntry) string {
	typ := e.Type.Canonical()
	if NonAddableTypes[typ] {
		return string(typ) + " records cannot be declared"
	}
	if typ == RT_TXT {
		var b64 []string
		_ = json.Unmarshal(e.RData["characterStringsBase64"], &b64)
		for _, s := range b64 {
			if s == "" {
				return "TXT records with an empty character string cannot be written through the API"
			}
		}
	}
	return ""
}

// RecordFromEntry converts a record read from the server into the declared
// form, for export. ok is false for types that cannot be declared.
func RecordFromEntry(zone string, e RecordEntry) (r AddRecordRequest, ok bool) {
	typ := e.Type.Canonical()
	if NonAddableTypes[typ] {
		return r, false
	}
	// The server writes the root as "", which a config cannot leave out.
	m := map[string]any{"domain": ZoneName(e.Name), "type": string(typ)}
	if zone != "" {
		m["zone"] = zone
	}
	for _, f := range fieldsFor(typ) {
		raw, present := e.RData[f.rdata]
		if !present || string(raw) == "null" {
			continue
		}
		switch f.kind {
		case kindSvcParams:
			m[f.param] = svcParamsParam(raw)
		case kindMailbox:
			var s string
			if json.Unmarshal(raw, &s) == nil {
				m[f.param] = s
			}
		case kindName:
			// The server writes the root as "", which a config cannot leave
			// out of a required field.
			var s string
			if json.Unmarshal(raw, &s) == nil {
				if s == "" {
					s = "."
				}
				m[f.param] = s
			}
		case kindHex:
			var s string
			if json.Unmarshal(raw, &s) == nil {
				m[f.param] = strings.ReplaceAll(s, ":", "")
			}
		default:
			var v any
			if json.Unmarshal(raw, &v) == nil {
				m[f.param] = v
			}
		}
	}
	if typ == RT_TXT {
		// One character string of valid UTF-8 round-trips as text; anything
		// else keeps its exact bytes and boundaries.
		var b64 []string
		_ = json.Unmarshal(e.RData["characterStringsBase64"], &b64)
		delete(m, "characterStringsBase64")
		b, err := base64.StdEncoding.DecodeString(firstOrEmpty(b64))
		switch {
		case len(b64) == 0:
			// The server stores "" as no character strings at all.
			m["text"] = ""
		case len(b64) == 1 && err == nil && len(b) > 0 && utf8.Valid(b):
			m["text"] = string(b)
		default:
			m["characterStringsBase64"] = b64
		}
	}
	if _, typed := recordFields[typ]; !typed {
		if _, unknown := e.RData["value"]; !unknown {
			var data string
			_ = json.Unmarshal(e.RData["data"], &data)
			rdata, ok := hinfoRData(data)
			if typ != "HINFO" || !ok {
				return r, false
			}
			m["rdata"] = rdata
		}
	}
	if typ == RT_FWD {
		for _, k := range []string{"dnssecValidation", "proxyType", "proxyAddress", "proxyPort", "proxyUsername", "proxyPassword"} {
			var v any
			if raw, present := e.RData[k]; present && json.Unmarshal(raw, &v) == nil {
				m[k] = v
			}
		}
		if raw, present := e.RData["priority"]; present {
			var v any
			if json.Unmarshal(raw, &v) == nil {
				m["forwarderPriority"] = v
			}
		}
	}
	if typ == RT_SVCB || typ == RT_HTTPS {
		for _, k := range []string{"autoIpv4Hint", "autoIpv6Hint"} {
			var v bool
			if raw, present := e.RData[k]; present && json.Unmarshal(raw, &v) == nil && v {
				m[k] = v
			}
		}
	}
	if typ == RT_NS && len(e.GlueRecords) > 0 {
		m["glue"] = strings.Join(e.GlueRecords, ",")
	}
	m["ttl"] = e.TTL
	if e.Comments != "" {
		m["comments"] = e.Comments
	}
	if e.ExpiryTTL > 0 {
		m["expiryTtl"] = e.ExpiryTTL
	}
	b, err := json.Marshal(m)
	if err != nil {
		return r, false
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return r, false
	}
	return r, true
}

func svcParamsParam(raw json.RawMessage) string {
	var pairs map[string]string
	if json.Unmarshal(raw, &pairs) != nil || len(pairs) == 0 {
		return "false"
	}
	keys := make([]string, 0, len(pairs))
	for k := range pairs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		parts = append(parts, k, pairs[k])
	}
	return strings.Join(parts, "|")
}

// DescribeValue renders a record's value for log messages. It leaves out
// APP record data and proxy passwords, which may hold credentials.
func DescribeValue(e RecordEntry) string {
	typ := e.Type.Canonical()
	var fields []string
	switch typ {
	case RT_TXT:
		fields = []string{"text"}
	case RT_SVCB, RT_HTTPS:
		fields = []string{"svcPriority", "svcTargetName", "svcParams"}
	case RT_APP:
		fields = []string{"appName", "classPath"}
	default:
		for _, f := range fieldsFor(typ) {
			fields = append(fields, f.rdata)
		}
		if _, typed := recordFields[typ]; !typed {
			fields = append(fields, "data")
		}
	}
	var parts []string
	for _, name := range fields {
		if raw, ok := e.RData[name]; ok {
			var s string
			if json.Unmarshal(raw, &s) != nil {
				s = string(raw)
			}
			parts = append(parts, s)
		}
	}
	return strings.Join(parts, " ")
}

func firstOrEmpty(s []string) string {
	if len(s) == 0 {
		return ""
	}
	return s[0]
}

// SameGlue reports whether a declared glue list ("addr,addr") names the
// same addresses as an NS record's glue records.
func SameGlue(declared string, glue []string) bool {
	set := func(list []string) map[string]bool {
		m := map[string]bool{}
		for _, a := range list {
			if a = strings.TrimSpace(a); a == "" {
				continue
			}
			if ip, err := ParseIP(a); err == nil {
				a = ip.String()
			}
			m[a] = true
		}
		return m
	}
	d, g := set(strings.Split(declared, ",")), set(glue)
	if len(d) != len(g) {
		return false
	}
	for a := range d {
		if !g[a] {
			return false
		}
	}
	return true
}
