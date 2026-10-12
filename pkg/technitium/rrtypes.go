package technitium

import (
	"strconv"
	"strings"
)

// recordTypeNames is the server's DnsResourceRecordType enum. The server
// parses a record type by name or number and reports it by this name, or by
// number when the enum has none.
var recordTypeNames = map[uint16]RecordType{
	1: "A", 2: "NS", 3: "MD", 4: "MF", 5: "CNAME", 6: "SOA", 7: "MB", 8: "MG", 9: "MR", 10: "NULL",
	11: "WKS", 12: "PTR", 13: "HINFO", 14: "MINFO", 15: "MX", 16: "TXT", 17: "RP", 18: "AFSDB", 19: "X25", 20: "ISDN",
	21: "RT", 22: "NSAP", 23: "NSAP_PTR", 24: "SIG", 25: "KEY", 26: "PX", 27: "GPOS", 28: "AAAA", 29: "LOC", 30: "NXT",
	31: "EID", 32: "NIMLOC", 33: "SRV", 34: "ATMA", 35: "NAPTR", 36: "KX", 37: "CERT", 38: "A6", 39: "DNAME", 40: "SINK",
	41: "OPT", 42: "APL", 43: "DS", 44: "SSHFP", 45: "IPSECKEY", 46: "RRSIG", 47: "NSEC", 48: "DNSKEY", 49: "DHCID", 50: "NSEC3",
	51: "NSEC3PARAM", 52: "TLSA", 53: "SMIMEA", 55: "HIP", 56: "NINFO", 57: "RKEY", 58: "TALINK", 59: "CDS", 60: "CDNSKEY",
	61: "OPENPGPKEY", 62: "CSYNC", 63: "ZONEMD", 64: "SVCB", 65: "HTTPS", 99: "SPF", 100: "UINFO", 101: "UID", 102: "GID",
	103: "UNSPEC", 104: "NID", 105: "L32", 106: "L64", 107: "LP", 108: "EUI48", 109: "EUI64", 128: "NXNAME",
	249: "TKEY", 250: "TSIG", 251: "IXFR", 252: "AXFR", 253: "MAILB", 254: "MAILA", 255: "ANY",
	256: "URI", 257: "CAA", 258: "AVC", 259: "DOA", 260: "AMTRELAY", 261: "RESINFO", 262: "WALLET", 263: "CLA", 264: "IPN",
	32768: "TA", 32769: "DLV",
	65280: "ANAME", 65281: "FWD", 65282: "APP", 65283: "CHILD_NS", 65284: "PARENT_NS", 65357: "ALIAS",
}

var recordTypeNumbers = func() map[RecordType]uint16 {
	m := make(map[RecordType]uint16, len(recordTypeNames))
	for n, name := range recordTypeNames {
		m[name] = n
	}
	return m
}()

// Canonical returns the type as the server reports it: its enum name in
// upper case, or "TYPE<n>" for a number without a name. "TYPE1", "1" and
// "a" are all "A". A value that is neither a name nor a number is returned
// in upper case, and Known reports false for it.
func (t RecordType) Canonical() RecordType {
	s := strings.ToUpper(strings.TrimSpace(string(t)))
	digits := strings.TrimPrefix(s, "TYPE")
	if n, err := strconv.ParseUint(digits, 10, 16); err == nil && digits != "" {
		if name, ok := recordTypeNames[uint16(n)]; ok {
			return name
		}
		return RecordType("TYPE" + strconv.FormatUint(n, 10))
	}
	return RecordType(s)
}

// Known reports whether the server can parse the type.
func (t RecordType) Known() bool {
	c := t.Canonical()
	if _, ok := recordTypeNumbers[c]; ok {
		return true
	}
	_, err := strconv.ParseUint(strings.TrimPrefix(string(c), "TYPE"), 10, 16)
	return strings.HasPrefix(string(c), "TYPE") && err == nil
}

// APIValue is the type parameter for /api/zones/records/add. The server
// parses names and plain numbers, not "TYPE<n>".
func (t RecordType) APIValue() string {
	c := t.Canonical()
	if _, named := recordTypeNumbers[c]; named || !c.Known() {
		return string(c)
	}
	return strings.TrimPrefix(string(c), "TYPE")
}
