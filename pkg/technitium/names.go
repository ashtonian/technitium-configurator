package technitium

import (
	"net/netip"
	"strings"

	"golang.org/x/net/idna"
)

// idnaProfile converts names the way the server's IdnMapping does: UTS 46
// mapping (case folding and NFC) before Punycode, so "BÜCHER" and a
// decomposed "bu\u0308cher" both become "xn--bcher-kva". STD3 rules are off
// because DNS names may hold "_" and "*" labels.
var idnaProfile = idna.New(idna.MapForLookup(), idna.Transitional(false), idna.StrictDomainName(false), idna.BidiRule())

// CanonicalName returns a DNS name the way the server stores and compares
// it: ASCII (IDNA), lower case, without the trailing dot. The root is "".
func CanonicalName(name string) string {
	n := strings.TrimSuffix(strings.TrimSpace(name), ".")
	if n == "" {
		return ""
	}
	if ascii, err := idnaProfile.ToASCII(n); err == nil {
		n = ascii
	}
	return strings.ToLower(n)
}

// ParseIP parses an address as .NET's IPAddress.Parse does for the forms a
// config holds, including an IPv6 address in brackets.
func ParseIP(s string) (netip.Addr, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		s = s[1 : len(s)-1]
	}
	return netip.ParseAddr(s)
}

// SameName reports whether a and b name the same DNS node.
func SameName(a, b string) bool {
	return CanonicalName(a) == CanonicalName(b)
}

// ZoneKey identifies a zone: its canonical name, or "." for the root zone,
// which a config writes as "." and the server lists as "". Validation
// rejects a blank zone name before it gets here.
func ZoneKey(name string) string {
	if c := CanonicalName(name); c != "" {
		return c
	}
	return "."
}

// ZoneName is a zone name for the API and for configs: "." for the root.
func ZoneName(name string) string {
	if CanonicalName(name) == "" {
		return "."
	}
	return name
}

// InZone reports whether name is zone or a name below it. name is
// canonical (see CanonicalName) and zone a ZoneKey or canonical name.
func InZone(name, zone string) bool {
	return name == zone || zone == "" || zone == "." || strings.HasSuffix(name, "."+zone)
}

// zoneDepth orders zones from the closest to the furthest: longer names
// first and the root last.
func zoneDepth(zone string) int {
	if zone == "." {
		return 0
	}
	return len(zone)
}

// ReverseName returns the PTR owner name for an IP address, for example
// 4.3.2.1.in-addr.arpa for 1.2.3.4.
func ReverseName(addr netip.Addr) string {
	addr = addr.Unmap()
	if addr.Is4() {
		b := addr.As4()
		return itoa(b[3]) + "." + itoa(b[2]) + "." + itoa(b[1]) + "." + itoa(b[0]) + ".in-addr.arpa"
	}
	const hex = "0123456789abcdef"
	b := addr.As16()
	var sb strings.Builder
	for i := len(b) - 1; i >= 0; i-- {
		sb.WriteByte(hex[b[i]&0x0f])
		sb.WriteByte('.')
		sb.WriteByte(hex[b[i]>>4])
		sb.WriteByte('.')
	}
	sb.WriteString("ip6.arpa")
	return sb.String()
}

func itoa(b byte) string {
	const digits = "0123456789"
	if b < 10 {
		return digits[b : b+1]
	}
	if b < 100 {
		return string([]byte{digits[b/10], digits[b%10]})
	}
	return string([]byte{digits[b/100], digits[(b/10)%10], digits[b%10]})
}
