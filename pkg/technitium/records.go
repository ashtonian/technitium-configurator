package technitium

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type RecordType string
type DSAlgorithm string
type DSDigestType string
type SSHFPAlgorithm string
type SSHFPFingerprintType string
type TLSACertUsage string
type TLSASelector string
type TLSAMatchType string
type ForwarderProtocol string
type ProxyType string

const (
	RT_A                   RecordType           = "A"
	RT_AAAA                RecordType           = "AAAA"
	RT_NS                  RecordType           = "NS"
	RT_CNAME               RecordType           = "CNAME"
	RT_PTR                 RecordType           = "PTR"
	RT_MX                  RecordType           = "MX"
	RT_TXT                 RecordType           = "TXT"
	RT_SRV                 RecordType           = "SRV"
	RT_DNAME               RecordType           = "DNAME"
	RT_DS                  RecordType           = "DS"
	RT_SSHFP               RecordType           = "SSHFP"
	RT_TLSA                RecordType           = "TLSA"
	RT_SVCB                RecordType           = "SVCB"
	RT_HTTPS               RecordType           = "HTTPS"
	RT_URI                 RecordType           = "URI"
	RT_CAA                 RecordType           = "CAA"
	RT_ANAME               RecordType           = "ANAME"
	RT_NAPTR               RecordType           = "NAPTR"
	RT_RP                  RecordType           = "RP"
	RT_FWD                 RecordType           = "FWD"
	RT_APP                 RecordType           = "APP"
	DSAlgoRSAMD5           DSAlgorithm          = "RSAMD5"
	DSAlgoDSA              DSAlgorithm          = "DSA"
	DSAlgoRSASHA1          DSAlgorithm          = "RSASHA1"
	DSAlgoDSANSEC3SHA1     DSAlgorithm          = "DSA-NSEC3-SHA1"
	DSAlgoRSASHA1NSEC3SHA1 DSAlgorithm          = "RSASHA1-NSEC3-SHA1"
	DSAlgoRSASHA256        DSAlgorithm          = "RSASHA256"
	DSAlgoRSASHA512        DSAlgorithm          = "RSASHA512"
	DSAlgoECCGOST          DSAlgorithm          = "ECC-GOST"
	DSAlgoECDSAP256SHA256  DSAlgorithm          = "ECDSAP256SHA256"
	DSAlgoECDSAP384SHA384  DSAlgorithm          = "ECDSAP384SHA384"
	DSAlgoED25519          DSAlgorithm          = "ED25519"
	DSAlgoED448            DSAlgorithm          = "ED448"
	DSDigestSHA1           DSDigestType         = "SHA1"
	DSDigestSHA256         DSDigestType         = "SHA256"
	DSDigestGOSTR341194    DSDigestType         = "GOST-R-34-11-94"
	DSDigestSHA384         DSDigestType         = "SHA384"
	SSHFPAlgoRSA           SSHFPAlgorithm       = "RSA"
	SSHFPAlgoDSA           SSHFPAlgorithm       = "DSA"
	SSHFPAlgoECDSA         SSHFPAlgorithm       = "ECDSA"
	SSHFPAlgoEd25519       SSHFPAlgorithm       = "Ed25519"
	SSHFPAlgoEd448         SSHFPAlgorithm       = "Ed448"
	SSHFPFP_SHA1           SSHFPFingerprintType = "SHA1"
	SSHFPFP_SHA256         SSHFPFingerprintType = "SHA256"
	TLSAUsagePKIXTA        TLSACertUsage        = "PKIX-TA"
	TLSAUsagePKIXEE        TLSACertUsage        = "PKIX-EE"
	TLSAUsageDANETA        TLSACertUsage        = "DANE-TA"
	TLSAUsageDANEEE        TLSACertUsage        = "DANE-EE"
	TLSASelCert            TLSASelector         = "Cert"
	TLSASelSPKI            TLSASelector         = "SPKI"
	TLSAMatchFull          TLSAMatchType        = "Full"
	TLSAMatchSHA256        TLSAMatchType        = "SHA2-256"
	TLSAMatchSHA512        TLSAMatchType        = "SHA2-512"
	FwdUDP                 ForwarderProtocol    = "Udp"
	FwdTCP                 ForwarderProtocol    = "Tcp"
	FwdTLS                 ForwarderProtocol    = "Tls"
	FwdHTTPS               ForwarderProtocol    = "Https"
	FwdQuic                ForwarderProtocol    = "Quic"
	ProxyNoProxy           ProxyType            = "NoProxy"
	ProxyDefault           ProxyType            = "DefaultProxy"
	ProxyHTTP              ProxyType            = "Http"
	ProxySOCKS5            ProxyType            = "Socks5"
)

type RecordMeta struct {
	TTL       *int    `json:"ttl,omitempty" yaml:"ttl,omitempty"` // seconds
	Comments  *string `json:"comments,omitempty" yaml:"comments,omitempty"`
	ExpiryTTL *int    `json:"expiryTtl,omitempty" yaml:"expiryTtl,omitempty"` // seconds from last-modified
}

type AddRecordRequest struct {
	Domain     string     `json:"domain" yaml:"domain"`                         // (required)
	Type       RecordType `json:"type" yaml:"type"`                             // (required)
	Zone       *string    `json:"zone,omitempty" yaml:"zone,omitempty"`         // optional authoritative zone
	RecordMeta            // TTL / comments / expiry
	Overwrite  *bool      `json:"overwrite,omitempty" yaml:"overwrite,omitempty"`

	/* ---------- Generic to A / AAAA --------- */
	IPAddress       string `json:"ipAddress,omitempty" yaml:"ipAddress,omitempty"`
	Ptr             *bool  `json:"ptr,omitempty" yaml:"ptr,omitempty"`
	CreatePtrZone   *bool  `json:"createPtrZone,omitempty" yaml:"createPtrZone,omitempty"`
	UpdateSvcbHints *bool  `json:"updateSvcbHints,omitempty" yaml:"updateSvcbHints,omitempty"`

	/* ---------- NS ---------- */
	NameServer string `json:"nameServer,omitempty" yaml:"nameServer,omitempty"`
	Glue       string `json:"glue,omitempty" yaml:"glue,omitempty"`

	/* ---------- CNAME / PTR / DNAME / ANAME ---------- */
	CName   string `json:"cname,omitempty" yaml:"cname,omitempty"`
	PtrName string `json:"ptrName,omitempty" yaml:"ptrName,omitempty"`
	DName   string `json:"dname,omitempty" yaml:"dname,omitempty"`
	AName   string `json:"aname,omitempty" yaml:"aname,omitempty"`

	/* ---------- MX ---------- */
	Exchange   string `json:"exchange,omitempty" yaml:"exchange,omitempty"`
	Preference *int   `json:"preference,omitempty" yaml:"preference,omitempty"`

	/* ---------- TXT / RP ---------- */
	Text      string `json:"text,omitempty" yaml:"text,omitempty"`
	SplitText *bool  `json:"splitText,omitempty" yaml:"splitText,omitempty"`
	Mailbox   string `json:"mailbox,omitempty" yaml:"mailbox,omitempty"`
	TxtDomain string `json:"txtDomain,omitempty" yaml:"txtDomain,omitempty"`

	/* ---------- SRV ---------- */
	Priority *int   `json:"priority,omitempty" yaml:"priority,omitempty"`
	Weight   *int   `json:"weight,omitempty" yaml:"weight,omitempty"`
	Port     *int   `json:"port,omitempty" yaml:"port,omitempty"`
	Target   string `json:"target,omitempty" yaml:"target,omitempty"`

	/* ---------- NAPTR ---------- */
	NaptrOrder       *int   `json:"naptrOrder,omitempty" yaml:"naptrOrder,omitempty"`
	NaptrPreference  *int   `json:"naptrPreference,omitempty" yaml:"naptrPreference,omitempty"`
	NaptrFlags       string `json:"naptrFlags,omitempty" yaml:"naptrFlags,omitempty"`
	NaptrServices    string `json:"naptrServices,omitempty" yaml:"naptrServices,omitempty"`
	NaptrRegexp      string `json:"naptrRegexp,omitempty" yaml:"naptrRegexp,omitempty"`
	NaptrReplacement string `json:"naptrReplacement,omitempty" yaml:"naptrReplacement,omitempty"`

	/* ---------- DS ---------- */
	KeyTag     *int         `json:"keyTag,omitempty" yaml:"keyTag,omitempty"`
	Algorithm  DSAlgorithm  `json:"algorithm,omitempty" yaml:"algorithm,omitempty"`
	DigestType DSDigestType `json:"digestType,omitempty" yaml:"digestType,omitempty"`
	Digest     string       `json:"digest,omitempty" yaml:"digest,omitempty"`

	/* ---------- SSHFP ---------- */
	SSHFPAlgorithm       SSHFPAlgorithm       `json:"sshfpAlgorithm,omitempty" yaml:"sshfpAlgorithm,omitempty"`
	SSHFPFingerprintType SSHFPFingerprintType `json:"sshfpFingerprintType,omitempty" yaml:"sshfpFingerprintType,omitempty"`
	SSHFPFingerprint     string               `json:"sshfpFingerprint,omitempty" yaml:"sshfpFingerprint,omitempty"`

	/* ---------- TLSA ---------- */
	TLSACertificateUsage           TLSACertUsage `json:"tlsaCertificateUsage,omitempty" yaml:"tlsaCertificateUsage,omitempty"`
	TLSASelector                   TLSASelector  `json:"tlsaSelector,omitempty" yaml:"tlsaSelector,omitempty"`
	TLSAMatchingType               TLSAMatchType `json:"tlsaMatchingType,omitempty" yaml:"tlsaMatchingType,omitempty"`
	TLSACertificateAssociationData string        `json:"tlsaCertificateAssociationData,omitempty" yaml:"tlsaCertificateAssociationData,omitempty"`

	/* ---------- SVCB / HTTPS ---------- */
	SvcPriority   *int   `json:"svcPriority,omitempty" yaml:"svcPriority,omitempty"`
	SvcTargetName string `json:"svcTargetName,omitempty" yaml:"svcTargetName,omitempty"`
	SvcParams     string `json:"svcParams,omitempty" yaml:"svcParams,omitempty"` // pipe-separated
	AutoIpv4Hint  *bool  `json:"autoIpv4Hint,omitempty" yaml:"autoIpv4Hint,omitempty"`
	AutoIpv6Hint  *bool  `json:"autoIpv6Hint,omitempty" yaml:"autoIpv6Hint,omitempty"`

	/* ---------- URI ---------- */
	URIPriority *int   `json:"uriPriority,omitempty" yaml:"uriPriority,omitempty"`
	URIWeight   *int   `json:"uriWeight,omitempty" yaml:"uriWeight,omitempty"`
	URI         string `json:"uri,omitempty" yaml:"uri,omitempty"`

	/* ---------- CAA ---------- */
	Flags *int   `json:"flags,omitempty" yaml:"flags,omitempty"`
	Tag   string `json:"tag,omitempty" yaml:"tag,omitempty"`
	Value string `json:"value,omitempty" yaml:"value,omitempty"`

	/* ---------- FWD (forwarder) ---------- */
	Protocol          ForwarderProtocol `json:"protocol,omitempty" yaml:"protocol,omitempty"`
	Forwarder         string            `json:"forwarder,omitempty" yaml:"forwarder,omitempty"`
	ForwarderPriority *int              `json:"forwarderPriority,omitempty" yaml:"forwarderPriority,omitempty"`
	DnssecValidation  *bool             `json:"dnssecValidation,omitempty" yaml:"dnssecValidation,omitempty"`
	ProxyType         ProxyType         `json:"proxyType,omitempty" yaml:"proxyType,omitempty"`
	ProxyAddress      string            `json:"proxyAddress,omitempty" yaml:"proxyAddress,omitempty"`
	ProxyPort         *int              `json:"proxyPort,omitempty" yaml:"proxyPort,omitempty"`
	ProxyUsername     string            `json:"proxyUsername,omitempty" yaml:"proxyUsername,omitempty"`
	ProxyPassword     string            `json:"proxyPassword,omitempty" yaml:"proxyPassword,omitempty"`

	/* ---------- APP ---------- */
	AppName    string `json:"appName,omitempty" yaml:"appName,omitempty"`
	ClassPath  string `json:"classPath,omitempty" yaml:"classPath,omitempty"`
	RecordData string `json:"recordData,omitempty" yaml:"recordData,omitempty"`

	/* ---------- Unknown / opaque ---------- */
	RData string `json:"rdata,omitempty" yaml:"rdata,omitempty"`
}

// UnmarshalYAML supports "name" as an alias for "domain" and "value" as an
// alias for "ipAddress" (for A/AAAA records) so configs can use the more
// intuitive field names.
func (r *AddRecordRequest) UnmarshalYAML(node *yaml.Node) error {
	type raw AddRecordRequest
	var tmp raw
	if err := node.Decode(&tmp); err != nil {
		return err
	}
	*r = AddRecordRequest(tmp)

	// Decode again into a map to pick up alias fields
	var m map[string]interface{}
	if err := node.Decode(&m); err != nil {
		return err
	}

	if r.Domain == "" {
		if name, ok := m["name"].(string); ok {
			r.Domain = name
		}
	}
	if r.IPAddress == "" {
		if val, ok := m["value"].(string); ok && (r.Type == RT_A || r.Type == RT_AAAA) {
			r.IPAddress = val
		}
	}

	return nil
}

type ZoneSummary struct {
	Name         string   `json:"name" yaml:"name"`
	Type         ZoneType `json:"type" yaml:"type"`
	Internal     bool     `json:"internal" yaml:"internal"`
	DnssecStatus string   `json:"dnssecStatus" yaml:"dnssecStatus"`
	Disabled     bool     `json:"disabled" yaml:"disabled"`
}

type AddedRecord struct {
	Disabled     bool            `json:"disabled" yaml:"disabled"`
	Name         string          `json:"name" yaml:"name"`
	Type         RecordType      `json:"type" yaml:"type"`
	TTL          int             `json:"ttl" yaml:"ttl"`
	RData        json.RawMessage `json:"rData" yaml:"rData"`
	DnssecStatus string          `json:"dnssecStatus" yaml:"dnssecStatus"`
	LastUsedOn   FuzzyTime       `json:"lastUsedOn" yaml:"lastUsedOn"`
}

type AddRecordResponse struct {
	Zone        ZoneSummary `json:"zone" yaml:"zone"`
	AddedRecord AddedRecord `json:"addedRecord" yaml:"addedRecord"`
}

func (c *Client) AddRecord(ctx context.Context, req AddRecordRequest) (*AddRecordResponse, error) {
	r, err := c.callPOSTForm(ctx, "/api/zones/records/add", req)
	if err != nil {
		return nil, fmt.Errorf("add record %q (%s): %w", req.Domain, req.Type, err)
	}
	return unmarshalResp[AddRecordResponse](r)
}

const (
	rfc3339NoZone = "2006-01-02T15:04:05" // no "Z±hh:mm"
)

type FuzzyTime struct{ time.Time }

func (ft *FuzzyTime) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "0001-01-01T00:00:00" {
		// keep zero time
		return nil
	}
	layouts := []string{time.RFC3339, "2006-01-02T15:04:05"}
	var err error
	for _, l := range layouts {
		if t, e := time.Parse(l, s); e == nil {
			ft.Time = t
			return nil
		} else {
			err = e
		}
	}
	return err
}
