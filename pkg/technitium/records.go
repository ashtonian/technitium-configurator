package technitium

import (
	"context"
	"encoding/json"
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
	TTL       *int    `url:"ttl,omitempty" json:"ttl,omitempty" yaml:"ttl,omitempty"` // seconds
	Comments  *string `url:"comments,omitempty" json:"comments,omitempty" yaml:"comments,omitempty"`
	ExpiryTTL *int    `url:"expiryTtl,omitempty" json:"expiryTtl,omitempty" yaml:"expiryTtl,omitempty"` // seconds from last-modified
}

type AddRecordRequest struct {
	Domain     string     `url:"domain" json:"domain" yaml:"domain"`                         // (required)
	Type       RecordType `url:"type" json:"type" yaml:"type"`                               // (required)
	Zone       *string    `url:"zone,omitempty" json:"zone,omitempty" yaml:"zone,omitempty"` // optional authoritative zone
	RecordMeta            // TTL / comments / expiry
	Overwrite  *bool      `url:"overwrite,omitempty" json:"overwrite,omitempty" yaml:"overwrite,omitempty"`

	/* ---------- Generic to A / AAAA --------- */
	IPAddress       string `url:"ipAddress,omitempty" json:"ipAddress,omitempty" yaml:"ipAddress,omitempty"`
	Ptr             *bool  `url:"ptr,omitempty" json:"ptr,omitempty" yaml:"ptr,omitempty"`
	CreatePtrZone   *bool  `url:"createPtrZone,omitempty" json:"createPtrZone,omitempty" yaml:"createPtrZone,omitempty"`
	UpdateSvcbHints *bool  `url:"updateSvcbHints,omitempty" json:"updateSvcbHints,omitempty" yaml:"updateSvcbHints,omitempty"`

	/* ---------- NS ---------- */
	NameServer string `url:"nameServer,omitempty" json:"nameServer,omitempty" yaml:"nameServer,omitempty"`
	Glue       string `url:"glue,omitempty" json:"glue,omitempty" yaml:"glue,omitempty"`

	/* ---------- CNAME / PTR / DNAME / ANAME ---------- */
	CName   string `url:"cname,omitempty" json:"cname,omitempty" yaml:"cname,omitempty"`
	PtrName string `url:"ptrName,omitempty" json:"ptrName,omitempty" yaml:"ptrName,omitempty"`
	DName   string `url:"dname,omitempty" json:"dname,omitempty" yaml:"dname,omitempty"`
	AName   string `url:"aname,omitempty" json:"aname,omitempty" yaml:"aname,omitempty"`

	/* ---------- MX ---------- */
	Exchange   string `url:"exchange,omitempty" json:"exchange,omitempty" yaml:"exchange,omitempty"`
	Preference *int   `url:"preference,omitempty" json:"preference,omitempty" yaml:"preference,omitempty"`

	/* ---------- TXT / RP ---------- */
	Text      string `url:"text,omitempty" json:"text,omitempty" yaml:"text,omitempty"`
	SplitText *bool  `url:"splitText,omitempty" json:"splitText,omitempty" yaml:"splitText,omitempty"`
	Mailbox   string `url:"mailbox,omitempty" json:"mailbox,omitempty" yaml:"mailbox,omitempty"`
	TxtDomain string `url:"txtDomain,omitempty" json:"txtDomain,omitempty" yaml:"txtDomain,omitempty"`

	/* ---------- SRV ---------- */
	Priority *int   `url:"priority,omitempty" json:"priority,omitempty" yaml:"priority,omitempty"`
	Weight   *int   `url:"weight,omitempty" json:"weight,omitempty" yaml:"weight,omitempty"`
	Port     *int   `url:"port,omitempty" json:"port,omitempty" yaml:"port,omitempty"`
	Target   string `url:"target,omitempty" json:"target,omitempty" yaml:"target,omitempty"`

	/* ---------- NAPTR ---------- */
	NaptrOrder       *int   `url:"naptrOrder,omitempty" json:"naptrOrder,omitempty" yaml:"naptrOrder,omitempty"`
	NaptrPreference  *int   `url:"naptrPreference,omitempty" json:"naptrPreference,omitempty" yaml:"naptrPreference,omitempty"`
	NaptrFlags       string `url:"naptrFlags,omitempty" json:"naptrFlags,omitempty" yaml:"naptrFlags,omitempty"`
	NaptrServices    string `url:"naptrServices,omitempty" json:"naptrServices,omitempty" yaml:"naptrServices,omitempty"`
	NaptrRegexp      string `url:"naptrRegexp,omitempty" json:"naptrRegexp,omitempty" yaml:"naptrRegexp,omitempty"`
	NaptrReplacement string `url:"naptrReplacement,omitempty" json:"naptrReplacement,omitempty" yaml:"naptrReplacement,omitempty"`

	/* ---------- DS ---------- */
	KeyTag     *int         `url:"keyTag,omitempty" json:"keyTag,omitempty" yaml:"keyTag,omitempty"`
	Algorithm  DSAlgorithm  `url:"algorithm,omitempty" json:"algorithm,omitempty" yaml:"algorithm,omitempty"`
	DigestType DSDigestType `url:"digestType,omitempty" json:"digestType,omitempty" yaml:"digestType,omitempty"`
	Digest     string       `url:"digest,omitempty" json:"digest,omitempty" yaml:"digest,omitempty"`

	/* ---------- SSHFP ---------- */
	SSHFPAlgorithm       SSHFPAlgorithm       `url:"sshfpAlgorithm,omitempty" json:"sshfpAlgorithm,omitempty" yaml:"sshfpAlgorithm,omitempty"`
	SSHFPFingerprintType SSHFPFingerprintType `url:"sshfpFingerprintType,omitempty" json:"sshfpFingerprintType,omitempty" yaml:"sshfpFingerprintType,omitempty"`
	SSHFPFingerprint     string               `url:"sshfpFingerprint,omitempty" json:"sshfpFingerprint,omitempty" yaml:"sshfpFingerprint,omitempty"`

	/* ---------- TLSA ---------- */
	TLSACertificateUsage           TLSACertUsage `url:"tlsaCertificateUsage,omitempty" json:"tlsaCertificateUsage,omitempty" yaml:"tlsaCertificateUsage,omitempty"`
	TLSASelector                   TLSASelector  `url:"tlsaSelector,omitempty" json:"tlsaSelector,omitempty" yaml:"tlsaSelector,omitempty"`
	TLSAMatchingType               TLSAMatchType `url:"tlsaMatchingType,omitempty" json:"tlsaMatchingType,omitempty" yaml:"tlsaMatchingType,omitempty"`
	TLSACertificateAssociationData string        `url:"tlsaCertificateAssociationData,omitempty" json:"tlsaCertificateAssociationData,omitempty" yaml:"tlsaCertificateAssociationData,omitempty"`

	/* ---------- SVCB / HTTPS ---------- */
	SvcPriority   *int   `url:"svcPriority,omitempty" json:"svcPriority,omitempty" yaml:"svcPriority,omitempty"`
	SvcTargetName string `url:"svcTargetName,omitempty" json:"svcTargetName,omitempty" yaml:"svcTargetName,omitempty"`
	SvcParams     string `url:"svcParams,omitempty" json:"svcParams,omitempty" yaml:"svcParams,omitempty"` // pipe-separated
	AutoIpv4Hint  *bool  `url:"autoIpv4Hint,omitempty" json:"autoIpv4Hint,omitempty" yaml:"autoIpv4Hint,omitempty"`
	AutoIpv6Hint  *bool  `url:"autoIpv6Hint,omitempty" json:"autoIpv6Hint,omitempty" yaml:"autoIpv6Hint,omitempty"`

	/* ---------- URI ---------- */
	URIPriority *int   `url:"uriPriority,omitempty" json:"uriPriority,omitempty" yaml:"uriPriority,omitempty"`
	URIWeight   *int   `url:"uriWeight,omitempty" json:"uriWeight,omitempty" yaml:"uriWeight,omitempty"`
	URI         string `url:"uri,omitempty" json:"uri,omitempty" yaml:"uri,omitempty"`

	/* ---------- CAA ---------- */
	Flags *int   `url:"flags,omitempty" json:"flags,omitempty" yaml:"flags,omitempty"`
	Tag   string `url:"tag,omitempty" json:"tag,omitempty" yaml:"tag,omitempty"`
	Value string `url:"value,omitempty" json:"value,omitempty" yaml:"value,omitempty"`

	/* ---------- FWD (forwarder) ---------- */
	Protocol          ForwarderProtocol `url:"protocol,omitempty" json:"protocol,omitempty" yaml:"protocol,omitempty"`
	Forwarder         string            `url:"forwarder,omitempty" json:"forwarder,omitempty" yaml:"forwarder,omitempty"`
	ForwarderPriority *int              `url:"forwarderPriority,omitempty" json:"forwarderPriority,omitempty" yaml:"forwarderPriority,omitempty"`
	DnssecValidation  *bool             `url:"dnssecValidation,omitempty" json:"dnssecValidation,omitempty" yaml:"dnssecValidation,omitempty"`
	ProxyType         ProxyType         `url:"proxyType,omitempty" json:"proxyType,omitempty" yaml:"proxyType,omitempty"`
	ProxyAddress      string            `url:"proxyAddress,omitempty" json:"proxyAddress,omitempty" yaml:"proxyAddress,omitempty"`
	ProxyPort         *int              `url:"proxyPort,omitempty" json:"proxyPort,omitempty" yaml:"proxyPort,omitempty"`
	ProxyUsername     string            `url:"proxyUsername,omitempty" json:"proxyUsername,omitempty" yaml:"proxyUsername,omitempty"`
	ProxyPassword     string            `url:"proxyPassword,omitempty" json:"proxyPassword,omitempty" yaml:"proxyPassword,omitempty"`

	/* ---------- APP ---------- */
	AppName    string `url:"appName,omitempty" json:"appName,omitempty" yaml:"appName,omitempty"`
	ClassPath  string `url:"classPath,omitempty" json:"classPath,omitempty" yaml:"classPath,omitempty"`
	RecordData string `url:"recordData,omitempty" json:"recordData,omitempty" yaml:"recordData,omitempty"`

	/* ---------- Unknown / opaque ---------- */
	RData string `url:"rdata,omitempty" json:"rdata,omitempty" yaml:"rdata,omitempty"`
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
	r, err := c.callPOSTForm(ctx, "api/zones/records/add", req)
	if err != nil {
		return nil, err
	}

	var resp AddRecordResponse
	if err := json.Unmarshal(r.Response, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
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
