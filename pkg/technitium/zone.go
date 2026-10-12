package technitium

import (
	"context"
	"fmt"
	"net/url"
)

type (
	ZoneType             string
	ZoneTransferProtocol string
)

const (
	ZonePrimary            ZoneType             = "Primary"
	ZoneSecondary          ZoneType             = "Secondary"
	ZoneStub               ZoneType             = "Stub"
	ZoneForwarder          ZoneType             = "Forwarder"
	ZoneSecondaryForwarder ZoneType             = "SecondaryForwarder"
	ZoneCatalog            ZoneType             = "Catalog"
	ZoneSecondaryCatalog   ZoneType             = "SecondaryCatalog"
	ZTPTcp                 ZoneTransferProtocol = "Tcp"
	ZTPTls                 ZoneTransferProtocol = "Tls"
	ZTPQuic                ZoneTransferProtocol = "Quic"
)

type ZoneCreateRequest struct {
	Zone                       string                `json:"zone" yaml:"zone"` // required
	Type                       ZoneType              `json:"type" yaml:"type"` // required
	Catalog                    *string               `json:"catalog,omitempty" yaml:"catalog,omitempty"`
	UseSoaSerialDateScheme     *bool                 `json:"useSoaSerialDateScheme,omitempty" yaml:"useSoaSerialDateScheme,omitempty"`
	PrimaryNameServerAddresses []string              `json:"primaryNameServerAddresses,omitempty" yaml:"primaryNameServerAddresses,omitempty"`
	ZoneTransferProtocol       *ZoneTransferProtocol `json:"zoneTransferProtocol,omitempty" yaml:"zoneTransferProtocol,omitempty"`
	TsigKeyName                *string               `json:"tsigKeyName,omitempty" yaml:"tsigKeyName,omitempty"`
	ValidateZone               *bool                 `json:"validateZone,omitempty" yaml:"validateZone,omitempty"`
	InitializeForwarder        *bool                 `json:"initializeForwarder,omitempty" yaml:"initializeForwarder,omitempty"`
	Protocol                   *ForwarderProtocol    `json:"protocol,omitempty" yaml:"protocol,omitempty"`
	Forwarder                  *string               `json:"forwarder,omitempty" yaml:"forwarder,omitempty"`
	DnssecValidation           *bool                 `json:"dnssecValidation,omitempty" yaml:"dnssecValidation,omitempty"`
	ProxyType                  *ProxyType            `json:"proxyType,omitempty" yaml:"proxyType,omitempty"`
	ProxyAddress               *string               `json:"proxyAddress,omitempty" yaml:"proxyAddress,omitempty"`
	ProxyPort                  *int                  `json:"proxyPort,omitempty" yaml:"proxyPort,omitempty"`
	ProxyUsername              *string               `json:"proxyUsername,omitempty" yaml:"proxyUsername,omitempty"`
	ProxyPassword              *string               `json:"proxyPassword,omitempty" yaml:"proxyPassword,omitempty"`
}

// CatalogMemberTypes are the zone types that can belong to a catalog zone.
var CatalogMemberTypes = map[ZoneType]bool{
	ZonePrimary:   true,
	ZoneSecondary: true,
	ZoneStub:      true,
	ZoneForwarder: true,
}

// ListZones returns every zone on the server.
func (c *Client) ListZones(ctx context.Context) ([]ZoneSummary, error) {
	const path = "/api/zones/list"
	raw, err := c.get(ctx, path, nil)
	if err != nil {
		return nil, fmt.Errorf("list zones: %w", err)
	}
	resp, err := decodeResponse[struct {
		Zones []ZoneSummary `json:"zones"`
	}](path, raw)
	if err != nil {
		return nil, err
	}
	return resp.Zones, nil
}

func (c *Client) CreateZone(ctx context.Context, z ZoneCreateRequest) error {
	form, err := jsonToFormValues(z)
	if err != nil {
		return fmt.Errorf("create zone %q: %w", z.Zone, err)
	}
	if _, err := c.postForm(ctx, "/api/zones/create", form); err != nil {
		return fmt.Errorf("create zone %q: %w", z.Zone, err)
	}
	return nil
}

type ZoneAccessOption string
type ZoneTransferOption string
type NotifyOption string
type UpdateOption string

const (
	AccessDeny                                   ZoneAccessOption   = "Deny"
	AccessAllow                                  ZoneAccessOption   = "Allow"
	AccessAllowOnlyPrivateNetworks               ZoneAccessOption   = "AllowOnlyPrivateNetworks"
	AccessAllowOnlyZoneNameServers               ZoneAccessOption   = "AllowOnlyZoneNameServers"
	AccessUseSpecifiedNetworkACL                 ZoneAccessOption   = "UseSpecifiedNetworkACL"
	AccessAllowZoneNameServersAndSpecified       ZoneAccessOption   = "AllowZoneNameServersAndUseSpecifiedNetworkACL"
	XfrDeny                                      ZoneTransferOption = "Deny"
	XfrAllow                                     ZoneTransferOption = "Allow"
	XfrAllowOnlyZoneNameServers                  ZoneTransferOption = "AllowOnlyZoneNameServers"
	XfrUseSpecifiedNetworkACL                    ZoneTransferOption = "UseSpecifiedNetworkACL"
	XfrAllowZoneNameServersAndSpecified          ZoneTransferOption = "AllowZoneNameServersAndUseSpecifiedNetworkACL"
	NotifyNone                                   NotifyOption       = "None"
	NotifyZoneNameServers                        NotifyOption       = "ZoneNameServers"
	NotifySpecifiedNameServers                   NotifyOption       = "SpecifiedNameServers"
	NotifyBothZoneAndSpecifiedNameServers        NotifyOption       = "BothZoneAndSpecifiedNameServers"
	NotifySeparateNameServersForCatalogAndMember NotifyOption       = "SeparateNameServersForCatalogAndMemberZones"
	UpdateDeny                                   UpdateOption       = "Deny"
	UpdateAllow                                  UpdateOption       = "Allow"
	UpdateAllowOnlyZoneNameServers               UpdateOption       = "AllowOnlyZoneNameServers"
	UpdateUseSpecifiedNetworkACL                 UpdateOption       = "UseSpecifiedNetworkACL"
	UpdateAllowZoneNameServersAndSpecified       UpdateOption       = "AllowZoneNameServersAndUseSpecifiedNetworkACL"
)

// ACLSettings are a zone's access, notify and update options. A list left
// out is not sent; an explicit empty list is sent and clears the option.
type ACLSettings struct {
	QueryAccess                     *ZoneAccessOption   `json:"queryAccess,omitempty" yaml:"queryAccess,omitempty"`
	QueryAccessNetworkACL           []string            `json:"queryAccessNetworkACL" yaml:"queryAccessNetworkACL,omitempty"`
	ZoneTransfer                    *ZoneTransferOption `json:"zoneTransfer,omitempty" yaml:"zoneTransfer,omitempty"`
	ZoneTransferNetworkACL          []string            `json:"zoneTransferNetworkACL" yaml:"zoneTransferNetworkACL,omitempty"`
	ZoneTransferTsigKeys            []string            `json:"zoneTransferTsigKeyNames" yaml:"zoneTransferTsigKeyNames,omitempty"`
	Notify                          *NotifyOption       `json:"notify,omitempty" yaml:"notify,omitempty"`
	NotifyNameServers               []string            `json:"notifyNameServers" yaml:"notifyNameServers,omitempty"`
	NotifySecondaryCatalogNameSrvrs []string            `json:"notifySecondaryCatalogsNameServers" yaml:"notifySecondaryCatalogsNameServers,omitempty"`
	Update                          *UpdateOption       `json:"update,omitempty" yaml:"update,omitempty"`
	UpdateNetworkACL                []string            `json:"updateNetworkACL" yaml:"updateNetworkACL,omitempty"`
	UpdateSecPolicies               *string             `json:"updateSecurityPolicies,omitempty" yaml:"updateSecurityPolicies,omitempty"`
}

type ZoneOptionsUpdate struct {
	Zone                       string                `json:"zone"` // required
	Disabled                   *bool                 `json:"disabled,omitempty"`
	Catalog                    *string               `json:"catalog,omitempty"`
	OverrideCatalogQueryAccess *bool                 `json:"overrideCatalogQueryAccess,omitempty"`
	OverrideCatalogZoneXfr     *bool                 `json:"overrideCatalogZoneTransfer,omitempty"`
	OverrideCatalogNotify      *bool                 `json:"overrideCatalogNotify,omitempty"`
	PrimaryNameServerAddresses []string              `json:"primaryNameServerAddresses"`
	PrimaryXfrProto            *ZoneTransferProtocol `json:"primaryZoneTransferProtocol,omitempty"`
	PrimaryXfrTsigKey          *string               `json:"primaryZoneTransferTsigKeyName,omitempty"`
	ValidateZone               *bool                 `json:"validateZone,omitempty"`
	ACLSettings
}

// UpdateSecurityPolicy is one entry of a zone's dynamic update policy as
// returned by /api/zones/options/get.
type UpdateSecurityPolicy struct {
	TsigKeyName  string   `json:"tsigKeyName"`
	Domain       string   `json:"domain"`
	AllowedTypes []string `json:"allowedTypes"`
}

// ZoneOptions is the /api/zones/options/get response. Its policy list is a
// structured array, unlike the pipe-separated form the setter takes.
type ZoneOptions struct {
	Name                               string                 `json:"name"`
	Type                               ZoneType               `json:"type"`
	Internal                           bool                   `json:"internal"`
	DnssecStatus                       string                 `json:"dnssecStatus"`
	Disabled                           bool                   `json:"disabled"`
	Catalog                            string                 `json:"catalog"`
	IsSecondaryCatalogMember           bool                   `json:"isSecondaryCatalogMember"`
	PrimaryNameServerAddresses         []string               `json:"primaryNameServerAddresses"`
	PrimaryZoneTransferProtocol        string                 `json:"primaryZoneTransferProtocol"`
	PrimaryZoneTransferTsigKeyName     string                 `json:"primaryZoneTransferTsigKeyName"`
	ValidateZone                       bool                   `json:"validateZone"`
	NotifySecondaryCatalogsNameServers []string               `json:"notifySecondaryCatalogsNameServers"`
	OverrideCatalogQueryAccess         bool                   `json:"overrideCatalogQueryAccess"`
	OverrideCatalogZoneTransfer        bool                   `json:"overrideCatalogZoneTransfer"`
	OverrideCatalogNotify              bool                   `json:"overrideCatalogNotify"`
	QueryAccess                        string                 `json:"queryAccess"`
	QueryAccessNetworkACL              []string               `json:"queryAccessNetworkACL"`
	ZoneTransfer                       string                 `json:"zoneTransfer"`
	ZoneTransferNetworkACL             []string               `json:"zoneTransferNetworkACL"`
	ZoneTransferTsigKeyNames           []string               `json:"zoneTransferTsigKeyNames"`
	Notify                             string                 `json:"notify"`
	NotifyNameServers                  []string               `json:"notifyNameServers"`
	Update                             string                 `json:"update"`
	UpdateNetworkACL                   []string               `json:"updateNetworkACL"`
	UpdateSecurityPolicies             []UpdateSecurityPolicy `json:"updateSecurityPolicies"`
}

func (c *Client) GetZoneOptions(ctx context.Context, zone string) (*ZoneOptions, error) {
	const path = "/api/zones/options/get"
	raw, err := c.get(ctx, path, url.Values{"zone": {zone}})
	if err != nil {
		return nil, fmt.Errorf("get zone options %q: %w", zone, err)
	}
	return decodeResponse[ZoneOptions](path, raw)
}

func (c *Client) SetZoneOptions(ctx context.Context, z ZoneOptionsUpdate) error {
	form, err := jsonToFormValues(z)
	if err != nil {
		return fmt.Errorf("set zone options %q: %w", z.Zone, err)
	}
	if _, err := c.postForm(ctx, "/api/zones/options/set", form); err != nil {
		return fmt.Errorf("set zone options %q: %w", z.Zone, err)
	}
	return nil
}
