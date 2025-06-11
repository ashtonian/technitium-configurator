package technitium

import (
	"context"
	"encoding/json"
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
	ProxyNone              ProxyType            = "NoProxy"
)

type ZoneCreateRequest struct {
	Zone                       string                `url:"zone" yaml:"zone"` // required
	Type                       ZoneType              `url:"type" yaml:"type"` // required
	Catalog                    *string               `url:"catalog,omitempty" yaml:"catalog,omitempty"`
	UseSoaSerialDateScheme     *bool                 `url:"useSoaSerialDateScheme,omitempty" yaml:"useSoaSerialDateScheme,omitempty"`
	PrimaryNameServerAddresses []string              `url:"primaryNameServerAddresses,comma,omitempty" yaml:"primaryNameServerAddresses,omitempty"`
	ZoneTransferProtocol       *ZoneTransferProtocol `url:"zoneTransferProtocol,omitempty" yaml:"zoneTransferProtocol,omitempty"`
	TsigKeyName                *string               `url:"tsigKeyName,omitempty" yaml:"tsigKeyName,omitempty"`
	ValidateZone               *bool                 `url:"validateZone,omitempty" yaml:"validateZone,omitempty"`
	InitializeForwarder        *bool                 `url:"initializeForwarder,omitempty" yaml:"initializeForwarder,omitempty"`
	Protocol                   *ForwarderProtocol    `url:"protocol,omitempty" yaml:"protocol,omitempty"`
	Forwarder                  *string               `url:"forwarder,omitempty" yaml:"forwarder,omitempty"`
	DnssecValidation           *bool                 `url:"dnssecValidation,omitempty" yaml:"dnssecValidation,omitempty"`
	ProxyType                  *ProxyType            `url:"proxyType,omitempty" yaml:"proxyType,omitempty"`
	ProxyAddress               *string               `url:"proxyAddress,omitempty" yaml:"proxyAddress,omitempty"`
	ProxyPort                  *int                  `url:"proxyPort,omitempty" yaml:"proxyPort,omitempty"`
	ProxyUsername              *string               `url:"proxyUsername,omitempty" yaml:"proxyUsername,omitempty"`
	ProxyPassword              *string               `url:"proxyPassword,omitempty" yaml:"proxyPassword,omitempty"`
}

func (c *Client) CreateZone(ctx context.Context, z ZoneCreateRequest) (string, error) {
	r, err := c.callPOSTForm(ctx, "/api/zones/create", z)
	if err != nil {
		return "", err
	}

	var payload struct {
		Domain string `json:"domain"`
	}
	if err = json.Unmarshal(r.Response, &payload); err != nil {
		return "", err
	}
	return payload.Domain, nil
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

// ACLSettings groups the repetitive ACL/Notify/Update knobs so it can be reused
// in the "set request" *and* in the JSON "get response".
type ACLSettings struct {
	QueryAccess                     *ZoneAccessOption   `url:"queryAccess,omitempty"            json:"queryAccess,omitempty"            yaml:"queryAccess,omitempty"`
	QueryAccessNetworkACL           []string            `url:"queryAccessNetworkACL,comma,omitempty"  json:"queryAccessNetworkACL,omitempty"  yaml:"queryAccessNetworkACL,omitempty"`
	ZoneTransfer                    *ZoneTransferOption `url:"zoneTransfer,omitempty"           json:"zoneTransfer,omitempty"           yaml:"zoneTransfer,omitempty"`
	ZoneTransferNetworkACL          []string            `url:"zoneTransferNetworkACL,comma,omitempty" json:"zoneTransferNetworkACL,omitempty" yaml:"zoneTransferNetworkACL,omitempty"`
	ZoneTransferTsigKeys            []string            `url:"zoneTransferTsigKeyNames,comma,omitempty" json:"zoneTransferTsigKeyNames,omitempty" yaml:"zoneTransferTsigKeyNames,omitempty"`
	Notify                          *NotifyOption       `url:"notify,omitempty"                        json:"notify,omitempty"                        yaml:"notify,omitempty"`
	NotifyNameServers               []string            `url:"notifyNameServers,comma,omitempty"       json:"notifyNameServers,omitempty"       yaml:"notifyNameServers,omitempty"`
	NotifySecondaryCatalogNameSrvrs []string            `url:"notifySecondaryCatalogsNameServers,comma,omitempty" json:"notifySecondaryCatalogsNameServers,omitempty" yaml:"notifySecondaryCatalogsNameServers,omitempty"`
	Update                          *UpdateOption       `url:"update,omitempty"              json:"update,omitempty"              yaml:"update,omitempty"`
	UpdateNetworkACL                []string            `url:"updateNetworkACL,comma,omitempty"  json:"updateNetworkACL,omitempty"  yaml:"updateNetworkACL,omitempty"`
	UpdateSecPolicies               *string             `url:"updateSecurityPolicies,omitempty" json:"updateSecurityPolicies,omitempty" yaml:"updateSecurityPolicies,omitempty"`
}

type ZoneOptionsUpdate struct {
	Zone                       string                `url:"zone"` // required
	Disabled                   *bool                 `url:"disabled,omitempty"`
	Catalog                    *string               `url:"catalog,omitempty"`
	OverrideCatalogQueryAccess *bool                 `url:"overrideCatalogQueryAccess,omitempty"`
	OverrideCatalogZoneXfr     *bool                 `url:"overrideCatalogZoneTransfer,omitempty"`
	OverrideCatalogNotify      *bool                 `url:"overrideCatalogNotify,omitempty"`
	PrimaryNameServerAddresses []string              `url:"primaryNameServerAddresses,comma,omitempty"`
	PrimaryXfrProto            *ZoneTransferProtocol `url:"primaryZoneTransferProtocol,omitempty"`
	PrimaryXfrTsigKey          *string               `url:"primaryZoneTransferTsigKeyName,omitempty"`
	ValidateZone               *bool                 `url:"validateZone,omitempty"`
	ACLSettings
}

type ZoneOptionsFetch struct {
	Zone                         string `url:"zone"` // required
	IncludeAvailableCatalogZones bool   `url:"includeAvailableCatalogZoneNames,omitempty"`
	IncludeAvailableTsigKeyNames bool   `url:"includeAvailableTsigKeyNames,omitempty"`
}

type UpdateSecurityPolicy struct {
	TsigKeyName  string   `json:"tsigKeyName"`
	Domain       string   `json:"domain"`
	AllowedTypes []string `json:"allowedTypes"`
}

type ZoneOptions struct {
	Name                      string   `json:"name"`
	Type                      ZoneType `json:"type"`
	Internal                  bool     `json:"internal"`
	DnssecStatus              string   `json:"dnssecStatus"`
	NotifyFailed              bool     `json:"notifyFailed"`
	NotifyFailedFor           []string `json:"notifyFailedFor"`
	Disabled                  bool     `json:"disabled"`
	Catalog                   string   `json:"catalog,omitempty"`
	ACLSettings               `json:",inline"`
	AvailableCatalogZoneNames []string `json:"availableCatalogZoneNames,omitempty"`
	AvailableTsigKeyNames     []string `json:"availableTsigKeyNames,omitempty"`
	UpdateSecurityPolicies    string   `json:"updateSecurityPolicies,omitempty"`
}

func (c *Client) GetZoneOptions(ctx context.Context, z ZoneOptionsFetch) (*ZoneOptions, error) {
	r, err := c.callGET(ctx, "/api/zones/options/get", z)
	if err != nil {
		return nil, err
	}

	var resp ZoneOptions
	if err = json.Unmarshal(r.Response, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) SetZoneOptions(ctx context.Context, z ZoneOptionsUpdate) (*ZoneOptions, error) {
	r, err := c.callPOSTForm(ctx, "/api/zones/options/set", z)
	if err != nil {
		return nil, err
	}

	var resp ZoneOptions
	if err = json.Unmarshal(r.Response, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}
