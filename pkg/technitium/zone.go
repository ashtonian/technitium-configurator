package technitium

import (
	"context"
	"fmt"
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

func (c *Client) CreateZone(ctx context.Context, z ZoneCreateRequest) (string, error) {
	r, err := c.callPOSTForm(ctx, "/api/zones/create", z)
	if err != nil {
		return "", fmt.Errorf("create zone %q: %w", z.Zone, err)
	}

	type domainResp struct {
		Domain string `json:"domain"`
	}
	payload, err := unmarshalResp[domainResp](r)
	if err != nil {
		return "", fmt.Errorf("create zone %q: %w", z.Zone, err)
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
	QueryAccess                     *ZoneAccessOption   `json:"queryAccess,omitempty" yaml:"queryAccess,omitempty"`
	QueryAccessNetworkACL           []string            `json:"queryAccessNetworkACL,omitempty" yaml:"queryAccessNetworkACL,omitempty"`
	ZoneTransfer                    *ZoneTransferOption `json:"zoneTransfer,omitempty" yaml:"zoneTransfer,omitempty"`
	ZoneTransferNetworkACL          []string            `json:"zoneTransferNetworkACL,omitempty" yaml:"zoneTransferNetworkACL,omitempty"`
	ZoneTransferTsigKeys            []string            `json:"zoneTransferTsigKeyNames,omitempty" yaml:"zoneTransferTsigKeyNames,omitempty"`
	Notify                          *NotifyOption       `json:"notify,omitempty" yaml:"notify,omitempty"`
	NotifyNameServers               []string            `json:"notifyNameServers,omitempty" yaml:"notifyNameServers,omitempty"`
	NotifySecondaryCatalogNameSrvrs []string            `json:"notifySecondaryCatalogsNameServers,omitempty" yaml:"notifySecondaryCatalogsNameServers,omitempty"`
	Update                          *UpdateOption       `json:"update,omitempty" yaml:"update,omitempty"`
	UpdateNetworkACL                []string            `json:"updateNetworkACL,omitempty" yaml:"updateNetworkACL,omitempty"`
	UpdateSecPolicies               *string             `json:"updateSecurityPolicies,omitempty" yaml:"updateSecurityPolicies,omitempty"`
}

type ZoneOptionsUpdate struct {
	Zone                       string                `json:"zone"` // required
	Disabled                   *bool                 `json:"disabled,omitempty"`
	Catalog                    *string               `json:"catalog,omitempty"`
	OverrideCatalogQueryAccess *bool                 `json:"overrideCatalogQueryAccess,omitempty"`
	OverrideCatalogZoneXfr     *bool                 `json:"overrideCatalogZoneTransfer,omitempty"`
	OverrideCatalogNotify      *bool                 `json:"overrideCatalogNotify,omitempty"`
	PrimaryNameServerAddresses []string              `json:"primaryNameServerAddresses,omitempty"`
	PrimaryXfrProto            *ZoneTransferProtocol `json:"primaryZoneTransferProtocol,omitempty"`
	PrimaryXfrTsigKey          *string               `json:"primaryZoneTransferTsigKeyName,omitempty"`
	ValidateZone               *bool                 `json:"validateZone,omitempty"`
	ACLSettings
}

type ZoneOptionsFetch struct {
	Zone                         string `url:"zone"` // required
	IncludeAvailableCatalogZones bool   `url:"includeAvailableCatalogZoneNames,omitempty"`
	IncludeAvailableTsigKeyNames bool   `url:"includeAvailableTsigKeyNames,omitempty"`
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
	return unmarshalResp[ZoneOptions](r)
}

func (c *Client) SetZoneOptions(ctx context.Context, z ZoneOptionsUpdate) (*ZoneOptions, error) {
	r, err := c.callPOSTForm(ctx, "/api/zones/options/set", z)
	if err != nil {
		return nil, err
	}
	return unmarshalResp[ZoneOptions](r)
}
