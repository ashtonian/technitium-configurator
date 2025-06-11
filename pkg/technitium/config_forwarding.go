package technitium

import "gopkg.in/yaml.v3"

type ForwardingConfig struct {
	AppPreference    uint8             `yaml:"appPreference,omitempty"     json:"appPreference,omitempty"`
	EnableForwarding *bool             `yaml:"enableForwarding"           json:"enableForwarding"`
	ProxyServers     []ProxyServer     `yaml:"proxyServers"               json:"proxyServers"`
	Forwarders       []Forwarder       `yaml:"forwarders"                 json:"forwarders"`
	NetworkGroupMap  map[string]string `yaml:"networkGroupMap"            json:"networkGroupMap"`
	Groups           []ForwardingGroup `yaml:"groups"                     json:"groups"`
}

func (c *ForwardingConfig) SetDefaults() {
	if c.EnableForwarding == nil {
		c.EnableForwarding = new(bool)
		*c.EnableForwarding = true // Default to enabled
	}
	if c.ProxyServers == nil {
		c.ProxyServers = []ProxyServer{}
	}
	if c.Forwarders == nil {
		c.Forwarders = []Forwarder{}
	}
	if c.NetworkGroupMap == nil {
		c.NetworkGroupMap = make(map[string]string)
	}
	if c.Groups == nil {
		c.Groups = []ForwardingGroup{}
	}
}

type ProxyServer struct {
	Name          string `yaml:"name,omitempty"          json:"name,omitempty"`
	Type          string `yaml:"type,omitempty"          json:"type,omitempty"`
	ProxyAddress  string `yaml:"proxyAddress,omitempty"  json:"proxyAddress,omitempty"`
	ProxyPort     uint16 `yaml:"proxyPort,omitempty"     json:"proxyPort,omitempty"`
	ProxyUsername string `yaml:"proxyUsername,omitempty" json:"proxyUsername,omitempty"`
	ProxyPassword string `yaml:"proxyPassword,omitempty" json:"proxyPassword,omitempty"`
}

type Forwarder struct {
	Name               string   `yaml:"name,omitempty"               json:"name,omitempty"`
	Proxy              string   `yaml:"proxy,omitempty"              json:"proxy,omitempty"`
	DNSSECValidation   *bool    `yaml:"dnssecValidation,omitempty"   json:"dnssecValidation,omitempty"`
	ForwarderProtocol  string   `yaml:"forwarderProtocol,omitempty"  json:"forwarderProtocol,omitempty"`
	ForwarderAddresses []string `yaml:"forwarderAddresses,omitempty" json:"forwarderAddresses,omitempty"`
}

func (f *Forwarder) SetDefaults() {
	if f.ForwarderAddresses == nil {
		f.ForwarderAddresses = []string{}
	}
	if f.DNSSECValidation == nil {
		f.DNSSECValidation = new(bool)
		*f.DNSSECValidation = false
	}
}

type ForwardingGroup struct {
	Name             string            `yaml:"name"             json:"name"`
	EnableForwarding *bool             `yaml:"enableForwarding" json:"enableForwarding"`
	Forwardings      []Forwarding      `yaml:"forwardings"      json:"forwardings"`
	AdguardUpstreams []AdguardUpstream `yaml:"adguardUpstreams" json:"adguardUpstreams"`
}

func (g *ForwardingGroup) SetDefaults() {
	if g.EnableForwarding == nil {
		g.EnableForwarding = new(bool)
		*g.EnableForwarding = true // Default to enabled
	}
	if g.Forwardings == nil {
		g.Forwardings = []Forwarding{}
	}
	if g.AdguardUpstreams == nil {
		g.AdguardUpstreams = []AdguardUpstream{}
	}
}

type Forwarding struct {
	Forwarders []string `yaml:"forwarders"  json:"forwarders"`
	Domains    []string `yaml:"domains"     json:"domains"`
}

func (f *Forwarding) SetDefaults() {
	if f.Forwarders == nil {
		f.Forwarders = []string{}
	}
	if f.Domains == nil {
		f.Domains = []string{}
	}
}

type AdguardUpstream struct {
	Proxy            string `yaml:"proxy,omitempty"            json:"proxy,omitempty"`
	DNSSECValidation *bool  `yaml:"dnssecValidation,omitempty" json:"dnssecValidation,omitempty"`
	ConfigFile       string `yaml:"configFile,omitempty"       json:"configFile,omitempty"`
}

func (a *AdguardUpstream) SetDefaults() {
	if a.DNSSECValidation == nil {
		a.DNSSECValidation = new(bool)
		*a.DNSSECValidation = false // Default to disabled
	}
}

func (c *ForwardingConfig) UnmarshalYAML(node *yaml.Node) error {
	type raw ForwardingConfig
	var tmp raw
	if err := node.Decode(&tmp); err != nil {
		return err
	}
	*c = ForwardingConfig(tmp)
	c.SetDefaults()
	return nil
}

func (f *Forwarder) UnmarshalYAML(node *yaml.Node) error {
	type raw Forwarder
	var tmp raw
	if err := node.Decode(&tmp); err != nil {
		return err
	}
	*f = Forwarder(tmp)
	f.SetDefaults()
	return nil
}

func (g *ForwardingGroup) UnmarshalYAML(node *yaml.Node) error {
	type raw ForwardingGroup
	var tmp raw
	if err := node.Decode(&tmp); err != nil {
		return err
	}
	*g = ForwardingGroup(tmp)
	g.SetDefaults()

	// Propagate defaults to nested elements.
	for i := range g.Forwardings {
		g.Forwardings[i].SetDefaults()
	}
	for i := range g.AdguardUpstreams {
		g.AdguardUpstreams[i].SetDefaults()
	}
	return nil
}

func (f *Forwarding) UnmarshalYAML(node *yaml.Node) error {
	type raw Forwarding
	var tmp raw
	if err := node.Decode(&tmp); err != nil {
		return err
	}
	*f = Forwarding(tmp)
	f.SetDefaults()
	return nil
}

func (a *AdguardUpstream) UnmarshalYAML(node *yaml.Node) error {
	type raw AdguardUpstream
	var tmp raw
	if err := node.Decode(&tmp); err != nil {
		return err
	}
	*a = AdguardUpstream(tmp)
	a.SetDefaults()
	return nil
}
