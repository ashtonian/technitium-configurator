package technitium

type ForwardingConfig struct {
	AppPreference    uint8             `yaml:"appPreference,omitempty"    json:"appPreference,omitempty"`
	EnableForwarding *bool             `yaml:"enableForwarding,omitempty" json:"enableForwarding,omitempty"`
	ProxyServers     []ProxyServer     `yaml:"proxyServers,omitempty"     json:"proxyServers,omitempty"`
	Forwarders       []Forwarder       `yaml:"forwarders,omitempty"       json:"forwarders,omitempty"`
	NetworkGroupMap  map[string]string `yaml:"networkGroupMap,omitempty"  json:"networkGroupMap,omitempty"`
	Groups           []ForwardingGroup `yaml:"groups,omitempty"           json:"groups,omitempty"`
}

type ProxyServer struct {
	Name          string `yaml:"name,omitempty"         json:"name,omitempty"`
	Type          string `yaml:"type,omitempty"         json:"type,omitempty"`
	ProxyAddress  string `yaml:"proxyAddress,omitempty" json:"proxyAddress,omitempty"`
	ProxyPort     uint16 `yaml:"proxyPort,omitempty"    json:"proxyPort,omitempty"`
	ProxyUsername string `yaml:"proxyUsername,omitempty"json:"proxyUsername,omitempty"`
	ProxyPassword string `yaml:"proxyPassword,omitempty"json:"proxyPassword,omitempty"`
}

type Forwarder struct {
	Name               string   `yaml:"name,omitempty"              json:"name,omitempty"`
	Proxy              string   `yaml:"proxy,omitempty"             json:"proxy,omitempty"`
	DNSSECValidation   *bool    `yaml:"dnssecValidation,omitempty"  json:"dnssecValidation,omitempty"`
	ForwarderProtocol  string   `yaml:"forwarderProtocol,omitempty" json:"forwarderProtocol,omitempty"`
	ForwarderAddresses []string `yaml:"forwarderAddresses,omitempty"json:"forwarderAddresses,omitempty"`
}

type ForwardingGroup struct {
	Name             string            `yaml:"name,omitempty"            json:"name,omitempty"`
	EnableForwarding *bool             `yaml:"enableForwarding,omitempty"json:"enableForwarding,omitempty"`
	Forwardings      []Forwarding      `yaml:"forwardings,omitempty"     json:"forwardings,omitempty"`
	AdguardUpstreams []AdguardUpstream `yaml:"adguardUpstreams,omitempty"json:"adguardUpstreams,omitempty"`
}

type Forwarding struct {
	Forwarders []string `yaml:"forwarders,omitempty" json:"forwarders,omitempty"`
	Domains    []string `yaml:"domains,omitempty"    json:"domains,omitempty"`
}

type AdguardUpstream struct {
	Proxy            string `yaml:"proxy,omitempty"           json:"proxy,omitempty"`
	DNSSECValidation *bool  `yaml:"dnssecValidation,omitempty"json:"dnssecValidation,omitempty"`
	ConfigFile       string `yaml:"configFile,omitempty"      json:"configFile,omitempty"`
}
