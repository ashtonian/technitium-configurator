package technitium

type ForwardingConfig struct {
	AppPreference    uint8             `yaml:"appPreference,omitempty"     json:"appPreference,omitempty"`
	EnableForwarding *bool             `yaml:"enableForwarding"           json:"enableForwarding"`
	ProxyServers     []ProxyServer     `yaml:"proxyServers"               json:"proxyServers"`
	Forwarders       []Forwarder       `yaml:"forwarders"                 json:"forwarders"`
	NetworkGroupMap  map[string]string `yaml:"networkGroupMap"            json:"networkGroupMap"`
	Groups           []ForwardingGroup `yaml:"groups"                     json:"groups"`
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

type ForwardingGroup struct {
	Name             string            `yaml:"name"             json:"name"`
	EnableForwarding *bool             `yaml:"enableForwarding" json:"enableForwarding"`
	Forwardings      []Forwarding      `yaml:"forwardings"      json:"forwardings"`
	AdguardUpstreams []AdguardUpstream `yaml:"adguardUpstreams" json:"adguardUpstreams"`
}

type Forwarding struct {
	Forwarders []string `yaml:"forwarders"  json:"forwarders"`
	Domains    []string `yaml:"domains"     json:"domains"`
}

type AdguardUpstream struct {
	Proxy            string `yaml:"proxy,omitempty"            json:"proxy,omitempty"`
	DNSSECValidation *bool  `yaml:"dnssecValidation,omitempty" json:"dnssecValidation,omitempty"`
	ConfigFile       string `yaml:"configFile,omitempty"       json:"configFile,omitempty"`
}
