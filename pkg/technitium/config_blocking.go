package technitium

import (
	"encoding/json"
	"fmt"

	"gopkg.in/yaml.v3"
)

// BlockingConfig represents the full Advanced-Blocking app config.
type BlockingConfig struct {
	EnableBlocking                  bool              `yaml:"enableBlocking"           json:"enableBlocking"`
	BlockListUrlUpdateIntervalHours int               `yaml:"blockListUrlUpdateIntervalHours" json:"blockListUrlUpdateIntervalHours"`
	LocalEndPointGroupMap           map[string]string `yaml:"localEndPointGroupMap"    json:"localEndPointGroupMap"`
	NetworkGroupMap                 map[string]string `yaml:"networkGroupMap"          json:"networkGroupMap"`
	Groups                          []BlockingGroup   `yaml:"groups"                   json:"groups"`
}

// BlockingGroup represents a single blocking group section.
type BlockingGroup struct {
	Name                   string    `yaml:"name"                   json:"name"`
	EnableBlocking         bool      `yaml:"enableBlocking"         json:"enableBlocking"`
	AllowTxtBlockingReport bool      `yaml:"allowTxtBlockingReport" json:"allowTxtBlockingReport"`
	BlockAsNxDomain        bool      `yaml:"blockAsNxDomain"        json:"blockAsNxDomain"`
	BlockingAddresses      []string  `yaml:"blockingAddresses"      json:"blockingAddresses"`
	Allowed                []string  `yaml:"allowed" json:"allowed"`
	Blocked                []string  `yaml:"blocked"            json:"blocked"`
	AllowListUrls          []string  `yaml:"allowListUrls"      json:"allowListUrls"`
	BlockListUrls          []ListURL `yaml:"blockListUrls"      json:"blockListUrls"`
	AllowedRegex           []string  `yaml:"allowedRegex"       json:"allowedRegex"`
	BlockedRegex           []string  `yaml:"blockedRegex"       json:"blockedRegex"`
	RegexAllowListUrls     []string  `yaml:"regexAllowListUrls" json:"regexAllowListUrls"`
	RegexBlockListUrls     []ListURL `yaml:"regexBlockListUrls" json:"regexBlockListUrls"`
	AdblockListUrls        []ListURL `yaml:"adblockListUrls"    json:"adblockListUrls"`
}

// Raw object form (exact field names taken from Technitium source).
type listURLObj struct {
	URL               string   `yaml:"url,omitempty"               json:"url,omitempty"`
	BlockAsNxDomain   bool     `yaml:"blockAsNxDomain,omitempty"   json:"blockAsNxDomain,omitempty"`
	BlockingAddresses []string `yaml:"blockingAddresses,omitempty" json:"blockingAddresses,omitempty"`
}

// Every *ListUrls slice accepts **either**
//
//   - a bare string:         "- https://example.com/hosts"
//
//   - or a full object:
//
//   - url: https://example.com/hosts
//     blockAsNxDomain: true
//     blockingAddresses: [ "0.0.0.0", "::" ]
//
// When marshalled they collapse back to the short form whenever the extra
// fields are unused (mirroring the C# server’s own config files).
// ListURL is a wrapper that can hold either the short-hand (scalar string)
// or the long object form.  It satisfies json/yaml (un)marshal interfaces
// so callers can use it transparently.
type ListURL struct {
	listURLObj
}

func (l ListURL) decideObject() bool {
	return l.BlockAsNxDomain || len(l.BlockingAddresses) > 0
}

func (l *ListURL) UnmarshalJSON(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	switch data[0] {
	case '"': // scalar string
		return json.Unmarshal(data, &l.URL)
	default: // mapping
		return json.Unmarshal(data, &l.listURLObj)
	}
}

func (l ListURL) MarshalJSON() ([]byte, error) {
	if !l.decideObject() {
		return json.Marshal(l.URL)
	}
	return json.Marshal(l.listURLObj)
}

func (l *ListURL) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.ScalarNode: // plain string
		return value.Decode(&l.URL)
	case yaml.MappingNode: // object
		return value.Decode(&l.listURLObj)
	default:
		return fmt.Errorf("ListURL: unsupported YAML node kind %v", value.Kind)
	}
}

func (l ListURL) MarshalYAML() (interface{}, error) {
	if !l.decideObject() {
		return l.URL, nil
	}
	return l.listURLObj, nil
}
