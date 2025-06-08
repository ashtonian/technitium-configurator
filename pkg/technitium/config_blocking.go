package technitium

import (
	"encoding/json"
	"fmt"

	"gopkg.in/yaml.v3"
)

// BlockingConfig represents the full Advanced-Blocking app config.
type BlockingConfig struct {
	EnableBlocking                  bool              `yaml:"enableBlocking,omitempty"           json:"enableBlocking,omitempty"`
	BlockListUrlUpdateIntervalHours int               `yaml:"blockListUrlUpdateIntervalHours,omitempty" json:"blockListUrlUpdateIntervalHours,omitempty"`
	LocalEndPointGroupMap           map[string]string `yaml:"localEndPointGroupMap,omitempty"    json:"localEndPointGroupMap,omitempty"`
	NetworkGroupMap                 map[string]string `yaml:"networkGroupMap,omitempty"          json:"networkGroupMap,omitempty"`
	Groups                          []BlockingGroup   `yaml:"groups,omitempty"                   json:"groups,omitempty"`
}

// BlockingGroup represents a single blocking group section.
type BlockingGroup struct {
	Name                   string    `yaml:"name,omitempty"                   json:"name,omitempty"`
	EnableBlocking         bool      `yaml:"enableBlocking,omitempty"         json:"enableBlocking,omitempty"`
	AllowTxtBlockingReport bool      `yaml:"allowTxtBlockingReport,omitempty" json:"allowTxtBlockingReport,omitempty"`
	BlockAsNxDomain        bool      `yaml:"blockAsNxDomain,omitempty"        json:"blockAsNxDomain,omitempty"`
	BlockingAddresses      []string  `yaml:"blockingAddresses,omitempty"      json:"blockingAddresses,omitempty"`
	Allowed                []string  `yaml:"allowed,omitempty"            json:"allowed,omitempty"`
	Blocked                []string  `yaml:"blocked,omitempty"            json:"blocked,omitempty"`
	AllowListUrls          []string  `yaml:"allowListUrls,omitempty"      json:"allowListUrls,omitempty"`
	BlockListUrls          []ListURL `yaml:"blockListUrls,omitempty"      json:"blockListUrls,omitempty"`
	AllowedRegex           []string  `yaml:"allowedRegex,omitempty"       json:"allowedRegex,omitempty"`
	BlockedRegex           []string  `yaml:"blockedRegex,omitempty"       json:"blockedRegex,omitempty"`
	RegexAllowListUrls     []string  `yaml:"regexAllowListUrls,omitempty" json:"regexAllowListUrls,omitempty"`
	RegexBlockListUrls     []ListURL `yaml:"regexBlockListUrls,omitempty" json:"regexBlockListUrls,omitempty"`

	AdblockListUrls []ListURL `yaml:"adblockListUrls,omitempty"    json:"adblockListUrls,omitempty"`
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
