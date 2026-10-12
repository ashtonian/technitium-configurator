package technitium

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config is the desired DNS server state read from one or more YAML files.
type Config struct {
	// RecordPolicy is the default for every record: "merge" (the default)
	// adds missing values and leaves others alone; "replace" makes the
	// declared values the only ones for each declared name and type.
	RecordPolicy   *string            `yaml:"recordPolicy,omitempty"`
	Cluster        *ClusterConfig     `yaml:"cluster,omitempty"`
	DNSSettings    *DnsSettings       `yaml:"dnsSettings,omitempty"`
	Administration *Administration    `yaml:"administration,omitempty"`
	Zones          []ZoneConfig       `yaml:"zones,omitempty"`
	Records        []AddRecordRequest `yaml:"records,omitempty"`
	Apps           []AppConfig        `yaml:"apps,omitempty"`

	origins origins
	// keyOrigins names the document that set recordPolicy, cluster and each
	// "dnsSettings.<key>"; each may be set in only one.
	keyOrigins map[string]string
}

// origins records the file and document each list entry came from, so a
// validation error names "b.yaml: zones[0]" rather than an index into the
// merged lists.
type origins map[string][]string

func (o origins) add(list, where string, n int) {
	for i := 0; i < n; i++ {
		o[list] = append(o[list], fmt.Sprintf("%s: %s[%d]", where, list, i))
	}
}

// at labels entry i of list. A Config built in code has no origins and
// gets the plain index.
func (o origins) at(list string, i int) string {
	if labels := o[list]; i < len(labels) {
		return labels[i]
	}
	return fmt.Sprintf("%s[%d]", list, i)
}

// Record policies.
const (
	PolicyMerge   = "merge"
	PolicyReplace = "replace"
)

// ZoneConfig declares a zone to create if absent and the options to apply to
// it on every run.
type ZoneConfig struct {
	ZoneCreateRequest `yaml:",inline"`
	ACLSettings       *ACLSettings `yaml:"aclSettings,omitempty"`
	// A catalog member zone follows the catalog's query access, zone transfer
	// and notify settings unless the matching override is true. On a cluster,
	// overriding zone transfer or notify replaces the policy that replicates
	// the zone, so the zone's own ACL must then admit the cluster nodes.
	OverrideCatalogQueryAccess  *bool `yaml:"overrideCatalogQueryAccess,omitempty"`
	OverrideCatalogZoneTransfer *bool `yaml:"overrideCatalogZoneTransfer,omitempty"`
	OverrideCatalogNotify       *bool `yaml:"overrideCatalogNotify,omitempty"`
	// RecordPolicy overrides the file's record policy for records in this zone.
	RecordPolicy *string `yaml:"recordPolicy,omitempty"`
	// Disabled stops the zone answering queries; applied every run when set.
	Disabled *bool `yaml:"disabled,omitempty"`
}

// ClusterConfig declares cluster initialisation (primary) or join (secondary).
type ClusterConfig struct {
	Mode             string `yaml:"mode"`                       // "primary" or "secondary"
	Domain           string `yaml:"domain,omitempty"`           // cluster domain name
	NodeIPs          string `yaml:"nodeIPs"`                    // this node's IP(s), comma-separated
	PrimaryURL       string `yaml:"primaryURL,omitempty"`       // primary node URL (secondary only)
	PrimaryIP        string `yaml:"primaryIP,omitempty"`        // primary node IP (secondary, optional)
	PrimaryUsername  string `yaml:"primaryUsername,omitempty"`  // primary node credentials (secondary only)
	PrimaryPassword  string `yaml:"primaryPassword,omitempty"`  // primary node credentials (secondary only)
	PrimaryTotp      string `yaml:"primaryTotp,omitempty"`      // TOTP for 2FA-enabled primaries (secondary only)
	IgnoreCertErrors bool   `yaml:"ignoreCertErrors,omitempty"` // ignore TLS cert errors (secondary, optional)
	// Cluster timing options (primary only)
	ConfigRefreshIntervalSecs    int `yaml:"configRefreshIntervalSeconds,omitempty"`
	ConfigRetryIntervalSecs      int `yaml:"configRetryIntervalSeconds,omitempty"`
	HeartbeatRefreshIntervalSecs int `yaml:"heartbeatRefreshIntervalSeconds,omitempty"`
	HeartbeatRetryIntervalSecs   int `yaml:"heartbeatRetryIntervalSeconds,omitempty"`
}

// Options returns the timing options to apply on the primary.
func (cc *ClusterConfig) Options() ClusterOptionsRequest {
	return ClusterOptionsRequest{
		HeartbeatRefreshIntervalSecs: cc.HeartbeatRefreshIntervalSecs,
		HeartbeatRetryIntervalSecs:   cc.HeartbeatRetryIntervalSecs,
		ConfigRefreshIntervalSecs:    cc.ConfigRefreshIntervalSecs,
		ConfigRetryIntervalSecs:      cc.ConfigRetryIntervalSecs,
	}
}

// NodeIPList returns the node IPs as a list.
func (cc *ClusterConfig) NodeIPList() []string {
	var ips []string
	for _, ip := range strings.Split(cc.NodeIPs, ",") {
		if ip = strings.TrimSpace(ip); ip != "" {
			ips = append(ips, ip)
		}
	}
	return ips
}

// Source is one YAML input; Name is used in error messages.
type Source struct {
	Name string
	Data []byte
}

// LoadConfigPaths reads the given files and directories (their *.yaml and
// *.yml files, in name order) and merges them like LoadConfig.
func LoadConfigPaths(paths []string) (*Config, error) {
	var sources []Source
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			return nil, fmt.Errorf("read DNS config: %w", err)
		}
		files := []string{p}
		if info.IsDir() {
			files = nil
			entries, err := os.ReadDir(p)
			if err != nil {
				return nil, fmt.Errorf("read DNS config directory: %w", err)
			}
			for _, e := range entries {
				ext := strings.ToLower(filepath.Ext(e.Name()))
				if !e.IsDir() && (ext == ".yaml" || ext == ".yml") {
					files = append(files, filepath.Join(p, e.Name()))
				}
			}
			sort.Strings(files)
			if len(files) == 0 {
				return nil, fmt.Errorf("DNS config directory %s has no .yaml or .yml files", p)
			}
		}
		for _, f := range files {
			data, err := os.ReadFile(f)
			if err != nil {
				return nil, fmt.Errorf("read DNS config: %w", err)
			}
			sources = append(sources, Source{Name: f, Data: data})
		}
	}
	return LoadConfig(sources...)
}

// LoadConfig parses, merges and validates YAML sources. A source may hold
// several documents separated by "---". Unknown keys are errors, so a
// misspelt or obsolete key fails before any API call.
//
// Merging: zones, records, apps and administration entries are combined;
// recordPolicy, cluster and each dnsSettings key may be set in only one
// document, so nothing is silently overridden.
func LoadConfig(sources ...Source) (*Config, error) {
	merged := &Config{origins: origins{}}
	origin := map[string]string{}
	merged.keyOrigins = origin
	documents := 0
	for _, src := range sources {
		dec := yaml.NewDecoder(bytes.NewReader(src.Data))
		dec.KnownFields(true)
		for n := 1; ; n++ {
			var doc Config
			err := dec.Decode(&doc)
			if errors.Is(err, io.EOF) {
				break
			}
			where := src.Name
			if n > 1 {
				where = fmt.Sprintf("%s (document %d)", src.Name, n)
			}
			if err != nil {
				return nil, fmt.Errorf("parse %s: %w", where, err)
			}
			documents++
			if err := merged.merge(&doc, where, origin); err != nil {
				return nil, err
			}
		}
	}
	if documents == 0 {
		return nil, errors.New("parse config: no YAML documents found")
	}
	if err := merged.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	return merged, nil
}

func (c *Config) merge(doc *Config, where string, origin map[string]string) error {
	claim := func(key string) error {
		if prev, ok := origin[key]; ok {
			return fmt.Errorf("%s is set in both %s and %s", key, prev, where)
		}
		origin[key] = where
		return nil
	}
	if doc.RecordPolicy != nil {
		if err := claim("recordPolicy"); err != nil {
			return err
		}
		c.RecordPolicy = doc.RecordPolicy
	}
	if doc.Cluster != nil {
		if err := claim("cluster"); err != nil {
			return err
		}
		c.Cluster = doc.Cluster
	}
	if doc.DNSSettings != nil {
		if c.DNSSettings == nil {
			c.DNSSettings = &DnsSettings{}
		}
		dst := reflect.ValueOf(c.DNSSettings).Elem()
		src := reflect.ValueOf(doc.DNSSettings).Elem()
		for i := 0; i < src.NumField(); i++ {
			if src.Field(i).IsNil() {
				continue
			}
			name, _, _ := strings.Cut(src.Type().Field(i).Tag.Get("yaml"), ",")
			if err := claim("dnsSettings." + name); err != nil {
				return err
			}
			dst.Field(i).Set(src.Field(i))
		}
	}
	if doc.Administration != nil {
		if c.Administration == nil {
			c.Administration = &Administration{}
		}
		c.Administration.Groups = append(c.Administration.Groups, doc.Administration.Groups...)
		c.Administration.Users = append(c.Administration.Users, doc.Administration.Users...)
		c.Administration.Permissions = append(c.Administration.Permissions, doc.Administration.Permissions...)
		c.origins.add("administration.groups", where, len(doc.Administration.Groups))
		c.origins.add("administration.users", where, len(doc.Administration.Users))
		c.origins.add("administration.permissions", where, len(doc.Administration.Permissions))
	}
	c.Zones = append(c.Zones, doc.Zones...)
	c.Records = append(c.Records, doc.Records...)
	c.Apps = append(c.Apps, doc.Apps...)
	c.origins.add("zones", where, len(doc.Zones))
	c.origins.add("records", where, len(doc.Records))
	c.origins.add("apps", where, len(doc.Apps))
	return nil
}

// Origin names the document that set recordPolicy, cluster or a
// "dnsSettings.<key>", or returns "" when none did.
func (c *Config) Origin(key string) string {
	return c.keyOrigins[key]
}

// PolicyFor returns the record policy for r: the record's own, then the
// declared zone's, then the file's, then merge.
func (c *Config) PolicyFor(r AddRecordRequest, zone string) string {
	if r.RecordPolicy != nil {
		return *r.RecordPolicy
	}
	for _, z := range c.Zones {
		if z.RecordPolicy != nil && SameName(z.Zone, zone) {
			return *z.RecordPolicy
		}
	}
	if c.RecordPolicy != nil {
		return *c.RecordPolicy
	}
	return PolicyMerge
}
