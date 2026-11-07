//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestE2EBlockingColdLoad(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}
	requireDocker(t)
	bin := buildBinary(t)
	port := freePort(t)
	apiURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	restart := startDNSServer(t, port)
	waitForHealth(t, apiURL+"/api/status", 60*time.Second)
	runConfigurator(t, bin, "change-password", envMap{
		"DNS_API_URL": apiURL, "DNS_USERNAME": defaultUser,
		"DNS_PASSWORD": defaultPassword, "DNS_NEW_PASSWORD": newPassword,
	})

	var example struct {
		Apps []struct {
			Name   string         `yaml:"name"`
			URL    string         `yaml:"url"`
			Config map[string]any `yaml:"config"`
		} `yaml:"apps"`
	}
	data, err := os.ReadFile(filepath.Join("..", "examples", "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(data, &example); err != nil {
		t.Fatal(err)
	}
	const blocked = "example.com"
	var app any
	for _, candidate := range example.Apps {
		if candidate.Name != "Advanced Blocking" {
			continue
		}
		groups := candidate.Config["groups"].([]any)
		group := groups[0].(map[string]any)
		// Keep the example's app schema, while isolating blocking from list downloads.
		for _, field := range []string{"allowed", "allowedRegex", "blockedRegex", "allowListUrls", "blockListUrls", "regexAllowListUrls", "regexBlockListUrls", "adblockListUrls"} {
			group[field] = []string{}
		}
		group["blocked"] = []string{blocked}
		candidate.Config["groups"] = []any{group}
		candidate.Config["networkGroupMap"] = map[string]string{"0.0.0.0/0": group["name"].(string), "::/0": group["name"].(string)}
		app = candidate
		break
	}
	if app == nil {
		t.Fatal("the canonical example has no Advanced Blocking configuration")
	}
	config, err := yaml.Marshal(map[string]any{
		"apps":    []any{app},
		"zones":   []any{map[string]any{"zone": "cold-load.test", "type": "Primary"}},
		"records": []any{map[string]any{"name": "allowed.cold-load.test", "type": "A", "value": "192.0.2.42"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "blocking.yaml")
	if err := os.WriteFile(path, config, 0o600); err != nil {
		t.Fatal(err)
	}
	runConfigurator(t, bin, "configure", envMap{
		"DNS_API_URL": apiURL, "DNS_USERNAME": defaultUser, "DNS_PASSWORD": newPassword,
	}, path)
	restart()
	waitForHealth(t, apiURL+"/api/status", 60*time.Second)
	token := loginAndGetToken(t, apiURL, defaultUser, newPassword)
	for _, protocol := range []string{"Udp", "Tcp"} {
		query := url.Values{"server": {"this-server"}, "domain": {blocked}, "type": {"A"}, "protocol": {protocol}}
		result := queryDNSAPI(t, apiURL, token, "/api/dnsClient/resolve?"+query.Encode())
		var reply struct {
			Result struct {
				RCODE  string `json:"RCODE"`
				Answer []struct {
					Data struct {
						IP string `json:"IPAddress"`
					} `json:"RDATA"`
				} `json:"Answer"`
			} `json:"result"`
		}
		if err := json.Unmarshal(result, &reply); err != nil {
			t.Fatal(err)
		}
		if reply.Result.RCODE != "NxDomain" || !strings.Contains(string(result), "source=advanced-blocking-app") {
			t.Fatalf("%s cold-loaded app did not block: %s", protocol, result)
		}
		query.Set("domain", "allowed.cold-load.test")
		result = queryDNSAPI(t, apiURL, token, "/api/dnsClient/resolve?"+query.Encode())
		if err := json.Unmarshal(result, &reply); err != nil {
			t.Fatal(err)
		}
		if reply.Result.RCODE != "NoError" || len(reply.Result.Answer) != 1 || reply.Result.Answer[0].Data.IP != "192.0.2.42" {
			t.Fatalf("%s persisted control record did not resolve: %s", protocol, result)
		}
	}
}
