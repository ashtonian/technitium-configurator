//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// TestE2EBootstrapEdgeCases covers the cases a plain bootstrap and re-run
// miss: multi-file configs, record policies, PTR preservation, IDN names,
// TSIG names with a trailing dot, APP records, TXT character strings, ACL
// clearing, preflight validation, administration and export round trips.
func TestE2EBootstrapEdgeCases(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}
	requireDocker(t)

	bin := buildBinary(t)
	port := freePort(t)
	apiURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	startDNSServer(t, port)
	waitForHealth(t, apiURL+"/api/status", 60*time.Second)

	env := envMap{
		"DNS_API_URL":  apiURL,
		"DNS_USERNAME": defaultUser,
		"DNS_PASSWORD": newPassword,
		// Debug logs every request, which assertCleanRerun reads.
		"DNS_LOG_LEVEL": "debug",
		// Password of the user the administration section creates.
		"E2E_OPERATOR_PASSWORD": "operator-initial-password",
	}
	runConfigurator(t, bin, "change-password", envMap{
		"DNS_API_URL":      apiURL,
		"DNS_USERNAME":     defaultUser,
		"DNS_PASSWORD":     defaultPassword,
		"DNS_NEW_PASSWORD": newPassword,
	})

	dir := t.TempDir()
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("10-base.yaml", `
dnsSettings:
  tsigKeys:
    - keyName: "e2e-dotted.edge.test."
      algorithmName: "hmac-sha256"
      sharedSecret: "ZTJlLWRvdHRlZC1zZWNyZXQtZm9yLXRoZS1lMmUtdGVzdA=="
zones:
  - zone: "edge.test"
    type: "Primary"
    aclSettings:
      update: "UseSpecifiedNetworkACL"
      updateNetworkACL: ["10.0.0.0/8"]
  - zone: "bücher.test"
    type: "Primary"
  - zone: "off.test"
    type: "Primary"
    disabled: true
  - zone: "fwd.edge"
    type: "Forwarder"
    initializeForwarder: false
  # The root zone: everything not in a closer zone is forwarded to this
  # server's own resolver, so resolution is unchanged.
  - zone: "."
    type: "Forwarder"
    initializeForwarder: true
    forwarder: "this-server"
apps:
  - name: "NO DATA"
    url: "https://download.technitium.com/dns/apps/NoDataApp-v6.zip"
    # Past float64 precision; must survive export exactly.
    config: {note: 9007199254740993}
administration:
  groups:
    - name: "e2e-operators"
      description: "created by the e2e suite"
  users:
    - username: "operator"
      passwordEnv: "E2E_OPERATOR_PASSWORD"
      groups: ["e2e-operators"]
  permissions:
    - section: "Zones"
      groups:
        e2e-operators: [view, modify]
---
records:
  - domain: "www.edge.test"
    type: "A"
    ipAddress: "10.20.30.40"
    ptr: true
    createPtrZone: true
`)
	write("20-records.yaml", `
records:
  - domain: "nodata.edge.test"
    type: "APP"
    appName: "NO DATA"
    classPath: "NoData.App"
    recordData: '{"blockedTypes": ["AAAA"]}'
  - domain: "www.bücher.test"
    type: "CNAME"
    cname: "Bücher.test."
  - domain: "bytes.edge.test"
    type: "TXT"
    characterStringsBase64: ["aGVsbG8=", "d29ybGQ="]
  - domain: "pool.edge.test"
    type: "A"
    recordPolicy: "replace"
    ipAddress: "192.0.2.1"
  - domain: "pool.edge.test"
    type: "A"
    recordPolicy: "replace"
    ipAddress: "192.0.2.2"
  - domain: "shared.edge.test"
    type: "A"
    ipAddress: "192.0.2.10"
  # Values the server stores in another form; an unchanged re-run must
  # recognise every one of them.
  - {domain: "split.edge.test", type: "TXT", text: "hello\nworld", splitText: true}
  - {domain: "bin.edge.test", type: "TXT", characterStringsBase64: ["/wA="]}
  - {domain: "rp.edge.test", type: "RP", mailbox: "hostmaster.edge.test.", txtDomain: "info.edge.test."}
  - {domain: "_http._tcp.edge.test", type: "URI", uriPriority: 1, uriWeight: 1, uri: "HTTPS://Example.COM:443/a/../b"}
  - {domain: "svc.edge.test", type: "HTTPS", svcPriority: 1, svcTargetName: ".", svcParams: "alpn|h2"}
  - {domain: "svcb.edge.test", type: "SVCB", svcPriority: 1, svcTargetName: "target.edge.test", svcParams: "port|0443|ipv6hint|2001:0DB8::1"}
  - {domain: "idn.edge.test", type: "CNAME", cname: "BÜCHER.test."}
  - {domain: "sub.edge.test", type: "NS", nameServer: "ns1.sub.edge.test", glue: "10.9.9.9"}
  - {domain: "v6.edge.test", type: "AAAA", ipAddress: "[2001:db8::20]", ptr: true, createPtrZone: true}
  - {domain: "opaque.edge.test", type: "TYPE65200", rdata: "0a0b"}
  - {domain: "fwd.edge", type: "FWD", forwarder: "192.0.2.53", dnssecValidation: true, forwarderPriority: 5}
  # No zone given: lands in the root zone.
  - {domain: "corp.invalid", type: "FWD", forwarder: "192.0.2.54"}
  - {domain: "empty.edge.test", type: "TXT", text: ""}
  - {domain: "ds.edge.test", type: "DS", keyTag: 1, algorithm: "8", digestType: "2", digest: "abababababababababababababababababababababababababababababababab"}
  - {domain: "_ldap._tcp.edge.test", type: "URI", uriPriority: 1, uriWeight: 1, uri: "https://example.com/a%2Fb/%7euser"}
`)

	t.Log("=== First run from a config directory ===")
	runConfigurator(t, bin, "configure", env, dir)
	t.Log("=== Unchanged re-run ===")
	assertCleanRerun(t, runConfigurator(t, bin, "configure", env, dir))

	token := loginAndGetToken(t, apiURL, defaultUser, newPassword)

	// A re-run must not touch an existing PTR, even one changed by hand.
	ptr := "40.30.20.10.in-addr.arpa"
	apiCall(t, apiURL, token, "/api/zones/records/add", url.Values{
		"domain": {ptr}, "type": {"PTR"}, "ptrName": {"operator-set.edge.test"}, "overwrite": {"true"},
	})
	assertCleanRerun(t, runConfigurator(t, bin, "configure", env, dir))
	if got := recordValues(t, apiURL, token, ptr, "PTR", "ptrName"); !equalStrings(got, []string{"operator-set.edge.test"}) {
		t.Errorf("PTR = %v, want the hand-set value kept", got)
	}
	// The same for an IPv6 address written in brackets.
	ptr6 := "0.2.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
	apiCall(t, apiURL, token, "/api/zones/records/add", url.Values{
		"domain": {ptr6}, "type": {"PTR"}, "ptrName": {"operator6.edge.test"}, "overwrite": {"true"},
	})
	assertCleanRerun(t, runConfigurator(t, bin, "configure", env, dir))
	if got := recordValues(t, apiURL, token, ptr6, "PTR", "ptrName"); !equalStrings(got, []string{"operator6.edge.test"}) {
		t.Errorf("IPv6 PTR = %v, want the hand-set value kept", got)
	}

	// Merge keeps values the file does not list and reports them.
	apiCall(t, apiURL, token, "/api/zones/records/add", url.Values{
		"domain": {"shared.edge.test"}, "type": {"A"}, "ipAddress": {"192.0.2.11"},
	})
	out := runConfigurator(t, bin, "configure", env, dir)
	assertCleanRerun(t, out)
	if !strings.Contains(out, "does not list") {
		t.Errorf("merge did not report the extra value:\n%s", out)
	}
	if got := recordValues(t, apiURL, token, "shared.edge.test", "A", "ipAddress"); !equalStrings(got, []string{"192.0.2.10", "192.0.2.11"}) {
		t.Errorf("shared A = %v, want both values kept", got)
	}

	// Replace makes the declared values the only ones.
	write("20-records.yaml", strings.Replace(readFile(t, filepath.Join(dir, "20-records.yaml")), `ipAddress: "192.0.2.1"`, `ipAddress: "192.0.2.3"`, 1))
	runConfigurator(t, bin, "configure", env, dir)
	if got := recordValues(t, apiURL, token, "pool.edge.test", "A", "ipAddress"); !equalStrings(got, []string{"192.0.2.2", "192.0.2.3"}) {
		t.Errorf("pool A = %v, want exactly the declared values", got)
	}
	assertCleanRerun(t, runConfigurator(t, bin, "configure", env, dir))

	// An explicit empty list clears a zone option.
	clear := filepath.Join(t.TempDir(), "clear.yaml")
	if err := os.WriteFile(clear, []byte("zones:\n  - zone: edge.test\n    type: Primary\n    aclSettings:\n      updateNetworkACL: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runConfigurator(t, bin, "configure", env, clear)
	var opts struct {
		UpdateNetworkACL []string `json:"updateNetworkACL"`
	}
	if err := json.Unmarshal(queryDNSAPI(t, apiURL, token, "/api/zones/options/get?zone=edge.test"), &opts); err != nil {
		t.Fatal(err)
	}
	if len(opts.UpdateNetworkACL) != 0 {
		t.Errorf("updateNetworkACL = %v, want cleared", opts.UpdateNetworkACL)
	}

	// Invalid values fail before anything changes.
	bad := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(bad, []byte("dnsSettings:\n  recursion: Sometimes\nzones:\n  - {zone: never-created.test, type: Primary}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out = runConfiguratorExpectFailure(t, bin, "configure", env, bad)
	if !strings.Contains(out, "Sometimes") || !strings.Contains(out, "must be one of") {
		t.Errorf("unexpected validation output:\n%s", out)
	}
	if zoneExists(t, apiURL, token, "never-created.test") {
		t.Error("a zone was created although the config was invalid")
	}

	// A forwarder the server would reject after applying earlier settings
	// is caught first, so no setting changes.
	badForwarder := filepath.Join(t.TempDir(), "bad-forwarder.yaml")
	if err := os.WriteFile(badForwarder, []byte("dnsSettings:\n  defaultRecordTtl: 2345\n  forwarderProtocol: Udp\n  forwarders: ['192.0.2.1 (192.0.2.2)']\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out = runConfiguratorExpectFailure(t, bin, "configure", env, badForwarder)
	if !strings.Contains(out, "not a name server address") {
		t.Errorf("unexpected output for a malformed forwarder:\n%s", out)
	}
	var settings struct {
		DefaultRecordTtl int `json:"defaultRecordTtl"`
	}
	if err := json.Unmarshal(queryDNSAPI(t, apiURL, token, "/api/settings/get"), &settings); err != nil {
		t.Fatal(err)
	}
	if settings.DefaultRecordTtl == 2345 {
		t.Error("defaultRecordTtl changed although the config was invalid")
	}

	// Administration: the user exists, in its group, and can log in.
	var user struct {
		MemberOfGroups []string `json:"memberOfGroups"`
	}
	if err := json.Unmarshal(queryDNSAPI(t, apiURL, token, "/api/admin/users/get?user=operator&includeGroups=true"), &user); err != nil {
		t.Fatal(err)
	}
	if !containsFold(user.MemberOfGroups, "e2e-operators") {
		t.Errorf("operator groups = %v, want e2e-operators", user.MemberOfGroups)
	}
	loginAndGetToken(t, apiURL, "operator", "operator-initial-password")

	// Export, then apply the export: nothing changes and nothing conflicts.
	exported := filepath.Join(t.TempDir(), "export.yaml")
	runConfigurator(t, bin, "export", env, exported)
	out = runConfigurator(t, bin, "configure", env, exported)
	assertCleanRerun(t, out)
	if !strings.Contains(out, "created=0") {
		t.Errorf("applying the export created resources:\n%s", out)
	}
	second := filepath.Join(t.TempDir(), "export2.yaml")
	runConfigurator(t, bin, "export", env, second)
	if a, b := stripHeader(readFile(t, exported)), stripHeader(readFile(t, second)); a != b {
		t.Errorf("export is not stable across an apply:\n--- first\n%s\n--- second\n%s", a, b)
	}

	t.Log("=== Export restored onto a fresh server ===")
	port2 := freePort(t)
	apiURL2 := fmt.Sprintf("http://127.0.0.1:%d", port2)
	startDNSServer(t, port2)
	waitForHealth(t, apiURL2+"/api/status", 60*time.Second)
	runConfigurator(t, bin, "change-password", envMap{
		"DNS_API_URL":      apiURL2,
		"DNS_USERNAME":     defaultUser,
		"DNS_PASSWORD":     defaultPassword,
		"DNS_NEW_PASSWORD": newPassword,
	})
	env2 := envMap{}
	for k, v := range env {
		env2[k] = v
	}
	env2["DNS_API_URL"] = apiURL2

	// Passwords are not exported; a new server needs one to create the user.
	restore := strings.Replace(readFile(t, exported), "- username: operator\n", "- username: operator\n      passwordEnv: E2E_OPERATOR_PASSWORD\n", 1)
	if restore == readFile(t, exported) {
		t.Fatalf("export has no operator user to add a password source to:\n%s", restore)
	}
	restorePath := filepath.Join(t.TempDir(), "restore.yaml")
	if err := os.WriteFile(restorePath, []byte(restore), 0o600); err != nil {
		t.Fatal(err)
	}
	runConfigurator(t, bin, "configure", env2, restorePath)
	assertCleanRerun(t, runConfigurator(t, bin, "configure", env2, restorePath))
	restored := filepath.Join(t.TempDir(), "export-restored.yaml")
	runConfigurator(t, bin, "export", env2, restored)
	if a, b := stripHeader(readFile(t, exported)), stripHeader(readFile(t, restored)); a != b {
		t.Errorf("the restored server exports differently:\n--- source\n%s\n--- restored\n%s", a, b)
	}
	token2 := loginAndGetToken(t, apiURL2, defaultUser, newPassword)
	var zones struct {
		Zones []struct {
			Name     string `json:"name"`
			Disabled bool   `json:"disabled"`
		} `json:"zones"`
	}
	if err := json.Unmarshal(queryDNSAPI(t, apiURL2, token2, "/api/zones/list"), &zones); err != nil {
		t.Fatal(err)
	}
	for _, z := range zones.Zones {
		if z.Name == "off.test" && !z.Disabled {
			t.Error("off.test is enabled on the restored server")
		}
	}
	var txt struct {
		Records []struct {
			RData struct {
				CharacterStringsBase64 []string `json:"characterStringsBase64"`
			} `json:"rData"`
		} `json:"records"`
	}
	if err := json.Unmarshal(queryDNSAPI(t, apiURL2, token2, "/api/zones/records/get?domain=bin.edge.test"), &txt); err != nil {
		t.Fatal(err)
	}
	if len(txt.Records) != 1 || !equalStrings(txt.Records[0].RData.CharacterStringsBase64, []string{"/wA="}) {
		t.Errorf("bin.edge.test TXT on the restored server = %+v, want the bytes ff 00", txt.Records)
	}
}

func apiCall(t *testing.T, apiURL, token, path string, form url.Values) json.RawMessage {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, apiURL+path, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	var env struct {
		Status   string          `json:"status"`
		Response json.RawMessage `json:"response"`
	}
	if err := json.Unmarshal(body, &env); err != nil || env.Status != "ok" {
		t.Fatalf("%s failed: %s", path, body)
	}
	return env.Response
}

func recordValues(t *testing.T, apiURL, token, domain, recordType, field string) []string {
	t.Helper()
	var result struct {
		Records []struct {
			Type  string                     `json:"type"`
			RData map[string]json.RawMessage `json:"rData"`
		} `json:"records"`
	}
	if err := json.Unmarshal(queryDNSAPI(t, apiURL, token, "/api/zones/records/get?domain="+url.QueryEscape(domain)), &result); err != nil {
		t.Fatal(err)
	}
	var values []string
	for _, r := range result.Records {
		if strings.EqualFold(r.Type, recordType) {
			var s string
			_ = json.Unmarshal(r.RData[field], &s)
			values = append(values, s)
		}
	}
	sort.Strings(values)
	return values
}

func zoneExists(t *testing.T, apiURL, token, zone string) bool {
	t.Helper()
	var result struct {
		Zones []struct {
			Name string `json:"name"`
		} `json:"zones"`
	}
	if err := json.Unmarshal(queryDNSAPI(t, apiURL, token, "/api/zones/list"), &result); err != nil {
		t.Fatal(err)
	}
	for _, z := range result.Zones {
		if strings.EqualFold(z.Name, zone) {
			return true
		}
	}
	return false
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// stripHeader drops export's comment header, which names the source.
func stripHeader(s string) string {
	var lines []string
	for _, l := range strings.Split(s, "\n") {
		if !strings.HasPrefix(l, "#") {
			lines = append(lines, l)
		}
	}
	return strings.Join(lines, "\n")
}

func equalStrings(a, b []string) bool {
	return strings.Join(a, ",") == strings.Join(b, ",")
}

func containsFold(list []string, s string) bool {
	for _, v := range list {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}
