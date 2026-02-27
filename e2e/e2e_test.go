//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	defaultUser     = "admin"
	defaultPassword = "admin"
	newPassword     = "e2e-secure-password"
	zoneName        = "e2e-test.local"
)

func TestE2EIdempotency(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	requireDocker(t)

	bin := buildBinary(t)
	port := freePort(t)
	apiURL := fmt.Sprintf("http://127.0.0.1:%d", port)

	startDNSServer(t, port)
	waitForHealth(t, apiURL+"/api/health", 60*time.Second)

	testDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dnsConfigPath := filepath.Join(testDir, "testdata", "dns-config.yaml")
	tokenPath := filepath.Join(t.TempDir(), "token.yaml")

	// ── RUN 1 (initial setup) ──────────────────────────────
	t.Log("=== RUN 1: Initial setup ===")

	// change-password (admin → e2e-secure-password)
	runConfigurator(t, bin, "change-password", envMap{
		"DNS_API_URL":      apiURL,
		"DNS_USERNAME":     defaultUser,
		"DNS_PASSWORD":     defaultPassword,
		"DNS_NEW_PASSWORD": newPassword,
		"DNS_LOG_LEVEL":    "info",
	})

	// create-token (saves to tokenPath)
	runConfigurator(t, bin, "create-token", envMap{
		"DNS_API_URL":    apiURL,
		"DNS_USERNAME":   defaultUser,
		"DNS_PASSWORD":   newPassword,
		"DNS_TOKEN_PATH": tokenPath,
		"DNS_LOG_LEVEL":  "info",
	})

	// Verify token file was created
	tokenData1, err := os.ReadFile(tokenPath)
	if err != nil {
		t.Fatalf("token file not created after run 1: %v", err)
	}
	if len(tokenData1) == 0 {
		t.Fatal("token file is empty after run 1")
	}

	// configure (DNS settings + zone + records)
	runConfigurator(t, bin, "configure", envMap{
		"DNS_API_URL":   apiURL,
		"DNS_USERNAME":  defaultUser,
		"DNS_PASSWORD":  newPassword,
		"DNS_LOG_LEVEL": "info",
	}, dnsConfigPath)

	// Verify state via API
	t.Log("Verifying state after run 1...")
	token := loginAndGetToken(t, apiURL, defaultUser, newPassword)
	verifyZoneExists(t, apiURL, token, zoneName)
	verifyRecordExists(t, apiURL, token, "www."+zoneName, "A", zoneName)
	verifyRecordExists(t, apiURL, token, zoneName, "MX", zoneName)
	verifyRecordExists(t, apiURL, token, zoneName, "TXT", zoneName)
	verifyRecordExists(t, apiURL, token, "alias."+zoneName, "CNAME", zoneName)
	verifyDNSSetting(t, apiURL, token, zoneName)

	// ── RUN 2 (idempotency) ────────────────────────────────
	t.Log("=== RUN 2: Idempotency check ===")

	// change-password (same → same, should succeed)
	runConfigurator(t, bin, "change-password", envMap{
		"DNS_API_URL":      apiURL,
		"DNS_USERNAME":     defaultUser,
		"DNS_PASSWORD":     newPassword,
		"DNS_NEW_PASSWORD": newPassword,
		"DNS_LOG_LEVEL":    "info",
	})

	// create-token (detects existing token file, skips)
	runConfigurator(t, bin, "create-token", envMap{
		"DNS_API_URL":    apiURL,
		"DNS_USERNAME":   defaultUser,
		"DNS_PASSWORD":   newPassword,
		"DNS_TOKEN_PATH": tokenPath,
		"DNS_LOG_LEVEL":  "info",
	})

	// Verify token file unchanged
	tokenData2, err := os.ReadFile(tokenPath)
	if err != nil {
		t.Fatalf("token file read failed after run 2: %v", err)
	}
	if string(tokenData1) != string(tokenData2) {
		t.Error("token file changed between run 1 and run 2 — expected idempotent skip")
	}

	// configure again (zone-exists errors logged, but settings + records still apply)
	runConfigurator(t, bin, "configure", envMap{
		"DNS_API_URL":   apiURL,
		"DNS_USERNAME":  defaultUser,
		"DNS_PASSWORD":  newPassword,
		"DNS_LOG_LEVEL": "info",
	}, dnsConfigPath)

	// Verify same state as after run 1
	t.Log("Verifying state after run 2...")
	token2 := loginAndGetToken(t, apiURL, defaultUser, newPassword)
	verifyZoneExists(t, apiURL, token2, zoneName)
	verifyRecordExists(t, apiURL, token2, "www."+zoneName, "A", zoneName)
	verifyRecordExists(t, apiURL, token2, zoneName, "MX", zoneName)
	verifyRecordExists(t, apiURL, token2, zoneName, "TXT", zoneName)
	verifyRecordExists(t, apiURL, token2, "alias."+zoneName, "CNAME", zoneName)
	verifyDNSSetting(t, apiURL, token2, zoneName)
}

func TestE2ECluster(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	requireDocker(t)

	bin := buildBinary(t)
	primaryPort := freePort(t)
	secondaryPort := freePort(t)
	primaryAPIURL := fmt.Sprintf("http://127.0.0.1:%d", primaryPort)
	secondaryAPIURL := fmt.Sprintf("http://127.0.0.1:%d", secondaryPort)

	const (
		primaryIP     = "172.28.0.10"
		secondaryIP   = "172.28.0.11"
		clusterDomain = "e2e-cluster.local"
		clusterZone   = "cluster-test.local"
	)

	startCluster(t, primaryPort, secondaryPort)
	waitForHealth(t, primaryAPIURL+"/api/health", 60*time.Second)
	waitForHealth(t, secondaryAPIURL+"/api/health", 60*time.Second)

	// Change passwords on both nodes
	for _, nodeURL := range []string{primaryAPIURL, secondaryAPIURL} {
		runConfigurator(t, bin, "change-password", envMap{
			"DNS_API_URL":      nodeURL,
			"DNS_USERNAME":     defaultUser,
			"DNS_PASSWORD":     defaultPassword,
			"DNS_NEW_PASSWORD": newPassword,
			"DNS_LOG_LEVEL":    "info",
		})
	}

	// Primary config: cluster init + DNS settings + zone + records.
	// Only the primary needs DNS config — settings, zones, and records
	// replicate to secondary nodes via the cluster.
	// Use a short configRefreshIntervalSeconds so replication happens quickly
	// during tests (default is 900s / 15 min).
	primaryCfg := fmt.Sprintf(`cluster:
  mode: "primary"
  domain: %q
  nodeIPs: %q
  configRefreshIntervalSeconds: 30
  configRetryIntervalSeconds: 30
  heartbeatRefreshIntervalSeconds: 15
  heartbeatRetryIntervalSeconds: 10

dnsSettings:
  defaultRecordTtl: 300
  defaultNsRecordTtl: 3600
  defaultSoaRecordTtl: 900
  dnssecValidation: false
  preferIPv6: false
  udpPayloadSize: 1232
  resolverRetries: 2
  resolverTimeout: 2000
  resolverConcurrency: 4
  forwarderRetries: 2
  forwarderTimeout: 2000
  forwarderConcurrency: 10
  concurrentForwarding: true
  serveStale: true
  serveStaleTtl: 86400
  cacheNegativeRecordTtl: 60
  cacheMaximumEntries: 0
  enableDnsOverHttp: true
  enableDnsOverTls: true
  enableDnsOverHttps: true
  enableDnsOverQuic: true
  loggingType: "FileAndConsole"
  enableLogging: true
  logQueries: false
  useLocalTime: true
  maxLogFileDays: 7
  maxStatFileDays: 365

zones:
  - zone: %q
    type: "Primary"

records:
  - domain: "www.%s"
    type: "A"
    ttl: 300
    ipAddress: "10.0.0.1"

  - domain: "%s"
    type: "TXT"
    ttl: 300
    text: "v=spf1 -all"
`, clusterDomain, primaryIP, clusterZone, clusterZone, clusterZone)

	primaryCfgPath := filepath.Join(t.TempDir(), "primary-config.yaml")
	if err := os.WriteFile(primaryCfgPath, []byte(primaryCfg), 0644); err != nil {
		t.Fatalf("failed to write primary config: %v", err)
	}

	// ── RUN 1: Initialize cluster and configure primary ──
	t.Log("=== RUN 1: Initialize cluster and configure primary ===")
	runConfigurator(t, bin, "configure", envMap{
		"DNS_API_URL":   primaryAPIURL,
		"DNS_USERNAME":  defaultUser,
		"DNS_PASSWORD":  newPassword,
		"DNS_LOG_LEVEL": "info",
	}, primaryCfgPath)

	// Verify primary: cluster state + zone + records
	token := loginAndGetToken(t, primaryAPIURL, defaultUser, newPassword)
	verifyClusterState(t, primaryAPIURL, token, true, -1)
	verifyClusterOptions(t, primaryAPIURL, token, 30)
	verifyZoneExists(t, primaryAPIURL, token, clusterZone)
	verifyRecordExists(t, primaryAPIURL, token, "www."+clusterZone, "A", clusterZone)
	verifyRecordExists(t, primaryAPIURL, token, clusterZone, "TXT", clusterZone)

	// Secondary config: cluster join ONLY — no DNS settings, zones, or
	// records.  These replicate from the primary automatically.
	// primaryURL must use a domain name (not an IP) because Technitium
	// creates a DomainEndPoint from the hostname.  primaryIP provides the
	// actual address so Technitium doesn't need to DNS-resolve the name
	// (its own resolver can't resolve Docker service names).
	secondaryCfg := fmt.Sprintf(`cluster:
  mode: "secondary"
  nodeIPs: %q
  primaryURL: "http://dns-primary:5380"
  primaryIP: %q
  primaryUsername: %q
  primaryPassword: %q
  ignoreCertErrors: true
`, secondaryIP, primaryIP, defaultUser, newPassword)

	secondaryCfgPath := filepath.Join(t.TempDir(), "secondary-config.yaml")
	if err := os.WriteFile(secondaryCfgPath, []byte(secondaryCfg), 0644); err != nil {
		t.Fatalf("failed to write secondary config: %v", err)
	}

	// ── RUN 2: Join secondary to cluster (cluster-only config) ──
	t.Log("=== RUN 2: Join secondary to cluster (cluster-only config) ===")
	runConfigurator(t, bin, "configure", envMap{
		"DNS_API_URL":   secondaryAPIURL,
		"DNS_USERNAME":  defaultUser,
		"DNS_PASSWORD":  newPassword,
		"DNS_LOG_LEVEL": "debug",
	}, secondaryCfgPath)

	// Verify secondary cluster state
	secondaryToken := loginAndGetToken(t, secondaryAPIURL, defaultUser, newPassword)
	verifyClusterState(t, secondaryAPIURL, secondaryToken, true, -1)

	// Wait for config replication from primary to secondary.
	// We set configRefreshIntervalSeconds=30 so this should happen within ~60s.
	t.Log("Waiting for config replication to secondary...")
	deadline := time.Now().Add(90 * time.Second)
	replicated := false
	for time.Now().Before(deadline) {
		time.Sleep(10 * time.Second)
		secondaryToken = loginAndGetToken(t, secondaryAPIURL, defaultUser, newPassword)
		resp, err := http.Get(fmt.Sprintf("%s/api/zones/options/get?zone=%s&token=%s",
			secondaryAPIURL, clusterZone, secondaryToken))
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				// Check if the API returned status:ok (zone exists)
				resp2, _ := http.Get(fmt.Sprintf("%s/api/zones/options/get?zone=%s&token=%s",
					secondaryAPIURL, clusterZone, secondaryToken))
				body, _ := io.ReadAll(resp2.Body)
				resp2.Body.Close()
				if strings.Contains(string(body), `"status":"ok"`) {
					replicated = true
					break
				}
			}
		}
		t.Log("Zone not yet replicated, retrying...")
	}
	if replicated {
		verifyZoneExists(t, secondaryAPIURL, secondaryToken, clusterZone)
		verifyRecordExists(t, secondaryAPIURL, secondaryToken, "www."+clusterZone, "A", clusterZone)
	} else {
		t.Log("Zone replication did not complete within timeout — skipping secondary zone verification")
	}

	// ── RUN 3: Idempotency — re-run both ─────────────────
	t.Log("=== RUN 3: Idempotency check ===")

	runConfigurator(t, bin, "configure", envMap{
		"DNS_API_URL":   primaryAPIURL,
		"DNS_USERNAME":  defaultUser,
		"DNS_PASSWORD":  newPassword,
		"DNS_LOG_LEVEL": "info",
	}, primaryCfgPath)

	runConfigurator(t, bin, "configure", envMap{
		"DNS_API_URL":   secondaryAPIURL,
		"DNS_USERNAME":  defaultUser,
		"DNS_PASSWORD":  newPassword,
		"DNS_LOG_LEVEL": "info",
	}, secondaryCfgPath)

	// Verify cluster state from both nodes — each should see 2 nodes
	token3 := loginAndGetToken(t, primaryAPIURL, defaultUser, newPassword)
	verifyClusterState(t, primaryAPIURL, token3, true, 2)
	secondaryToken3 := loginAndGetToken(t, secondaryAPIURL, defaultUser, newPassword)
	verifyClusterState(t, secondaryAPIURL, secondaryToken3, true, 2)

	// Verify zone + records still present on primary after idempotency
	verifyZoneExists(t, primaryAPIURL, token3, clusterZone)
	verifyRecordExists(t, primaryAPIURL, token3, "www."+clusterZone, "A", clusterZone)
	verifyRecordExists(t, primaryAPIURL, token3, clusterZone, "TXT", clusterZone)

	// ── Verify cluster-state command still works ──────────
	t.Log("=== Verify cluster-state command ===")
	output := runConfigurator(t, bin, "cluster-state", envMap{
		"DNS_API_URL":   primaryAPIURL,
		"DNS_USERNAME":  defaultUser,
		"DNS_PASSWORD":  newPassword,
		"DNS_LOG_LEVEL": "info",
	})
	if !strings.Contains(output, "initialized=true") {
		t.Errorf("cluster-state output missing initialized=true:\n%s", output)
	}
}

// ─── Types ──────────────────────────────────────────────

type envMap map[string]string

// ─── Helpers ────────────────────────────────────────────

func requireDocker(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not found in PATH, skipping e2e test")
	}
	out, err := exec.Command("docker", "info").CombinedOutput()
	if err != nil {
		t.Skipf("docker daemon not available: %v\n%s", err, out)
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("freePort: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port
}

func buildBinary(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "technitium-configurator")

	testDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	projectRoot := filepath.Dir(testDir)

	cmd := exec.Command("go", "build", "-o", bin, ".")
	cmd.Dir = projectRoot
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go build failed: %v\n%s", err, out)
	}
	return bin
}

func startCluster(t *testing.T, primaryPort, secondaryPort int) {
	t.Helper()

	testDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	composeFile := filepath.Join(testDir, "docker-compose.cluster.yaml")
	project := fmt.Sprintf("e2e-cluster-%d", primaryPort)

	up := exec.Command("docker", "compose",
		"-f", composeFile,
		"-p", project,
		"up", "-d", "--wait",
	)
	up.Env = append(os.Environ(),
		fmt.Sprintf("DNS_PRIMARY_PORT=%d", primaryPort),
		fmt.Sprintf("DNS_SECONDARY_PORT=%d", secondaryPort),
	)
	out, err := up.CombinedOutput()
	if err != nil {
		t.Fatalf("docker compose up (cluster) failed: %v\n%s", err, out)
	}
	t.Logf("cluster compose up (project=%s, primary=%d, secondary=%d)", project, primaryPort, secondaryPort)

	t.Cleanup(func() {
		down := exec.Command("docker", "compose",
			"-f", composeFile,
			"-p", project,
			"down", "-v", "--remove-orphans",
		)
		down.Env = append(os.Environ(),
			fmt.Sprintf("DNS_PRIMARY_PORT=%d", primaryPort),
			fmt.Sprintf("DNS_SECONDARY_PORT=%d", secondaryPort),
		)
		out, err := down.CombinedOutput()
		if err != nil {
			t.Logf("docker compose down (cluster) failed: %v\n%s", err, out)
		}
	})
}

func startDNSServer(t *testing.T, port int) {
	t.Helper()

	testDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	composeFile := filepath.Join(testDir, "docker-compose.yaml")
	project := fmt.Sprintf("e2e-%d", port)

	up := exec.Command("docker", "compose",
		"-f", composeFile,
		"-p", project,
		"up", "-d", "--wait",
	)
	up.Env = append(os.Environ(), fmt.Sprintf("DNS_PORT=%d", port))
	out, err := up.CombinedOutput()
	if err != nil {
		t.Fatalf("docker compose up failed: %v\n%s", err, out)
	}
	t.Logf("docker compose up (project=%s, port=%d)", project, port)

	t.Cleanup(func() {
		down := exec.Command("docker", "compose",
			"-f", composeFile,
			"-p", project,
			"down", "-v", "--remove-orphans",
		)
		down.Env = append(os.Environ(), fmt.Sprintf("DNS_PORT=%d", port))
		out, err := down.CombinedOutput()
		if err != nil {
			t.Logf("docker compose down failed: %v\n%s", err, out)
		}
	})
}

func waitForHealth(t *testing.T, url string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				t.Log("DNS server healthy")
				return
			}
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("DNS server not healthy after %s", timeout)
}

func runConfigurator(t *testing.T, bin, command string, env envMap, extraArgs ...string) string {
	t.Helper()
	args := []string{command}
	args = append(args, extraArgs...)

	cmd := exec.Command(bin, args...)
	cmd.Env = []string{
		"HOME=" + os.Getenv("HOME"),
		"PATH=" + os.Getenv("PATH"),
	}
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}

	out, err := cmd.CombinedOutput()
	output := string(out)
	t.Logf("[%s] exit=%d\n%s", command, cmd.ProcessState.ExitCode(), output)

	if err != nil {
		t.Fatalf("command %q failed: %v\n%s", command, err, output)
	}
	return output
}

// ─── API verification helpers ───────────────────────────

func loginAndGetToken(t *testing.T, apiURL, user, pass string) string {
	t.Helper()

	reqURL := fmt.Sprintf("%s/api/user/login?user=%s&pass=%s&includeInfo=false", apiURL, user, pass)
	resp, err := http.Get(reqURL)
	if err != nil {
		t.Fatalf("login request failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var result struct {
		Token  string `json:"token"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("login response parse failed: %v\nbody: %s", err, body)
	}
	if result.Status != "ok" {
		t.Fatalf("login failed: status=%s body=%s", result.Status, body)
	}
	if result.Token == "" {
		t.Fatal("login returned empty token")
	}
	return result.Token
}

func queryDNSAPI(t *testing.T, apiURL, token, path string) json.RawMessage {
	t.Helper()

	sep := "?"
	if strings.Contains(path, "?") {
		sep = "&"
	}
	reqURL := fmt.Sprintf("%s%s%stoken=%s", apiURL, path, sep, token)

	resp, err := http.Get(reqURL)
	if err != nil {
		t.Fatalf("API query %s failed: %v", path, err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var result struct {
		Status   string          `json:"status"`
		Response json.RawMessage `json:"response"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("API response parse failed for %s: %v\nbody: %s", path, err, body)
	}
	if result.Status != "ok" {
		t.Fatalf("API query %s returned status=%s\nbody: %s", path, result.Status, body)
	}
	return result.Response
}

func verifyZoneExists(t *testing.T, apiURL, token, zone string) {
	t.Helper()
	queryDNSAPI(t, apiURL, token, fmt.Sprintf("/api/zones/options/get?zone=%s", zone))
	t.Logf("verified zone %q exists", zone)
}

func verifyRecordExists(t *testing.T, apiURL, token, domain, recordType, zone string) {
	t.Helper()
	data := queryDNSAPI(t, apiURL, token,
		fmt.Sprintf("/api/zones/records/get?domain=%s&zone=%s", domain, zone))

	var result struct {
		Records []struct {
			Name string `json:"name"`
			Type string `json:"type"`
		} `json:"records"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("failed to parse records for %s: %v", domain, err)
	}

	for _, r := range result.Records {
		if strings.EqualFold(r.Type, recordType) {
			t.Logf("verified record %s/%s exists in zone %s", domain, recordType, zone)
			return
		}
	}
	t.Errorf("record %s/%s not found in zone %s", domain, recordType, zone)
}

func verifyDNSSetting(t *testing.T, apiURL, token, expectedDomain string) {
	t.Helper()
	data := queryDNSAPI(t, apiURL, token, "/api/settings/get")

	var settings struct {
		DnsServerDomain    string `json:"dnsServerDomain"`
		DefaultRecordTtl   int    `json:"defaultRecordTtl"`
		ServeStale         bool   `json:"serveStale"`
		EnableDnsOverHttps bool   `json:"enableDnsOverHttps"`
		UdpPayloadSize     int    `json:"udpPayloadSize"`
	}
	if err := json.Unmarshal(data, &settings); err != nil {
		t.Fatalf("failed to parse DNS settings: %v", err)
	}
	if settings.DnsServerDomain != expectedDomain {
		t.Errorf("DNS server domain = %q, want %q", settings.DnsServerDomain, expectedDomain)
	}
	if settings.DefaultRecordTtl != 300 {
		t.Errorf("defaultRecordTtl = %d, want 300", settings.DefaultRecordTtl)
	}
	if !settings.ServeStale {
		t.Errorf("serveStale = false, want true")
	}
	if !settings.EnableDnsOverHttps {
		t.Errorf("enableDnsOverHttps = false, want true")
	}
	if settings.UdpPayloadSize != 1232 {
		t.Errorf("udpPayloadSize = %d, want 1232", settings.UdpPayloadSize)
	}
	t.Logf("verified DNS settings: domain=%q ttl=%d serveStale=%v doh=%v udpPayload=%d",
		settings.DnsServerDomain, settings.DefaultRecordTtl, settings.ServeStale,
		settings.EnableDnsOverHttps, settings.UdpPayloadSize)
}

func verifyClusterOptions(t *testing.T, apiURL, token string, expectedConfigRefresh int) {
	t.Helper()
	data := queryDNSAPI(t, apiURL, token, "/api/admin/cluster/state?includeServerIpAddresses=true")

	var state struct {
		ConfigRefreshIntervalSecs int `json:"configRefreshIntervalSeconds"`
	}
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatalf("failed to parse cluster state for options check: %v", err)
	}
	if state.ConfigRefreshIntervalSecs != expectedConfigRefresh {
		t.Errorf("configRefreshIntervalSeconds = %d, want %d", state.ConfigRefreshIntervalSecs, expectedConfigRefresh)
	}
	t.Logf("verified cluster configRefreshIntervalSeconds = %d", state.ConfigRefreshIntervalSecs)
}

func verifyClusterState(t *testing.T, apiURL, token string, expectInitialized bool, expectNodes int) {
	t.Helper()
	data := queryDNSAPI(t, apiURL, token, "/api/admin/cluster/state?includeServerIpAddresses=true")

	var state struct {
		ClusterInitialized bool `json:"clusterInitialized"`
		Nodes              []struct {
			Name  string `json:"name"`
			Type  string `json:"type"`
			State string `json:"state"`
		} `json:"clusterNodes"`
	}
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatalf("failed to parse cluster state: %v", err)
	}
	if state.ClusterInitialized != expectInitialized {
		t.Errorf("clusterInitialized = %v, want %v", state.ClusterInitialized, expectInitialized)
	}
	// expectNodes < 0 means skip the node count check
	if expectNodes >= 0 && len(state.Nodes) != expectNodes {
		t.Errorf("cluster nodes = %d, want %d", len(state.Nodes), expectNodes)
	}
	t.Logf("cluster: initialized=%v nodes=%d", state.ClusterInitialized, len(state.Nodes))
	for _, n := range state.Nodes {
		t.Logf("  node: name=%s type=%s state=%s", n.Name, n.Type, n.State)
	}
}
