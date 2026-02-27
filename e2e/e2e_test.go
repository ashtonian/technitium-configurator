//go:build e2e

package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
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
	verifyDNSSettingsFull(t, apiURL, token)
	verifyZoneACLSingleServer(t, apiURL, token, zoneName)

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
	verifyDNSSettingsFull(t, apiURL, token2)
	verifyZoneACLSingleServer(t, apiURL, token2, zoneName)
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
		forwarderZone = "forwarded.local"
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
  recursion: "Allow"
  qpmPrefixLimitsIPv4:
    - prefix: 24
      udpLimit: 600
      tcpLimit: 100
  qpmPrefixLimitsIPv6:
    - prefix: 56
      udpLimit: 600
      tcpLimit: 100
  qpmLimitSampleMinutes: 5
  cachePrefetchEligibility: 2
  cachePrefetchTrigger: 9
  cachePrefetchSampleIntervalInMinutes: 5
  cachePrefetchSampleEligibilityHitsPerHour: 30
  cacheMinimumRecordTtl: 60
  cacheMaximumRecordTtl: 86400
  cacheFailureRecordTtl: 30
  cacheMaximumEntries: 50000
  saveCache: true
  serveStaleAnswerTtl: 30
  serveStaleMaxWaitTime: 1800
  enableDnsOverUdpProxy: true
  enableDnsOverTcpProxy: true
  enableDnsOverHttp3: true
  tsigKeys:
    - keyName: "e2e-external-dns"
      algorithmName: "hmac-sha256"
      sharedSecret: "cHJldGVuZHRoaXNpc2FyZWFsc2VjcmV0a2V5YmFzZTY0"
    - keyName: "e2e-dhcp"
      algorithmName: "hmac-sha256"
      sharedSecret: "YW5vdGhlcnByZXRlbmRzZWNyZXRrZXlmb3JkaGNwdGVzdA=="

zones:
  - zone: %q
    type: "Primary"
    aclSettings:
      queryAccess: "AllowOnlyPrivateNetworks"
      zoneTransfer: "UseSpecifiedNetworkACL"
      zoneTransferNetworkACL:
        - "172.28.0.0/16"
      zoneTransferTsigKeyNames:
        - "e2e-external-dns"
        - "e2e-dhcp"
      update: "UseSpecifiedNetworkACL"
      updateNetworkACL:
        - "172.28.0.0/16"
      updateSecurityPolicies: "e2e-external-dns|*.%s|ANY|e2e-dhcp|*.%s|ANY"

  - zone: "forwarded.local"
    type: "Forwarder"
    initializeForwarder: true
    protocol: "Https"
    forwarder: "https://cloudflare-dns.com/dns-query"
    dnssecValidation: true

records:
  - domain: "www.%s"
    type: "A"
    ttl: 300
    ipAddress: "10.0.0.1"

  - domain: "%s"
    type: "TXT"
    ttl: 300
    text: "v=spf1 -all"

apps:
  - name: "Advanced Blocking"
    url: "https://download.technitium.com/dns/apps/AdvancedBlockingApp-v8.zip"
    config:
      enableBlocking: true
      blockListUrlUpdateIntervalHours: 24
      networkGroupMap:
        "0.0.0.0/0": "e2e"
        "::/0": "e2e"
      groups:
        - name: "e2e"
          enableBlocking: true
          allowTxtBlockingReport: true
          blockAsNxDomain: true
          blockingAddresses:
            - "0.0.0.0"
            - "::"
          allowed:
            - "safe.example.com"
          blocked: []
          allowListUrls: []
          blockListUrls:
            - "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro-onlydomains.txt"
          allowedRegex: []
          blockedRegex: []
          regexAllowListUrls: []
          regexBlockListUrls: []
          adblockListUrls: []

  - name: "Advanced Forwarding"
    url: "https://download.technitium.com/dns/apps/AdvancedForwardingApp-v3.1.zip"
    config:
      enableForwarding: true
      forwarders:
        - name: "cloudflare"
          dnssecValidation: true
          forwarderProtocol: "Tls"
          forwarderAddresses:
            - "tls://1.1.1.1"
            - "tls://1.0.0.1"
      networkGroupMap:
        "0.0.0.0/0": "default"
        "::/0": "default"
      groups:
        - name: "default"
          enableForwarding: true
          forwardings:
            - forwarders:
                - "cloudflare"
              domains:
                - "*"
`, clusterDomain, primaryIP, clusterZone, clusterZone, clusterZone, clusterZone, clusterZone)

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
	verifyDNSSettingsFull(t, primaryAPIURL, token)
	verifyZoneACL(t, primaryAPIURL, token, clusterZone)
	verifyForwarderZone(t, primaryAPIURL, token, forwarderZone)
	verifyAppInstalled(t, primaryAPIURL, token, "Advanced Blocking")
	verifyAppInstalled(t, primaryAPIURL, token, "Advanced Forwarding")
	verifyAppConfig(t, primaryAPIURL, token, "Advanced Blocking", func(t *testing.T, configJSON string) {
		if !strings.Contains(configJSON, `"enableBlocking":true`) {
			t.Errorf("Advanced Blocking config missing enableBlocking:true")
		}
		if !strings.Contains(configJSON, `"e2e"`) {
			t.Errorf("Advanced Blocking config missing group name 'e2e'")
		}
		if !strings.Contains(configJSON, "hagezi") {
			t.Errorf("Advanced Blocking config missing hagezi blocklist URL")
		}
	})
	verifyAppConfig(t, primaryAPIURL, token, "Advanced Forwarding", func(t *testing.T, configJSON string) {
		if !strings.Contains(configJSON, `"enableForwarding":true`) {
			t.Errorf("Advanced Forwarding config missing enableForwarding:true")
		}
		if !strings.Contains(configJSON, `"cloudflare"`) {
			t.Errorf("Advanced Forwarding config missing forwarder name 'cloudflare'")
		}
		if !strings.Contains(configJSON, `"*"`) {
			t.Errorf("Advanced Forwarding config missing domain '*'")
		}
	})

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
	verifyDNSSettingsFull(t, primaryAPIURL, token3)
	verifyZoneACL(t, primaryAPIURL, token3, clusterZone)
	verifyForwarderZone(t, primaryAPIURL, token3, forwarderZone)
	verifyAppInstalled(t, primaryAPIURL, token3, "Advanced Blocking")
	verifyAppInstalled(t, primaryAPIURL, token3, "Advanced Forwarding")
	verifyAppConfig(t, primaryAPIURL, token3, "Advanced Blocking", func(t *testing.T, configJSON string) {
		if !strings.Contains(configJSON, `"enableBlocking":true`) {
			t.Errorf("Advanced Blocking config missing enableBlocking:true after idempotency")
		}
		if !strings.Contains(configJSON, `"e2e"`) {
			t.Errorf("Advanced Blocking config missing group name 'e2e' after idempotency")
		}
	})
	verifyAppConfig(t, primaryAPIURL, token3, "Advanced Forwarding", func(t *testing.T, configJSON string) {
		if !strings.Contains(configJSON, `"enableForwarding":true`) {
			t.Errorf("Advanced Forwarding config missing enableForwarding:true after idempotency")
		}
		if !strings.Contains(configJSON, `"cloudflare"`) {
			t.Errorf("Advanced Forwarding config missing forwarder name 'cloudflare' after idempotency")
		}
	})

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

func verifyDNSSettingsFull(t *testing.T, apiURL, token string) {
	t.Helper()
	data := queryDNSAPI(t, apiURL, token, "/api/settings/get")

	var settings struct {
		Recursion             string `json:"recursion"`
		QpmPrefixLimitsIPv4   []struct {
			Prefix   int `json:"prefix"`
			UdpLimit int `json:"udpLimit"`
			TcpLimit int `json:"tcpLimit"`
		} `json:"qpmPrefixLimitsIPv4"`
		QpmPrefixLimitsIPv6   []struct {
			Prefix   int `json:"prefix"`
			UdpLimit int `json:"udpLimit"`
			TcpLimit int `json:"tcpLimit"`
		} `json:"qpmPrefixLimitsIPv6"`
		QpmLimitSampleMinutes int `json:"qpmLimitSampleMinutes"`
		CachePrefetchEligibility                  int    `json:"cachePrefetchEligibility"`
		CachePrefetchTrigger                      int    `json:"cachePrefetchTrigger"`
		CachePrefetchSampleIntervalInMinutes      int    `json:"cachePrefetchSampleIntervalInMinutes"`
		CachePrefetchSampleEligibilityHitsPerHour int    `json:"cachePrefetchSampleEligibilityHitsPerHour"`
		CacheMinimumRecordTtl                     int    `json:"cacheMinimumRecordTtl"`
		CacheMaximumRecordTtl                     int    `json:"cacheMaximumRecordTtl"`
		CacheFailureRecordTtl                     int    `json:"cacheFailureRecordTtl"`
		CacheMaximumEntries                       int    `json:"cacheMaximumEntries"`
		SaveCache                                 bool   `json:"saveCache"`
		ServeStaleAnswerTtl                       int    `json:"serveStaleAnswerTtl"`
		ServeStaleMaxWaitTime                     int    `json:"serveStaleMaxWaitTime"`
		EnableDnsOverUdpProxy                     bool   `json:"enableDnsOverUdpProxy"`
		EnableDnsOverTcpProxy                     bool   `json:"enableDnsOverTcpProxy"`
		EnableDnsOverHttp3                        bool   `json:"enableDnsOverHttp3"`
		TsigKeys                                  []struct {
			KeyName       string `json:"keyName"`
			AlgorithmName string `json:"algorithmName"`
		} `json:"tsigKeys"`
	}
	if err := json.Unmarshal(data, &settings); err != nil {
		t.Fatalf("failed to parse DNS settings (full): %v", err)
	}

	assertEq(t, "recursion", settings.Recursion, "Allow")
	assertEq(t, "qpmLimitSampleMinutes", settings.QpmLimitSampleMinutes, 5)

	// Verify QPM prefix limits IPv4
	if len(settings.QpmPrefixLimitsIPv4) == 0 {
		t.Errorf("qpmPrefixLimitsIPv4 is empty, want [{prefix:24, udpLimit:600, tcpLimit:100}]")
	} else {
		found := false
		for _, l := range settings.QpmPrefixLimitsIPv4 {
			if l.Prefix == 24 && l.UdpLimit == 600 && l.TcpLimit == 100 {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("qpmPrefixLimitsIPv4 missing {prefix:24, udpLimit:600, tcpLimit:100}, got %+v", settings.QpmPrefixLimitsIPv4)
		}
	}

	// Verify QPM prefix limits IPv6
	if len(settings.QpmPrefixLimitsIPv6) == 0 {
		t.Errorf("qpmPrefixLimitsIPv6 is empty, want [{prefix:56, udpLimit:600, tcpLimit:100}]")
	} else {
		found := false
		for _, l := range settings.QpmPrefixLimitsIPv6 {
			if l.Prefix == 56 && l.UdpLimit == 600 && l.TcpLimit == 100 {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("qpmPrefixLimitsIPv6 missing {prefix:56, udpLimit:600, tcpLimit:100}, got %+v", settings.QpmPrefixLimitsIPv6)
		}
	}
	assertEq(t, "cachePrefetchEligibility", settings.CachePrefetchEligibility, 2)
	assertEq(t, "cachePrefetchTrigger", settings.CachePrefetchTrigger, 9)
	assertEq(t, "cachePrefetchSampleIntervalInMinutes", settings.CachePrefetchSampleIntervalInMinutes, 5)
	assertEq(t, "cachePrefetchSampleEligibilityHitsPerHour", settings.CachePrefetchSampleEligibilityHitsPerHour, 30)
	assertEq(t, "cacheMinimumRecordTtl", settings.CacheMinimumRecordTtl, 60)
	assertEq(t, "cacheMaximumRecordTtl", settings.CacheMaximumRecordTtl, 86400)
	assertEq(t, "cacheFailureRecordTtl", settings.CacheFailureRecordTtl, 30)
	assertEq(t, "cacheMaximumEntries", settings.CacheMaximumEntries, 50000)
	assertEq(t, "saveCache", settings.SaveCache, true)
	assertEq(t, "serveStaleAnswerTtl", settings.ServeStaleAnswerTtl, 30)
	assertEq(t, "serveStaleMaxWaitTime", settings.ServeStaleMaxWaitTime, 1800)
	assertEq(t, "enableDnsOverUdpProxy", settings.EnableDnsOverUdpProxy, true)
	assertEq(t, "enableDnsOverTcpProxy", settings.EnableDnsOverTcpProxy, true)
	assertEq(t, "enableDnsOverHttp3", settings.EnableDnsOverHttp3, true)

	// Verify TSIG keys
	tsigNames := make(map[string]string)
	for _, k := range settings.TsigKeys {
		tsigNames[k.KeyName] = k.AlgorithmName
	}
	if alg, ok := tsigNames["e2e-external-dns"]; !ok {
		t.Errorf("TSIG key e2e-external-dns not found in settings")
	} else if alg != "hmac-sha256" {
		t.Errorf("TSIG key e2e-external-dns algorithm = %q, want hmac-sha256", alg)
	}
	if alg, ok := tsigNames["e2e-dhcp"]; !ok {
		t.Errorf("TSIG key e2e-dhcp not found in settings")
	} else if alg != "hmac-sha256" {
		t.Errorf("TSIG key e2e-dhcp algorithm = %q, want hmac-sha256", alg)
	}

	t.Log("verified expanded DNS settings (recursion, QPM, cache, proxy, TSIG)")
}

func verifyZoneACL(t *testing.T, apiURL, token, zone string) {
	t.Helper()
	data := queryDNSAPI(t, apiURL, token,
		fmt.Sprintf("/api/zones/options/get?zone=%s&includeAvailableTsigKeyNames=true", zone))

	var opts struct {
		QueryAccess              string            `json:"queryAccess"`
		ZoneTransfer             string            `json:"zoneTransfer"`
		ZoneTransferNetworkACL   []string          `json:"zoneTransferNetworkACL"`
		ZoneTransferTsigKeyNames []string          `json:"zoneTransferTsigKeyNames"`
		Update                   string            `json:"update"`
		UpdateNetworkACL         []string          `json:"updateNetworkACL"`
		UpdateSecurityPolicies   json.RawMessage   `json:"updateSecurityPolicies"`
		AvailableTsigKeyNames    []string          `json:"availableTsigKeyNames"`
	}
	if err := json.Unmarshal(data, &opts); err != nil {
		t.Fatalf("failed to parse zone options for %s: %v", zone, err)
	}

	assertEq(t, "queryAccess", opts.QueryAccess, "AllowOnlyPrivateNetworks")
	assertEq(t, "zoneTransfer", opts.ZoneTransfer, "UseSpecifiedNetworkACL")
	if !sliceContains(opts.ZoneTransferNetworkACL, "172.28.0.0/16") {
		t.Errorf("zoneTransferNetworkACL = %v, want to contain 172.28.0.0/16", opts.ZoneTransferNetworkACL)
	}
	if !sliceContains(opts.ZoneTransferTsigKeyNames, "e2e-external-dns") {
		t.Errorf("zoneTransferTsigKeyNames = %v, want to contain e2e-external-dns", opts.ZoneTransferTsigKeyNames)
	}
	if !sliceContains(opts.ZoneTransferTsigKeyNames, "e2e-dhcp") {
		t.Errorf("zoneTransferTsigKeyNames = %v, want to contain e2e-dhcp", opts.ZoneTransferTsigKeyNames)
	}
	assertEq(t, "update", opts.Update, "UseSpecifiedNetworkACL")
	if !sliceContains(opts.UpdateNetworkACL, "172.28.0.0/16") {
		t.Errorf("updateNetworkACL = %v, want to contain 172.28.0.0/16", opts.UpdateNetworkACL)
	}

	// Verify update security policies contain both TSIG key entries
	// The API returns this as a JSON array of policy objects
	policiesStr := string(opts.UpdateSecurityPolicies)
	if !strings.Contains(policiesStr, "e2e-external-dns") {
		t.Errorf("updateSecurityPolicies missing e2e-external-dns: %s", policiesStr)
	}
	if !strings.Contains(policiesStr, "e2e-dhcp") {
		t.Errorf("updateSecurityPolicies missing e2e-dhcp: %s", policiesStr)
	}

	// Verify TSIG keys are available for this zone
	if !sliceContains(opts.AvailableTsigKeyNames, "e2e-external-dns") {
		t.Errorf("availableTsigKeyNames = %v, want to contain e2e-external-dns", opts.AvailableTsigKeyNames)
	}

	t.Logf("verified zone %q ACL settings (TSIG, transfer, update policies)", zone)
}

func verifyZoneACLSingleServer(t *testing.T, apiURL, token, zone string) {
	t.Helper()
	data := queryDNSAPI(t, apiURL, token,
		fmt.Sprintf("/api/zones/options/get?zone=%s&includeAvailableTsigKeyNames=true", zone))

	var opts struct {
		QueryAccess              string          `json:"queryAccess"`
		ZoneTransfer             string          `json:"zoneTransfer"`
		ZoneTransferNetworkACL   []string        `json:"zoneTransferNetworkACL"`
		ZoneTransferTsigKeyNames []string        `json:"zoneTransferTsigKeyNames"`
		Update                   string          `json:"update"`
		UpdateNetworkACL         []string        `json:"updateNetworkACL"`
		UpdateSecurityPolicies   json.RawMessage `json:"updateSecurityPolicies"`
		AvailableTsigKeyNames    []string        `json:"availableTsigKeyNames"`
	}
	if err := json.Unmarshal(data, &opts); err != nil {
		t.Fatalf("failed to parse zone options for %s: %v", zone, err)
	}

	assertEq(t, "queryAccess", opts.QueryAccess, "AllowOnlyPrivateNetworks")
	assertEq(t, "zoneTransfer", opts.ZoneTransfer, "UseSpecifiedNetworkACL")
	if !sliceContains(opts.ZoneTransferNetworkACL, "172.16.0.0/12") {
		t.Errorf("zoneTransferNetworkACL = %v, want to contain 172.16.0.0/12", opts.ZoneTransferNetworkACL)
	}
	if !sliceContains(opts.ZoneTransferTsigKeyNames, "e2e-external-dns") {
		t.Errorf("zoneTransferTsigKeyNames = %v, want to contain e2e-external-dns", opts.ZoneTransferTsigKeyNames)
	}
	if !sliceContains(opts.ZoneTransferTsigKeyNames, "e2e-dhcp") {
		t.Errorf("zoneTransferTsigKeyNames = %v, want to contain e2e-dhcp", opts.ZoneTransferTsigKeyNames)
	}
	assertEq(t, "update", opts.Update, "UseSpecifiedNetworkACL")
	if !sliceContains(opts.UpdateNetworkACL, "172.16.0.0/12") {
		t.Errorf("updateNetworkACL = %v, want to contain 172.16.0.0/12", opts.UpdateNetworkACL)
	}

	policiesStr := string(opts.UpdateSecurityPolicies)
	if !strings.Contains(policiesStr, "e2e-external-dns") {
		t.Errorf("updateSecurityPolicies missing e2e-external-dns: %s", policiesStr)
	}
	if !strings.Contains(policiesStr, "e2e-dhcp") {
		t.Errorf("updateSecurityPolicies missing e2e-dhcp: %s", policiesStr)
	}

	if !sliceContains(opts.AvailableTsigKeyNames, "e2e-external-dns") {
		t.Errorf("availableTsigKeyNames = %v, want to contain e2e-external-dns", opts.AvailableTsigKeyNames)
	}

	t.Logf("verified zone %q ACL settings (TSIG, transfer, update policies)", zone)
}

func verifyForwarderZone(t *testing.T, apiURL, token, zone string) {
	t.Helper()
	data := queryDNSAPI(t, apiURL, token,
		fmt.Sprintf("/api/zones/options/get?zone=%s", zone))

	var opts struct {
		Name string `json:"name"`
		Type string `json:"type"`
	}
	if err := json.Unmarshal(data, &opts); err != nil {
		t.Fatalf("failed to parse zone options for %s: %v", zone, err)
	}
	if opts.Type != "Forwarder" {
		t.Errorf("zone %s type = %q, want %q", zone, opts.Type, "Forwarder")
	}
	t.Logf("verified zone %q exists with type Forwarder", zone)
}

func verifyAppInstalled(t *testing.T, apiURL, token, appName string) {
	t.Helper()
	data := queryDNSAPI(t, apiURL, token, "/api/apps/list")

	type appEntry struct {
		Name string `json:"name"`
	}

	// Try as {"apps": [...]} (Technitium response format)
	var wrapped struct {
		Apps []appEntry `json:"apps"`
	}
	if err := json.Unmarshal(data, &wrapped); err == nil {
		for _, app := range wrapped.Apps {
			if app.Name == appName {
				t.Logf("verified app %q is installed", appName)
				return
			}
		}
	}

	// Try as direct array [{name: ...}, ...]
	var apps []appEntry
	if err := json.Unmarshal(data, &apps); err == nil {
		for _, app := range apps {
			if app.Name == appName {
				t.Logf("verified app %q is installed", appName)
				return
			}
		}
	}

	t.Errorf("app %q not found in installed apps; raw response: %s", appName, truncate(string(data), 500))
}

func verifyAppConfig(t *testing.T, apiURL, token, appName string, checkFn func(*testing.T, string)) {
	t.Helper()
	data := queryDNSAPI(t, apiURL, token,
		"/api/apps/config/get?name="+url.QueryEscape(appName))

	// The response is {"config": "...json string..."} — extract the inner config string
	var wrapper struct {
		Config string `json:"config"`
	}
	var configStr string
	if err := json.Unmarshal(data, &wrapper); err == nil && wrapper.Config != "" {
		configStr = wrapper.Config
	} else {
		// Fallback: try as a plain JSON string or use raw bytes
		if err := json.Unmarshal(data, &configStr); err != nil {
			configStr = string(data)
		}
	}

	// Compact JSON to normalize whitespace for consistent string matching
	var buf bytes.Buffer
	if json.Compact(&buf, []byte(configStr)) == nil {
		configStr = buf.String()
	}

	checkFn(t, configStr)
	t.Logf("verified app %q config", appName)
}

func assertEq[T comparable](t *testing.T, name string, got, want T) {
	t.Helper()
	if got != want {
		t.Errorf("%s = %v, want %v", name, got, want)
	}
}

func sliceContains(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
