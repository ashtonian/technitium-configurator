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
	verifyRecordExists(t, apiURL, token, "www."+zoneName, "A")
	verifyRecordExists(t, apiURL, token, zoneName, "MX")
	verifyRecordExists(t, apiURL, token, zoneName, "TXT")
	verifyRecordExists(t, apiURL, token, "alias."+zoneName, "CNAME")
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
	verifyRecordExists(t, apiURL, token2, "www."+zoneName, "A")
	verifyRecordExists(t, apiURL, token2, zoneName, "MX")
	verifyRecordExists(t, apiURL, token2, zoneName, "TXT")
	verifyRecordExists(t, apiURL, token2, "alias."+zoneName, "CNAME")
	verifyDNSSetting(t, apiURL, token2, zoneName)
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

func verifyRecordExists(t *testing.T, apiURL, token, domain, recordType string) {
	t.Helper()
	data := queryDNSAPI(t, apiURL, token,
		fmt.Sprintf("/api/zones/records/get?domain=%s&zone=%s", domain, zoneName))

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
			t.Logf("verified record %s/%s exists", domain, recordType)
			return
		}
	}
	t.Errorf("record %s/%s not found in zone %s", domain, recordType, zoneName)
}

func verifyDNSSetting(t *testing.T, apiURL, token, expectedDomain string) {
	t.Helper()
	data := queryDNSAPI(t, apiURL, token, "/api/settings/get")

	var settings struct {
		DnsServerDomain string `json:"dnsServerDomain"`
	}
	if err := json.Unmarshal(data, &settings); err != nil {
		t.Fatalf("failed to parse DNS settings: %v", err)
	}
	if settings.DnsServerDomain != expectedDomain {
		t.Errorf("DNS server domain = %q, want %q", settings.DnsServerDomain, expectedDomain)
	}
	t.Logf("verified DNS settings domain = %q", settings.DnsServerDomain)
}
