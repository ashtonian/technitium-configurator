//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func testNotifySourcePolicy(t *testing.T, bin, apiURL string, port int, zone string) {
	t.Helper()
	env := envMap{
		"DNS_API_URL":  apiURL,
		"DNS_USERNAME": defaultUser,
		"DNS_PASSWORD": newPassword,
	}
	path := filepath.Join(t.TempDir(), "notify.yaml")
	for _, tc := range []struct {
		name     string
		networks string
		want     dnsmessage.RCode
	}{
		{"unrecognized", "[]", dnsmessage.RCodeRefused},
		{"trusted-network", "[172.28.0.0/16]", dnsmessage.RCodeSuccess},
		{"cleared", "[]", dnsmessage.RCodeRefused},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := "dnsSettings:\n  notifyAllowedNetworks: " + tc.networks + "\n"
			if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
				t.Fatal(err)
			}
			runConfigurator(t, bin, "configure", env, path)
			// The published port makes this request originate at the bridge,
			// outside the registered primary addresses, as during address propagation.
			if got := sendNotify(t.Context(), t, fmt.Sprintf("127.0.0.1:%d", port), zone); got != tc.want {
				t.Fatalf("NOTIFY response = %s, want %s", got, tc.want)
			}
		})
	}
}

func sendNotify(ctx context.Context, t *testing.T, address, zone string) dnsmessage.RCode {
	t.Helper()
	name, err := dnsmessage.NewName(zone + ".")
	if err != nil {
		t.Fatal(err)
	}
	request := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 53, OpCode: 4, Authoritative: true},
		Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeSOA, Class: dnsmessage.ClassINET}},
	}
	packet, err := request.Pack()
	if err != nil {
		t.Fatal(err)
	}
	dialer := net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.DialContext(ctx, "udp4", address)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(packet); err != nil {
		t.Fatal(err)
	}
	var buffer [4096]byte
	n, err := conn.Read(buffer[:])
	if err != nil {
		t.Fatal(err)
	}
	var response dnsmessage.Message
	if err := response.Unpack(buffer[:n]); err != nil {
		t.Fatal(err)
	}
	if !response.Response || response.ID != request.ID || response.OpCode != request.OpCode {
		t.Fatalf("unexpected NOTIFY response header: %+v", response.Header)
	}
	return response.RCode
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := conn.LocalAddr().(*net.UDPAddr).Port
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}
