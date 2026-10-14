package kube

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/tools/clientcmd"
)

const kubeconfig = `apiVersion: v1
kind: Config
clusters:
  - name: test
    cluster:
      server: https://127.0.0.1:6443
users:
  - name: test
    user:
      token: test
contexts:
  - name: with-namespace
    context: {cluster: test, user: test, namespace: dns}
  - name: without-namespace
    context: {cluster: test, user: test}
current-context: %s
`

func TestNewK8sClientNamespace(t *testing.T) {
	// Outside a cluster, so the pod's namespace does not apply. CI runners
	// may themselves be pods.
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	t.Setenv("POD_NAMESPACE", "")

	tests := []struct {
		context string
		want    string
	}{
		{context: "with-namespace", want: "dns"},
		{context: "without-namespace", want: "default"},
	}
	for _, tt := range tests {
		t.Run(tt.context, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "kubeconfig")
			require.NoError(t, os.WriteFile(path, []byte(fmt.Sprintf(kubeconfig, tt.context)), 0o600))

			client, err := newK8sClient(&clientcmd.ClientConfigLoadingRules{ExplicitPath: path})
			require.NoError(t, err)
			assert.Equal(t, tt.want, client.Namespace())
		})
	}
}
