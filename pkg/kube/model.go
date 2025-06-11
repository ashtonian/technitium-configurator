package kube

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/retry"
)

var (
	k8sClientOnce sync.Once
	k8sClient     *K8sClient
	k8sInitErr    error
)

// ErrTokenNotFound signals that the key exists neither in `.data` nor in `.stringData`.
var ErrTokenNotFound = fmt.Errorf("token key not found or empty")

// K8sClient is a thin wrapper around client-go’s Clientset.
type K8sClient struct {
	clientset *kubernetes.Clientset
}

// NewK8sClient returns a singleton client or panics if the cluster
// configuration cannot be resolved.
func NewK8sClient() (*K8sClient, error) {
	k8sClientOnce.Do(func() {
		cfg, err := loadKubeConfig()
		if err != nil {
			k8sInitErr = fmt.Errorf("cannot build Kubernetes config: %w", err)
			return
		}

		cs, err := kubernetes.NewForConfig(cfg)
		if err != nil {
			k8sInitErr = fmt.Errorf("cannot create Kubernetes clientset: %w", err)
			return
		}

		k8sClient = &K8sClient{clientset: cs}
	})

	return k8sClient, k8sInitErr
}

// loadKubeConfig tries in-cluster, then falls back to the full kubeconfig-merge
// logic (KUBECONFIG env, $HOME/.kube/config, etc.).
func loadKubeConfig() (*rest.Config, error) {
	// 1. In-cluster
	if cfg, err := rest.InClusterConfig(); err == nil {
		return cfg, nil
	}

	// 2. Kubeconfig loading rules
	rules := clientcmd.NewDefaultClientConfigLoadingRules() // KUBECONFIG + default path
	overrides := &clientcmd.ConfigOverrides{}
	return clientcmd.
		NewNonInteractiveDeferredLoadingClientConfig(rules, overrides).
		ClientConfig()
}

// GetSecret fetches a Secret.
func (k *K8sClient) GetSecret(ctx context.Context, namespace, name string) (*corev1.Secret, error) {
	return k.clientset.CoreV1().Secrets(namespace).Get(ctx, name, metav1.GetOptions{})
}

// CreateOrUpdateSecret creates a Secret or updates an existing one.
// On update it retries on optimistic-lock conflicts.
func (k *K8sClient) CreateOrUpdateSecret(ctx context.Context, ns, name, key, value string) error {
	//
	_, err := k.GetSecret(ctx, ns, name)
	switch {
	case err == nil:

		return retry.RetryOnConflict(retry.DefaultBackoff, func() error {

			cur, gErr := k.GetSecret(ctx, ns, name)
			if gErr != nil {
				return gErr
			}
			if cur.Data == nil {
				cur.Data = map[string][]byte{}
			}
			cur.Data[key] = []byte(value)

			_, uErr := k.clientset.CoreV1().Secrets(ns).Update(ctx, cur, metav1.UpdateOptions{})
			if uErr == nil {
				slog.Info("updated secret", "namespace", ns, "name", name)
			}
			return uErr
		})

	case errors.IsNotFound(err):

		sec := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: ns,
			},
			Type:       corev1.SecretTypeOpaque,
			StringData: map[string]string{key: value},
		}
		if _, cErr := k.clientset.CoreV1().Secrets(ns).Create(ctx, sec, metav1.CreateOptions{}); cErr != nil {
			return fmt.Errorf("create secret %s/%s: %w", ns, name, cErr)
		}
		slog.Info("created secret", "namespace", ns, "name", name)
		return nil

	default:
		return fmt.Errorf("get secret %s/%s: %w", ns, name, err)
	}
}

// CheckSecretToken returns the token value or ErrTokenNotFound.
func (k *K8sClient) CheckSecretToken(ctx context.Context, ns, name, key string) (string, error) {
	sec, err := k.GetSecret(ctx, ns, name)
	if err != nil {
		return "", err
	}

	if b, ok := sec.Data[key]; ok && len(b) > 0 {
		return string(b), nil
	}
	if s, ok := sec.StringData[key]; ok && len(s) > 0 {
		return s, nil
	}

	return "", ErrTokenNotFound
}

// NotFound wraps IsNotFound for callers that need a terse predicate.
func NotFound(err error) bool { return errors.IsNotFound(err) }

// TokenNotFound returns true when err == ErrTokenNotFound.
func TokenNotFound(err error) bool { return err == ErrTokenNotFound }

// ResourceRef is a shorthand for constructing the GroupResource needed by
// apierrors.NewNotFound, e.g. ResourceRef("secret").
func ResourceRef(resource string) schema.GroupResource {
	return schema.GroupResource{Group: "", Resource: resource}
}
