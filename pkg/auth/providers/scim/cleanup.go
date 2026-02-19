package scim

import (
	"fmt"

	wcorev1 "github.com/rancher/wrangler/v3/pkg/generated/controllers/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

func CleanupSecrets(secrets wcorev1.SecretController, provider string) error {
	labelSet := labels.Set{
		secretKindLabel:   scimAuthToken,
		authProviderLabel: provider,
	}

	if err := secrets.DeleteCollection(tokenSecretNamespace, metav1.DeleteOptions{}, metav1.ListOptions{LabelSelector: labelSet.AsSelector().String()}); err != nil {
		return fmt.Errorf("scim::Cleanup: failed to list token secrets for provider %s: %w", provider, err)
	}

	return nil
}
