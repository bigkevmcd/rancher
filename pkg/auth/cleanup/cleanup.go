package cleanup

import (
	"errors"

	"github.com/rancher/rancher/pkg/auth/api/secrets"
	"github.com/rancher/rancher/pkg/auth/providers/oidc"
	wcorev1 "github.com/rancher/wrangler/v3/pkg/generated/controllers/core/v1"
	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

var cleanupProviders = []string{"genericoidc", "cognito"}

const cleanedUpSecretsAnnotation = "auth.cattle.io/unused-secrets-cleaned"

type genericClient interface {
	Get(name string, opts metav1.GetOptions) (runtime.Object, error)
	Update(name string, o runtime.Object) (runtime.Object, error)
}

// CleanupUnusedSecretTokens removes tokens from the cattle-system namespace that have
// been removed from the PerUserCacheProviders.
//
// The AuthConfig is annotated to indicate that the secrets have been cleaned.
func CleanupUnusedSecretTokens(secretsInterface wcorev1.SecretController, authConfigs genericClient) (cleanupErr error) {
	for _, name := range cleanupProviders {
		authConfig, err := oidc.GetOIDCConfig(name, authConfigs, nil)
		if err != nil {
			logrus.Errorf("getting AuthConfig %s: %s", name, err)
			cleanupErr = errors.Join(cleanupErr, err)
			continue
		}

		if val := authConfig.Annotations[cleanedUpSecretsAnnotation]; val == "true" {
			continue
		}

		logrus.Infof("Cleaning unused tokens from provider %s", name)
		if err := secrets.CleanupOAuthTokens(secretsInterface, name); err != nil {
			cleanupErr = errors.Join(cleanupErr, err)
			continue
		}

		authConfig = authConfig.DeepCopy()
		if authConfig.Annotations == nil {
			authConfig.Annotations = map[string]string{}
		}

		authConfig.Annotations[cleanedUpSecretsAnnotation] = "true"
		if _, err := authConfigs.Update(name, authConfig); err != nil {
			cleanupErr = errors.Join(cleanupErr, err)
		}
	}

	return
}
