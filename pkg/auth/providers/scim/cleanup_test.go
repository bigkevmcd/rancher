package scim

import (
	"errors"
	"testing"

	"github.com/rancher/wrangler/v3/pkg/generic/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

func TestCleanupSecrets(t *testing.T) {
	ctrl := gomock.NewController(t)
	provider := "okta"

	wantSelector := labels.Set{
		secretKindLabel:   scimAuthToken,
		authProviderLabel: provider,
	}.AsSelector()

	t.Run("deleting all labeled secrets", func(t *testing.T) {
		secrets := fake.NewMockControllerInterface[*v1.Secret, *v1.SecretList](ctrl)
		secrets.EXPECT().DeleteCollection(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(func(namespace string, deleteOpts metav1.DeleteOptions, opts metav1.ListOptions) error {
			assert.Equal(t, tokenSecretNamespace, namespace)
			assert.Equal(t, wantSelector.String(), opts.LabelSelector)

			return nil
		}).Times(1)

		err := CleanupSecrets(secrets, provider)
		require.NoError(t, err)
	})

	t.Run("delete collection fails", func(t *testing.T) {
		secrets := fake.NewMockControllerInterface[*v1.Secret, *v1.SecretList](ctrl)
		secrets.EXPECT().DeleteCollection(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(func(namespace string, deleteOpts metav1.DeleteOptions, opts metav1.ListOptions) error {
			assert.Equal(t, tokenSecretNamespace, namespace)
			assert.Equal(t, wantSelector.String(), opts.LabelSelector)

			return errors.New("permission denied")
		}).Times(1)

		err := CleanupSecrets(secrets, provider)
		require.Error(t, err)
		assert.ErrorContains(t, err, "permission denied")
	})
}
