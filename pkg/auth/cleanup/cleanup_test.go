package cleanup

import (
	"errors"
	"fmt"
	"testing"

	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/rancher/pkg/auth/tokens"
	v1 "github.com/rancher/rancher/pkg/generated/norman/core/v1"
	"go.uber.org/mock/gomock"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
)

func TestCleanupUnusedSecretTokens(t *testing.T) {
	secretStore := map[string]*v1.Secret{
		"cattle-system:test-secret-1": {
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-secret-1",
				Namespace: tokens.SecretNamespace,
			},
			Type: corev1.SecretTypeOpaque,
			Data: map[string][]byte{
				"genericoidc": []byte("my user token"),
			},
		},
		"cattle-system:test-secret-2": {
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-secret-2",
				Namespace: tokens.SecretNamespace,
			},
			Type: corev1.SecretTypeOpaque,
			Data: map[string][]byte{
				"cognito": []byte("my user token"),
			},
		},
	}
	ctrl := gomock.NewController(t)
	fakeClient := newFakeGenericClient(t,
		&v3.AuthConfig{ObjectMeta: metav1.ObjectMeta{Name: "genericoidc"}},
		&v3.AuthConfig{ObjectMeta: metav1.ObjectMeta{Name: "cognito"}})

	if err := CleanupUnusedSecretTokens(getSecretControllerMock(ctrl, secretStore), fakeClient); err != nil {
		t.Fatal(err)
	}

	if len(secretStore) != 0 {
		t.Errorf("failed to delete secrets: %#v", secretStore)
	}

	for _, provider := range cleanupProviders {
		if ann := fakeClient.updated[provider].GetAnnotations(); ann[cleanedUpSecretsAnnotation] != "true" {
			t.Errorf("didn't update the annotations: %#v", ann)
		}
	}
}

func TestCleanupUnusedSecretTokensHandlesErrors(t *testing.T) {
	secretStore := map[string]*v1.Secret{
		"cattle-system:test-secret-1": {
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-secret-1",
				Namespace: tokens.SecretNamespace,
			},
			Type: corev1.SecretTypeOpaque,
			Data: map[string][]byte{
				"genericoidc": []byte("my user token"),
			},
		},
	}
	fakeClient := newFakeGenericClient(t,
		&v3.AuthConfig{ObjectMeta: metav1.ObjectMeta{Name: "cognito"}},
		&v3.AuthConfig{ObjectMeta: metav1.ObjectMeta{Name: "genericoidc", Annotations: map[string]string{"fail": "true"}}})

	ctrl := gomock.NewController(t)
	err := CleanupUnusedSecretTokens(getSecretControllerMock(ctrl, secretStore), fakeClient)
	if msg := err.Error(); msg != "test error" {
		t.Fatalf("got error %v", err)
	}

	if len(secretStore) != 0 {
		t.Errorf("failed to delete secrets: %#v", secretStore)
	}

	for _, provider := range cleanupProviders {
		// Only the non-erroring configs should be updated
		if fakeClient.objects[provider].GetAnnotations()["fail"] == "true" {
			if fakeClient.updated["provider"] != nil {
				t.Errorf("updated a provider that failed: %s", provider)
			}
		} else {
			if ann := fakeClient.updated[provider].GetAnnotations(); ann[cleanedUpSecretsAnnotation] != "true" {
				t.Errorf("didn't update the annotations: %#v", ann)
			}
		}
	}
}

func TestCleanupUnusedSecretTokensAlreadyAnnotated(t *testing.T) {
	secretStore := map[string]*v1.Secret{
		"cattle-system:test-secret-1": {
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-secret-1",
				Namespace: tokens.SecretNamespace,
			},
			Type: corev1.SecretTypeOpaque,
			Data: map[string][]byte{
				"genericoidc": []byte("my user token"),
			},
		},
	}
	authConfigs := []*v3.AuthConfig{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:        "genericoidc",
				Annotations: map[string]string{cleanedUpSecretsAnnotation: "true"},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "cognito"},
		},
	}
	fakeClient := newFakeGenericClient(t, authConfigs...)
	ctrl := gomock.NewController(t)

	err := CleanupUnusedSecretTokens(getSecretControllerMock(ctrl, secretStore), fakeClient)
	if err != nil {
		t.Fatal(err)
	}

	if l := len(secretStore); l != 1 {
		t.Errorf("secrets were incorrectly deleted - remaining secrets = %d", l)
	}

	for _, authConfig := range authConfigs {
		if authConfig.Annotations[cleanedUpSecretsAnnotation] == "" {
			if ann := fakeClient.updated[authConfig.GetName()].Annotations; ann[cleanedUpSecretsAnnotation] != "true" {
				t.Errorf("didn't update the annotations: %#v", ann)
			}
		}
	}
}

func newFakeGenericClient(t *testing.T, configs ...*v3.AuthConfig) *fakeGenericClient {
	t.Helper()
	client := &fakeGenericClient{
		objects: map[string]*unstructured.Unstructured{},
		updated: map[string]*v3.OIDCConfig{},
	}

	for _, config := range configs {
		converted, err := runtime.DefaultUnstructuredConverter.ToUnstructured(config)
		if err != nil {
			t.Fatal(err)
		}
		client.objects[config.GetName()] = &unstructured.Unstructured{Object: converted}
	}

	return client
}

type fakeGenericClient struct {
	objects map[string]*unstructured.Unstructured
	updated map[string]*v3.OIDCConfig
}

func (m fakeGenericClient) Get(name string, opts metav1.GetOptions) (runtime.Object, error) {
	if u, ok := m.objects[name]; ok {
		return u, nil
	}

	return nil, fmt.Errorf("fake does not contain object: %s", name)
}

func (m fakeGenericClient) Update(name string, o runtime.Object) (runtime.Object, error) {
	if _, ok := m.objects[name]; ok {
		oc := o.(*v3.OIDCConfig)
		if ann := oc.GetAnnotations(); ann["fail"] == "true" {
			return nil, errors.New("test error")
		}
		m.updated[name] = oc
		return o, nil
	}

	return nil, fmt.Errorf("updating fake does not contain object: %s", name)
}
