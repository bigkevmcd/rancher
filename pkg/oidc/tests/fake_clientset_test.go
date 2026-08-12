package tests

import (
	"reflect"
	"testing"

	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/rancher/pkg/client/versioned/fake"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestCreatingAClient(t *testing.T) {
	fcs := fake.NewSimpleClientset()
	oidcClient := &v3.OIDCClient{
		ObjectMeta: metav1.ObjectMeta{
			Name: "testing-oidc-client",
		},
	}
	created, err := fcs.ManagementV3().OIDCClients().Create(t.Context(), oidcClient, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	queried, err := fcs.ManagementV3().OIDCClients().Get(t.Context(), "testing-oidc-client", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(queried, created) {
		t.Fatalf("failed to get OIDC Client, got %v, want %v", queried, created)
	}
}
