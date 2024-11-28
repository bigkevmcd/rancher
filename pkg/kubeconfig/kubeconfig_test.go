package kubeconfig

import (
	"testing"

	managementv3 "github.com/rancher/rancher/pkg/client/generated/management/v3"
	mgmtv3 "github.com/rancher/rancher/pkg/generated/norman/management.cattle.io/v3"
	"github.com/stretchr/testify/require"
)

func TestForClusterTokenBased(t *testing.T) {
	nodes := []*mgmtv3.Node{newNode()}
	cluster := newCluster()
	output, err := ForClusterTokenBased(cluster, nodes, "test-cluster", "host1.example.com", "test-token")
	require.NoError(t, err)

	want := `apiVersion: v1
kind: Config
clusters:
- name: "test-cluster"
  cluster:
    server: "https://host1.example.com/k8s/clusters/test-cluster"

users:
- name: "test-cluster"
  user:
    token: "test-token"


contexts:
- name: "test-cluster"
  context:
    user: "test-cluster"
    cluster: "test-cluster"

current-context: "test-cluster"
`
	require.Equal(t, want, output)
}

func TestForClusterTokenBasedWithACE(t *testing.T) {
	nodes := []*mgmtv3.Node{newNode()}
	cluster := newCluster(withLocalClusterEndpoint("https://hosts.example.com"))
	output, err := ForClusterTokenBased(cluster, nodes, "test-cluster", "host1.example.com", "test-token")
	require.NoError(t, err)

	want := `apiVersion: v1
kind: Config
clusters:
- name: "test-cluster"
  cluster:
    server: "https://host1.example.com/k8s/clusters/test-cluster"
- name: "test-cluster-fqdn"
  cluster:
    server: "https://https://hosts.example.com"

users:
- name: "test-cluster"
  user:
    token: "test-token"


contexts:
- name: "test-cluster"
  context:
    user: "test-cluster"
    cluster: "test-cluster"
- name: "test-cluster-fqdn"
  context:
    user: "test-cluster"
    cluster: "test-cluster-fqdn"

current-context: "test-cluster"
`
	require.Equal(t, want, output)
}

func withLocalClusterEndpoint(s string) func(*managementv3.Cluster) {
	return func(c *managementv3.Cluster) {
		c.LocalClusterAuthEndpoint.FQDN = s
	}
}

func newCluster(opts ...func(*managementv3.Cluster)) *managementv3.Cluster {
	c := &managementv3.Cluster{
		LocalClusterAuthEndpoint: &managementv3.LocalClusterAuthEndpoint{},
	}
	for _, opt := range opts {
		opt(c)
	}

	return c
}

func newNode() *mgmtv3.Node {
	return &mgmtv3.Node{}
}
