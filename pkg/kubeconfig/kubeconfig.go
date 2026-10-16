package kubeconfig

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"

	apiv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/rancher/pkg/auth/accessor"
	"github.com/rancher/rancher/pkg/auth/providers/common"
	clientv3 "github.com/rancher/rancher/pkg/client/generated/management/v3"
	normanv3 "github.com/rancher/rancher/pkg/generated/norman/management.cattle.io/v3"
	"github.com/rancher/rancher/pkg/node"
	"github.com/rancher/rancher/pkg/settings"
)

const (
	certDelim = "\\\n      "
	firstLen  = 49
)

var splitRegexp = regexp.MustCompile(`\S{1,76}`)

type kubeNode struct {
	ClusterName string
	Server      string
	Cert        string
	User        string
}

type data struct {
	ClusterName     string
	Host            string
	ClusterID       string
	Cert            string
	User            string
	Username        string
	Password        string
	Token           string
	EndpointEnabled bool
	Nodes           []kubeNode
	ExecUser        *ExecUser
}

// ExecUser is the Rancher user written in exec entries of a kubeconfig without a token.
// When set, exec entries run "rancher auth get-token" instead of "rancher token".
type ExecUser struct {
	ID           string
	AuthProvider string
}

// NewExecUser returns the exec entry user for the given user id who signed in with the given token.
//
// AuthProvider is set to the name of the AuthConfig the user signed in with, which may differ from
// the provider's name when several AuthConfigs share a provider. It falls back to the token's auth
// provider if the token's principal id can't be parsed.
func NewExecUser(userID string, token accessor.TokenAccessor) *ExecUser {
	configName, err := common.ConfigNameFromToken(token)
	if err != nil || configName == "" {
		configName = token.GetAuthProvider()
	}

	return &ExecUser{
		ID:           userID,
		AuthProvider: configName,
	}
}

type Cluster struct {
	Name   string
	Server string
	Cert   string
}
type User struct {
	Name      string
	Token     string
	Host      string
	ClusterID string
}

type Context struct {
	Name    string
	User    string
	Cluster string
}

type Meta struct {
	Name              string
	CreationTimestamp string
	TTL               string
}
type KubeConfig struct {
	Meta           Meta
	CACert         string
	Clusters       []Cluster
	Users          []User
	Contexts       []Context
	CurrentContext string
	ExecUser       *ExecUser
}

func FormatCertString(certData string) string {
	buf := &bytes.Buffer{}
	if len(certData) > firstLen {
		buf.WriteString(certData[:firstLen])
		certData = certData[firstLen:]
	} else {
		return certData
	}

	for _, part := range splitRegexp.FindAllStringSubmatch(certData, -1) {
		buf.WriteString(certDelim)
		buf.WriteString(part[0])
	}

	return buf.String()
}

func caCertString() string {
	certData := settings.CACerts.Get()
	if certData == "" {
		return ""
	}
	certData = base64.StdEncoding.EncodeToString([]byte(certData))
	return FormatCertString(certData)
}

func getDefaultNode(clusterName, clusterID, host string) kubeNode {
	return kubeNode{
		Server:      fmt.Sprintf("https://%s/k8s/clusters/%s", host, clusterID),
		Cert:        caCertString(),
		ClusterName: clusterName,
		User:        clusterName,
	}
}

func ForTokenBased(clusterName, clusterID, host, token string, execUser *ExecUser) (string, error) {
	data := &data{
		ClusterName:     clusterName,
		ClusterID:       clusterID,
		Host:            host,
		Cert:            caCertString(),
		User:            clusterName,
		Token:           token,
		Nodes:           []kubeNode{getDefaultNode(clusterName, clusterID, host)},
		EndpointEnabled: false,
		ExecUser:        execUser,
	}

	if data.ClusterName == "" {
		data.ClusterName = data.ClusterID
	}

	buf := &bytes.Buffer{}
	err := tokenTemplate.Execute(buf, data)
	return buf.String(), err
}

func ForClusterTokenBased(cluster *clientv3.Cluster, nodes []*normanv3.Node, clusterID, host, token string, execUser *ExecUser) (string, error) {
	clusterName := cluster.Name
	if clusterName == "" {
		clusterName = clusterID
	}

	nodesForConfig := []kubeNode{getDefaultNode(clusterName, clusterID, host)}

	if cluster.LocalClusterAuthEndpoint.FQDN != "" {
		fqdnCACerts := base64.StdEncoding.EncodeToString([]byte(cluster.LocalClusterAuthEndpoint.CACerts))
		clusterNode := kubeNode{
			ClusterName: clusterName + "-fqdn",
			Server:      "https://" + cluster.LocalClusterAuthEndpoint.FQDN,
			Cert:        FormatCertString(fqdnCACerts),
			User:        clusterName,
		}
		nodesForConfig = append(nodesForConfig, clusterNode)
	} else {
		for _, n := range nodes {
			if n.Spec.ControlPlane {
				nodeName := clusterName + "-" + strings.TrimPrefix(n.Spec.RequestedHostname, clusterName+"-")
				clusterNode := kubeNode{
					ClusterName: nodeName,
					Server:      "https://" + node.GetEndpointNodeIP(n) + ":6443",
					Cert:        FormatCertString(cluster.CACert),
					User:        clusterName,
				}
				nodesForConfig = append(nodesForConfig, clusterNode)
			}
		}
	}

	data := &data{
		ClusterName:     clusterName,
		ClusterID:       clusterID,
		Host:            host,
		Cert:            caCertString(),
		User:            clusterName,
		Token:           token,
		Nodes:           nodesForConfig,
		EndpointEnabled: true,
		ExecUser:        execUser,
	}

	buf := &bytes.Buffer{}
	err := tokenTemplate.Execute(buf, data)
	return buf.String(), err
}

type GenerateInput struct {
	Name              string
	CreationTimestamp string
	TTL               string
	Entries           []GenerateEntry
}

type GenerateEntry struct {
	ClusterID        string
	Cluster          *apiv3.Cluster
	Nodes            []*apiv3.Node
	TokenKey         string
	IsCurrentContext bool
}

func Generate(input KubeConfig) (string, error) {
	buf := &bytes.Buffer{}
	err := multiClusterTemplate.Execute(buf, input)

	return buf.String(), err
}
