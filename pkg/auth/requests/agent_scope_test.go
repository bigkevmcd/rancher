package requests

import (
	"net/http"
	"net/http/httptest"
	"testing"

	ext "github.com/rancher/rancher/pkg/apis/ext.cattle.io/v1"
	"github.com/stretchr/testify/assert"
)

func rule(verbs, groups, resources []string) ext.TokenAgentRule {
	return ext.TokenAgentRule{Verbs: verbs, APIGroups: groups, Resources: resources}
}

func TestAgentScopeCheck(t *testing.T) {
	readPods := &ext.TokenAgent{Name: "reader", Rules: []ext.TokenAgentRule{
		rule([]string{"get", "list"}, []string{""}, []string{"pods"}),
	}}
	deployments := &ext.TokenAgent{Name: "deployer", Rules: []ext.TokenAgentRule{
		rule([]string{"get", "list", "watch", "patch", "update"}, []string{"apps"}, []string{"deployments"}),
	}}
	logs := &ext.TokenAgent{Name: "logs", Rules: []ext.TokenAgentRule{
		rule([]string{"get"}, []string{""}, []string{"pods/log"}),
	}}
	multi := &ext.TokenAgent{Name: "multi", Rules: []ext.TokenAgentRule{
		rule([]string{"get"}, []string{""}, []string{"pods"}),
		rule([]string{"list"}, []string{""}, []string{"pods"}),
	}}
	everything := &ext.TokenAgent{Name: "all", Rules: []ext.TokenAgentRule{
		rule([]string{"*"}, []string{"*"}, []string{"*"}),
	}}
	crd := &ext.TokenAgent{Name: "crd", Rules: []ext.TokenAgentRule{
		rule([]string{"get", "list"}, []string{"management.cattle.io"}, []string{"clusters"}),
	}}

	tests := []struct {
		name    string
		agent   *ext.TokenAgent
		method  string
		url     string
		allowed bool
	}{
		// Kubernetes API.
		{"k8s list allowed", readPods, "GET", "/api/v1/namespaces/default/pods", true},
		{"k8s get allowed", readPods, "GET", "/api/v1/namespaces/default/pods/p1", true},
		{"k8s all namespaces list", readPods, "GET", "/api/v1/pods", true},
		{"k8s delete denied", readPods, "DELETE", "/api/v1/namespaces/default/pods/p1", false},
		{"k8s create denied", readPods, "POST", "/api/v1/namespaces/default/pods", false},
		{"k8s other resource denied", readPods, "GET", "/api/v1/namespaces/default/secrets", false},
		{"k8s other group denied", readPods, "GET", "/apis/apps/v1/namespaces/default/deployments", false},
		{"k8s subresource not implied by resource", readPods, "GET", "/api/v1/namespaces/default/pods/p1/log", false},
		{"k8s subresource allowed explicitly", logs, "GET", "/api/v1/namespaces/default/pods/p1/log", true},
		{"k8s exec denied", readPods, "POST", "/api/v1/namespaces/default/pods/p1/exec", false},
		{"k8s group resource allowed", deployments, "PATCH", "/apis/apps/v1/namespaces/default/deployments/d1", true},
		{"k8s watch needs watch verb", readPods, "GET", "/api/v1/namespaces/default/pods?watch=true", false},
		{"k8s watch allowed with watch verb", deployments, "GET", "/apis/apps/v1/namespaces/default/deployments?watch=true", true},
		{"k8s non-resource denied", everything, "GET", "/api/", false},
		{"k8s wildcard rule allows", everything, "DELETE", "/apis/apps/v1/namespaces/default/deployments/d1", true},

		// Proxied to a downstream cluster.
		{"cluster proxy k8s list allowed", readPods, "GET", "/k8s/clusters/c-m-abc/api/v1/namespaces/default/pods", true},
		{"cluster proxy k8s denied", readPods, "DELETE", "/k8s/clusters/c-m-abc/api/v1/namespaces/default/pods/p1", false},
		{"cluster proxy steve list allowed", readPods, "GET", "/k8s/clusters/c-m-abc/v1/pods", true},
		{"cluster proxy steve denied", readPods, "GET", "/k8s/clusters/c-m-abc/v1/secrets", false},
		{"cluster proxy to something else denied", everything, "GET", "/k8s/clusters/c-m-abc/healthz", false},
		{"cluster proxy path trick", readPods, "GET", "/k8s/clusters/c-m-abc/../../v3/users", false},

		// Steve API.
		{"steve list allowed", readPods, "GET", "/v1/pods", true},
		{"steve get needs get and list", readPods, "GET", "/v1/pods/default/p1", true},
		{"steve get denied without list", logs, "GET", "/v1/pods/default/p1", false},
		{"steve get denied when only get is allowed", &ext.TokenAgent{Name: "g", Rules: []ext.TokenAgentRule{
			rule([]string{"get"}, []string{""}, []string{"pods"})}}, "GET", "/v1/pods/default/p1", false},
		{"steve get allowed across rules", multi, "GET", "/v1/pods/default/p1", true},
		{"steve group resource", deployments, "GET", "/v1/apps.deployments", true},
		{"steve group with dots", crd, "GET", "/v1/management.cattle.io.clusters", true},
		{"steve group with dots denied", crd, "GET", "/v1/management.cattle.io.users", false},
		{"steve other group denied", readPods, "GET", "/v1/apps.deployments", false},
		{"steve create denied", readPods, "POST", "/v1/pods", false},
		{"steve create allowed", &ext.TokenAgent{Name: "c", Rules: []ext.TokenAgentRule{
			rule([]string{"create"}, []string{""}, []string{"configmaps"})}}, "POST", "/v1/configmaps", true},
		{"steve update allowed", deployments, "PUT", "/v1/apps.deployments/default/d1", true},
		{"steve patch allowed", deployments, "PATCH", "/v1/apps.deployments/default/d1", true},
		{"steve delete denied", deployments, "DELETE", "/v1/apps.deployments/default/d1", false},
		{"steve collection delete denied even with wildcard", everything, "DELETE", "/v1/pods", false},
		{"steve post to a resource denied", everything, "POST", "/v1/pods/default/p1", false},
		{"steve action denied even with wildcard", everything, "POST", "/v1/apps.deployments/default/d1?action=rollback", false},
		{"steve link denied even with wildcard", everything, "GET", "/v1/pods/default/p1?link=log", false},
		{"steve schemas denied", everything, "GET", "/v1/schemas", false},
		{"steve subscribe denied", everything, "GET", "/v1/subscribe", false},
		{"steve watch needs watch", readPods, "GET", "/v1/pods?watch=true", false},
		{"steve unsupported method", everything, "HEAD", "/v1/pods", false},
		{"steve empty type", everything, "GET", "/v1/", false},

		// Everything else is denied, even with a wildcard rule.
		{"norman denied", everything, "GET", "/v3/users", false},
		{"norman clusters denied", everything, "GET", "/v3/clusters", false},
		{"public api denied", everything, "GET", "/v3-public/authProviders", false},
		{"login denied", everything, "POST", "/v3-public/localProviders/local?action=login", false},
		{"ext api denied", everything, "GET", "/ext/apis/ext.cattle.io/v1/tokens", false},
		{"root denied", everything, "GET", "/", false},
		{"similar prefix denied", everything, "GET", "/v1-public/x", false},
		{"similar prefix denied 2", everything, "GET", "/apis", false},

		// Degenerate tokens.
		{"no agent", nil, "GET", "/v1/pods", false},
		{"no rules", &ext.TokenAgent{Name: "x"}, "GET", "/v1/pods", false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(test.method, test.url, nil)
			err := agentScopeCheck(req, test.agent)
			if test.allowed {
				assert.NoError(t, err)
				return
			}
			assert.Error(t, err)
			assert.ErrorAs(t, err, &errAgentScope{})
		})
	}
}

// The path in the request, not anything the caller can set in a header, decides.
func TestAgentScopeCheckIgnoresHeaders(t *testing.T) {
	agent := &ext.TokenAgent{Name: "a", Rules: []ext.TokenAgentRule{
		rule([]string{"get", "list"}, []string{""}, []string{"pods"}),
	}}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/namespaces/default/secrets", nil)
	req.Header.Set("X-HTTP-Method-Override", "GET")
	req.Header.Set("X-Original-URL", "/api/v1/pods")
	req.Header.Set("X-Forwarded-Prefix", "/api/v1/pods")
	assert.Error(t, agentScopeCheck(req, agent))
}
