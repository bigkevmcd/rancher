package requests

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"

	ext "github.com/rancher/rancher/pkg/apis/ext.cattle.io/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/kubernetes/plugin/pkg/auth/authorizer/rbac"
)

// clusterProxyPrefix matches the prefix of requests proxied to a cluster's API,
// capturing the rest of the path.
var clusterProxyPrefix = regexp.MustCompile(`^/k8s/clusters/[^/]+(/.*)$`)

var k8sRequestInfoFactory = &request.RequestInfoFactory{
	APIPrefixes:          sets.NewString("api", "apis"),
	GrouplessAPIPrefixes: sets.NewString("api"),
}

// errAgentScope is returned for requests an agent token is not allowed to make.
type errAgentScope struct{ reason string }

func (e errAgentScope) Error() string { return "agent token not permitted: " + e.reason }

// agentScopeCheck decides whether a request made with an agent token is within the token's
// rules. The rules limit the token; they never grant anything. What the owning user may do is
// still decided by the user's own permissions further down the request path, so the effective
// permissions are the intersection of the two.
//
// The check fails closed. Only requests that can be described as a Kubernetes resource request
// are considered: the Kubernetes API (optionally behind /k8s/clusters/<id>) and the Steve API
// (/v1, optionally behind /k8s/clusters/<id>). Anything else, e.g. the norman /v3 API, Steve's
// websocket subscriptions and resource actions or links, is denied.
func agentScopeCheck(req *http.Request, agent *ext.TokenAgent) error {
	if agent == nil || len(agent.Rules) == 0 {
		return errAgentScope{"token has no rules"}
	}

	attrs, err := agentRequestAttributes(req)
	if err != nil {
		return err
	}

	if len(attrs) == 0 {
		return errAgentScope{"request has no resource attributes"}
	}

	rules := make([]rbacv1.PolicyRule, 0, len(agent.Rules))
	for _, r := range agent.Rules {
		rules = append(rules, rbacv1.PolicyRule{Verbs: r.Verbs, APIGroups: r.APIGroups, Resources: r.Resources})
	}

	// Every verb the request may amount to has to be allowed by some rule.
	for _, a := range attrs {
		allowed := false
		for i := range rules {
			if rbac.RuleAllows(a, &rules[i]) {
				allowed = true
				break
			}
		}
		if !allowed {
			return errAgentScope{fmt.Sprintf("%s %s is not in the token's rules", a.GetVerb(), resourceName(a))}
		}
	}

	return nil
}

func resourceName(a authorizer.Attributes) string {
	name := a.GetResource()
	if a.GetAPIGroup() != "" {
		name += "." + a.GetAPIGroup()
	}
	if a.GetSubresource() != "" {
		name += "/" + a.GetSubresource()
	}
	return name
}

// agentRequestAttributes maps the request to the attributes of the resource requests it amounts to.
// There can be more than one, see steveAttributes.
func agentRequestAttributes(req *http.Request) ([]authorizer.Attributes, error) {
	path := req.URL.Path
	if m := clusterProxyPrefix.FindStringSubmatch(path); m != nil {
		path = m[1]
	}

	switch {
	case strings.HasPrefix(path, "/v1/"):
		return steveAttributes(req, strings.TrimPrefix(path, "/v1/"))
	case strings.HasPrefix(path, "/api/"), strings.HasPrefix(path, "/apis/"):
		r := req.Clone(req.Context())
		u := *req.URL
		u.Path = path
		r.URL = &u
		info, err := k8sRequestInfoFactory.NewRequestInfo(r)
		if err != nil {
			return nil, errAgentScope{"unparsable request"}
		}
		if !info.IsResourceRequest {
			return nil, errAgentScope{"not a resource request"}
		}
		return []authorizer.Attributes{authorizer.AttributesRecord{
			Verb:            info.Verb,
			APIGroup:        info.APIGroup,
			Resource:        info.Resource,
			Subresource:     info.Subresource,
			ResourceRequest: true,
		}}, nil
	}

	return nil, errAgentScope{"API not available to agent tokens"}
}

// steveAttributes maps a Steve API request, whose path after /v1/ is <type>[/<namespace>[/<name>]],
// to resource request attributes. A type is <group>.<resource>, or only <resource> for the core
// group. Group names contain dots and resources don't, so the split is at the last dot.
//
// Steve paths do not tell a namespaced from a cluster-scoped resource, so a GET with two or more
// segments could be a get or, with a namespace, a list. Both verbs are then required.
func steveAttributes(req *http.Request, path string) ([]authorizer.Attributes, error) {
	segments := strings.Split(strings.Trim(path, "/"), "/")
	resourceType := segments[0]
	if resourceType == "" || resourceType == "schemas" || resourceType == "subscribe" || strings.HasPrefix(resourceType, "meta.") {
		return nil, errAgentScope{"not a resource request"}
	}
	q := req.URL.Query()
	if q.Has("action") || q.Has("link") {
		return nil, errAgentScope{"resource actions and links are not available to agent tokens"}
	}

	var group, resource string
	if i := strings.LastIndex(resourceType, "."); i >= 0 {
		group, resource = resourceType[:i], resourceType[i+1:]
	} else {
		resource = resourceType
	}

	var verbs []string
	switch req.Method {
	case http.MethodGet:
		if len(segments) == 1 {
			verbs = []string{"list"}
		} else {
			verbs = []string{"get", "list"}
		}
		if q.Get("watch") == "true" || q.Get("watch") == "1" {
			verbs = append(verbs, "watch")
		}
	case http.MethodPost:
		if len(segments) != 1 {
			return nil, errAgentScope{"unsupported request"}
		}
		verbs = []string{"create"}
	case http.MethodPut:
		if len(segments) < 2 {
			return nil, errAgentScope{"unsupported request"}
		}
		verbs = []string{"update"}
	case http.MethodPatch:
		if len(segments) < 2 {
			return nil, errAgentScope{"unsupported request"}
		}
		verbs = []string{"patch"}
	case http.MethodDelete:
		if len(segments) < 2 {
			return nil, errAgentScope{"unsupported request"}
		}
		verbs = []string{"delete"}
	default:
		return nil, errAgentScope{"unsupported method"}
	}

	attrs := make([]authorizer.Attributes, 0, len(verbs))
	for _, verb := range verbs {
		attrs = append(attrs, authorizer.AttributesRecord{
			Verb:            verb,
			APIGroup:        group,
			Resource:        resource,
			ResourceRequest: true,
		})
	}
	return attrs, nil
}
