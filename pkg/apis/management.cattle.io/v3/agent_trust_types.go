package v3

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// AgentRule is a restricted form of an RBAC policy rule, which limits what an agent may do. Resource
// names and non-resource URLs are not supported.
type AgentRule struct {
	// Verbs is the list of allowed verbs, e.g. get, list, watch, create, update, patch, delete.
	// "*" matches all verbs.
	// +kubebuilder:validation:MinItems=1
	Verbs []string `json:"verbs"`
	// APIGroups is the list of API groups of the allowed resources. The empty string is the core
	// group. "*" matches all groups.
	// +kubebuilder:validation:MinItems=1
	APIGroups []string `json:"apiGroups"`
	// Resources is the list of allowed resources, optionally with a subresource such as "pods/log".
	// "*" matches all resources.
	// +kubebuilder:validation:MinItems=1
	Resources []string `json:"resources"`
}

// +genclient
// +genclient:nonNamespaced
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="Issuer",type="string",JSONPath=".spec.issuer"
// +kubebuilder:printcolumn:name="User",type="string",JSONPath=".spec.userID"
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AgentTrust makes Rancher trust identity tokens issued by an OIDC issuer for the workloads of AI
// agents. A workload which presents such a token, to the token exchange grant of the OIDC provider,
// receives a short-lived agent token for the user of the trust, limited by the rules of the trust.
// This replaces long-lived API keys in the agent.
//
// Creating an AgentTrust grants access to the user it names, so it should be limited to
// administrators, as is the default for cluster-scoped resources.
type AgentTrust struct {
	metav1.TypeMeta `json:",inline"`

	// Standard object metadata; More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#metadata.
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec is the desired configuration of the trust.
	Spec AgentTrustSpec `json:"spec"`
}

// AgentTrustSpec defines which identities are trusted and what they receive.
type AgentTrustSpec struct {
	// Description provides additional context about the trust.
	// +optional
	Description string `json:"description,omitempty"`
	// Issuer is the URL of the OIDC issuer of the identity tokens. It must use https and serve
	// OIDC discovery, from which the signing keys are fetched.
	// +kubebuilder:validation:Pattern=`^https://.+`
	Issuer string `json:"issuer"`
	// Audience is the audience identity tokens must be issued for. Tokens for other audiences are
	// rejected, so that a token issued for another service can't be replayed to Rancher.
	// +kubebuilder:validation:MinLength=1
	Audience string `json:"audience"`
	// Subjects lists the subjects (the "sub" claim) of the workloads which are trusted. There are
	// no wildcards: every trusted subject is named.
	// +kubebuilder:validation:MinItems=1
	Subjects []string `json:"subjects"`
	// UserID is the name of the Rancher user the agent acts for. Its permissions are the most the
	// agent can have.
	// +kubebuilder:validation:MinLength=1
	UserID string `json:"userID"`
	// AgentName identifies the agent in audit records. It defaults to the name of the trust and must
	// be a valid DNS label.
	// +optional
	AgentName string `json:"agentName,omitempty"`
	// Rules limit what the agent tokens may do, see AgentRule. The effective permissions are the
	// intersection of the rules and the permissions of the user.
	// +kubebuilder:validation:MinItems=1
	Rules []AgentRule `json:"rules"`
	// MaxTTLSeconds is the lifetime of the agent tokens issued. It is limited by the
	// agent-token-max-ttl-minutes setting.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:default=3600
	// +optional
	MaxTTLSeconds int64 `json:"maxTTLSeconds,omitempty"`
}
