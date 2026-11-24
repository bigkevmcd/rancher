package client

const (
	AgentRuleType           = "agentRule"
	AgentRuleFieldAPIGroups = "apiGroups"
	AgentRuleFieldResources = "resources"
	AgentRuleFieldVerbs     = "verbs"
)

type AgentRule struct {
	APIGroups []string `json:"apiGroups,omitempty" yaml:"apiGroups,omitempty"`
	Resources []string `json:"resources,omitempty" yaml:"resources,omitempty"`
	Verbs     []string `json:"verbs,omitempty" yaml:"verbs,omitempty"`
}
