package client

const (
	OIDCClientBackchannelScopeType             = "oidcClientBackchannelScope"
	OIDCClientBackchannelScopeFieldDescription = "description"
	OIDCClientBackchannelScopeFieldName        = "name"
	OIDCClientBackchannelScopeFieldRules       = "rules"
)

type OIDCClientBackchannelScope struct {
	Description string      `json:"description,omitempty" yaml:"description,omitempty"`
	Name        string      `json:"name,omitempty" yaml:"name,omitempty"`
	Rules       []AgentRule `json:"rules,omitempty" yaml:"rules,omitempty"`
}
