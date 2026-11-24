package client

const (
	OIDCClientBackchannelType                          = "oidcClientBackchannel"
	OIDCClientBackchannelFieldAgentName                = "agentName"
	OIDCClientBackchannelFieldRequestExpirationSeconds = "requestExpirationSeconds"
	OIDCClientBackchannelFieldScopes                   = "scopes"
	OIDCClientBackchannelFieldTokenExpirationSeconds   = "tokenExpirationSeconds"
)

type OIDCClientBackchannel struct {
	AgentName                string                       `json:"agentName,omitempty" yaml:"agentName,omitempty"`
	RequestExpirationSeconds int64                        `json:"requestExpirationSeconds,omitempty" yaml:"requestExpirationSeconds,omitempty"`
	Scopes                   []OIDCClientBackchannelScope `json:"scopes,omitempty" yaml:"scopes,omitempty"`
	TokenExpirationSeconds   int64                        `json:"tokenExpirationSeconds,omitempty" yaml:"tokenExpirationSeconds,omitempty"`
}
