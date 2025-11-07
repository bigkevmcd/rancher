package client

const (
	GithubApplyInputType                     = "githubApplyInput"
	GithubApplyInputFieldAdditionalClientIDs = "additionalClientIds"
	GithubApplyInputFieldClientID            = "clientId"
	GithubApplyInputFieldClientSecret        = "clientSecret"
	GithubApplyInputFieldHostname            = "hostname"
	GithubApplyInputFieldHostnameToClientID  = "hostnameToClientId"
	GithubApplyInputFieldTLS                 = "tls"
)

type GithubApplyInput struct {
	AdditionalClientIDs map[string]string `json:"additionalClientIds,omitempty" yaml:"additionalClientIds,omitempty"`
	ClientID            string            `json:"clientId,omitempty" yaml:"clientId,omitempty"`
	ClientSecret        string            `json:"clientSecret,omitempty" yaml:"clientSecret,omitempty"`
	Hostname            string            `json:"hostname,omitempty" yaml:"hostname,omitempty"`
	HostnameToClientID  map[string]string `json:"hostnameToClientId,omitempty" yaml:"hostnameToClientId,omitempty"`
	TLS                 bool              `json:"tls,omitempty" yaml:"tls,omitempty"`
}
