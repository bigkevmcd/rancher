package client

const (
	GithubConfigType                     = "githubConfig"
	GithubConfigFieldAdditionalClientIDs = "additionalClientIds"
	GithubConfigFieldClientID            = "clientId"
	GithubConfigFieldClientSecretRef     = "clientSecretRef"
	GithubConfigFieldHostname            = "hostname"
	GithubConfigFieldHostnameToClientID  = "hostnameToClientId"
	GithubConfigFieldTLS                 = "tls"
)

type GithubConfig struct {
	AdditionalClientIDs map[string]string `json:"additionalClientIds,omitempty" yaml:"additionalClientIds,omitempty"`
	ClientID            string            `json:"clientId,omitempty" yaml:"clientId,omitempty"`
	ClientSecretRef     *SecretReference  `json:"clientSecretRef,omitempty" yaml:"clientSecretRef,omitempty"`
	Hostname            string            `json:"hostname,omitempty" yaml:"hostname,omitempty"`
	HostnameToClientID  map[string]string `json:"hostnameToClientId,omitempty" yaml:"hostnameToClientId,omitempty"`
	TLS                 bool              `json:"tls,omitempty" yaml:"tls,omitempty"`
}
