package client

const (
	GoogleOauthConfigType                              = "googleOauthConfig"
	GoogleOauthConfigFieldAdminEmail                   = "adminEmail"
	GoogleOauthConfigFieldHostname                     = "hostname"
	GoogleOauthConfigFieldNestedGroupMembershipEnabled = "nestedGroupMembershipEnabled"
	GoogleOauthConfigFieldOauthCredentialRef           = "oauthCredentialRef"
	GoogleOauthConfigFieldServiceAccountCredentialRef  = "serviceAccountCredentialRef"
	GoogleOauthConfigFieldUserInfoEndpoint             = "userInfoEndpoint"
)

type GoogleOauthConfig struct {
	AdminEmail                   string           `json:"adminEmail,omitempty" yaml:"adminEmail,omitempty"`
	Hostname                     string           `json:"hostname,omitempty" yaml:"hostname,omitempty"`
	NestedGroupMembershipEnabled bool             `json:"nestedGroupMembershipEnabled,omitempty" yaml:"nestedGroupMembershipEnabled,omitempty"`
	OauthCredentialRef           *SecretReference `json:"oauthCredentialRef,omitempty" yaml:"oauthCredentialRef,omitempty"`
	ServiceAccountCredentialRef  string           `json:"serviceAccountCredentialRef,omitempty" yaml:"serviceAccountCredentialRef,omitempty"`
	UserInfoEndpoint             string           `json:"userInfoEndpoint,omitempty" yaml:"userInfoEndpoint,omitempty"`
}
