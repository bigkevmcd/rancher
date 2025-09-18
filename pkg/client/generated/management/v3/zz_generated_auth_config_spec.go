package client

const (
	AuthConfigSpecType                     = "authConfigSpec"
	AuthConfigSpecFieldAccessMode          = "accessMode"
	AuthConfigSpecFieldActiveDirectory     = "activedirectory"
	AuthConfigSpecFieldAllowedPrincipalIDs = "allowedPrincipalIds"
	AuthConfigSpecFieldAzureAD             = "azuread"
	AuthConfigSpecFieldEnabled             = "enabled"
	AuthConfigSpecFieldFreeIPA             = "freeipa"
	AuthConfigSpecFieldGithub              = "github"
	AuthConfigSpecFieldGoogleOauth         = "googleoauth"
	AuthConfigSpecFieldLocal               = "local"
	AuthConfigSpecFieldLogoutAllSupported  = "logoutAllSupported"
	AuthConfigSpecFieldOpenLDAP            = "openldap"
)

type AuthConfigSpec struct {
	AccessMode          string                 `json:"accessMode,omitempty" yaml:"accessMode,omitempty"`
	ActiveDirectory     *ActiveDirectoryConfig `json:"activedirectory,omitempty" yaml:"activedirectory,omitempty"`
	AllowedPrincipalIDs []string               `json:"allowedPrincipalIds,omitempty" yaml:"allowedPrincipalIds,omitempty"`
	AzureAD             *AzureADConfig         `json:"azuread,omitempty" yaml:"azuread,omitempty"`
	Enabled             bool                   `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	FreeIPA             *LdapFields            `json:"freeipa,omitempty" yaml:"freeipa,omitempty"`
	Github              *GithubConfig          `json:"github,omitempty" yaml:"github,omitempty"`
	GoogleOauth         *GoogleOauthConfig     `json:"googleoauth,omitempty" yaml:"googleoauth,omitempty"`
	Local               *LocalAuthConfig       `json:"local,omitempty" yaml:"local,omitempty"`
	LogoutAllSupported  bool                   `json:"logoutAllSupported,omitempty" yaml:"logoutAllSupported,omitempty"`
	OpenLDAP            *LdapFields            `json:"openldap,omitempty" yaml:"openldap,omitempty"`
}
