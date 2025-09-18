package client

const (
	CognitoConfigType                      = "cognitoConfig"
	CognitoConfigFieldAccessMode           = "accessMode"
	CognitoConfigFieldAcrValue             = "acrValue"
	CognitoConfigFieldActiveDirectory      = "activedirectory"
	CognitoConfigFieldAllowedPrincipalIDs  = "allowedPrincipalIds"
	CognitoConfigFieldAnnotations          = "annotations"
	CognitoConfigFieldAuthEndpoint         = "authEndpoint"
	CognitoConfigFieldAzureAD              = "azuread"
	CognitoConfigFieldCertificate          = "certificate"
	CognitoConfigFieldClientID             = "clientId"
	CognitoConfigFieldClientSecret         = "clientSecret"
	CognitoConfigFieldCreated              = "created"
	CognitoConfigFieldCreatorID            = "creatorId"
	CognitoConfigFieldEmailClaim           = "emailClaim"
	CognitoConfigFieldEnabled              = "enabled"
	CognitoConfigFieldEndSessionEndpoint   = "endSessionEndpoint"
	CognitoConfigFieldFreeIPA              = "freeipa"
	CognitoConfigFieldGithub               = "github"
	CognitoConfigFieldGoogleOauth          = "googleoauth"
	CognitoConfigFieldGroupSearchEnabled   = "groupSearchEnabled"
	CognitoConfigFieldGroupsClaim          = "groupsClaim"
	CognitoConfigFieldIssuer               = "issuer"
	CognitoConfigFieldJWKSUrl              = "jwksUrl"
	CognitoConfigFieldLabels               = "labels"
	CognitoConfigFieldLocal                = "local"
	CognitoConfigFieldLogoutAllEnabled     = "logoutAllEnabled"
	CognitoConfigFieldLogoutAllForced      = "logoutAllForced"
	CognitoConfigFieldLogoutAllSupported   = "logoutAllSupported"
	CognitoConfigFieldName                 = "name"
	CognitoConfigFieldNameClaim            = "nameClaim"
	CognitoConfigFieldOpenLDAP             = "openldap"
	CognitoConfigFieldOwnerReferences      = "ownerReferences"
	CognitoConfigFieldPrivateKey           = "privateKey"
	CognitoConfigFieldRancherURL           = "rancherUrl"
	CognitoConfigFieldRemoved              = "removed"
	CognitoConfigFieldScopes               = "scope"
	CognitoConfigFieldState                = "state"
	CognitoConfigFieldStatus               = "status"
	CognitoConfigFieldTokenEndpoint        = "tokenEndpoint"
	CognitoConfigFieldTransitioning        = "transitioning"
	CognitoConfigFieldTransitioningMessage = "transitioningMessage"
	CognitoConfigFieldType                 = "type"
	CognitoConfigFieldUUID                 = "uuid"
	CognitoConfigFieldUserInfoEndpoint     = "userInfoEndpoint"
)

type CognitoConfig struct {
	AccessMode           string                 `json:"accessMode,omitempty" yaml:"accessMode,omitempty"`
	AcrValue             string                 `json:"acrValue,omitempty" yaml:"acrValue,omitempty"`
	ActiveDirectory      *ActiveDirectoryConfig `json:"activedirectory,omitempty" yaml:"activedirectory,omitempty"`
	AllowedPrincipalIDs  []string               `json:"allowedPrincipalIds,omitempty" yaml:"allowedPrincipalIds,omitempty"`
	Annotations          map[string]string      `json:"annotations,omitempty" yaml:"annotations,omitempty"`
	AuthEndpoint         string                 `json:"authEndpoint,omitempty" yaml:"authEndpoint,omitempty"`
	AzureAD              *AzureADConfig         `json:"azuread,omitempty" yaml:"azuread,omitempty"`
	Certificate          string                 `json:"certificate,omitempty" yaml:"certificate,omitempty"`
	ClientID             string                 `json:"clientId,omitempty" yaml:"clientId,omitempty"`
	ClientSecret         string                 `json:"clientSecret,omitempty" yaml:"clientSecret,omitempty"`
	Created              string                 `json:"created,omitempty" yaml:"created,omitempty"`
	CreatorID            string                 `json:"creatorId,omitempty" yaml:"creatorId,omitempty"`
	EmailClaim           string                 `json:"emailClaim,omitempty" yaml:"emailClaim,omitempty"`
	Enabled              bool                   `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	EndSessionEndpoint   string                 `json:"endSessionEndpoint,omitempty" yaml:"endSessionEndpoint,omitempty"`
	FreeIPA              *LdapFields            `json:"freeipa,omitempty" yaml:"freeipa,omitempty"`
	Github               *GithubConfig          `json:"github,omitempty" yaml:"github,omitempty"`
	GoogleOauth          *GoogleOauthConfig     `json:"googleoauth,omitempty" yaml:"googleoauth,omitempty"`
	GroupSearchEnabled   *bool                  `json:"groupSearchEnabled,omitempty" yaml:"groupSearchEnabled,omitempty"`
	GroupsClaim          string                 `json:"groupsClaim,omitempty" yaml:"groupsClaim,omitempty"`
	Issuer               string                 `json:"issuer,omitempty" yaml:"issuer,omitempty"`
	JWKSUrl              string                 `json:"jwksUrl,omitempty" yaml:"jwksUrl,omitempty"`
	Labels               map[string]string      `json:"labels,omitempty" yaml:"labels,omitempty"`
	Local                *LocalAuthConfig       `json:"local,omitempty" yaml:"local,omitempty"`
	LogoutAllEnabled     bool                   `json:"logoutAllEnabled,omitempty" yaml:"logoutAllEnabled,omitempty"`
	LogoutAllForced      bool                   `json:"logoutAllForced,omitempty" yaml:"logoutAllForced,omitempty"`
	LogoutAllSupported   bool                   `json:"logoutAllSupported,omitempty" yaml:"logoutAllSupported,omitempty"`
	Name                 string                 `json:"name,omitempty" yaml:"name,omitempty"`
	NameClaim            string                 `json:"nameClaim,omitempty" yaml:"nameClaim,omitempty"`
	OpenLDAP             *LdapFields            `json:"openldap,omitempty" yaml:"openldap,omitempty"`
	OwnerReferences      []OwnerReference       `json:"ownerReferences,omitempty" yaml:"ownerReferences,omitempty"`
	PrivateKey           string                 `json:"privateKey,omitempty" yaml:"privateKey,omitempty"`
	RancherURL           string                 `json:"rancherUrl,omitempty" yaml:"rancherUrl,omitempty"`
	Removed              string                 `json:"removed,omitempty" yaml:"removed,omitempty"`
	Scopes               string                 `json:"scope,omitempty" yaml:"scope,omitempty"`
	State                string                 `json:"state,omitempty" yaml:"state,omitempty"`
	Status               *AuthConfigStatus      `json:"status,omitempty" yaml:"status,omitempty"`
	TokenEndpoint        string                 `json:"tokenEndpoint,omitempty" yaml:"tokenEndpoint,omitempty"`
	Transitioning        string                 `json:"transitioning,omitempty" yaml:"transitioning,omitempty"`
	TransitioningMessage string                 `json:"transitioningMessage,omitempty" yaml:"transitioningMessage,omitempty"`
	Type                 string                 `json:"type,omitempty" yaml:"type,omitempty"`
	UUID                 string                 `json:"uuid,omitempty" yaml:"uuid,omitempty"`
	UserInfoEndpoint     string                 `json:"userInfoEndpoint,omitempty" yaml:"userInfoEndpoint,omitempty"`
}
