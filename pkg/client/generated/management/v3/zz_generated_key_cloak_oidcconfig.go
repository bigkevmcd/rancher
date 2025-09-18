package client

const (
	KeyCloakOIDCConfigType                      = "keyCloakOIDCConfig"
	KeyCloakOIDCConfigFieldAccessMode           = "accessMode"
	KeyCloakOIDCConfigFieldAcrValue             = "acrValue"
	KeyCloakOIDCConfigFieldActiveDirectory      = "activedirectory"
	KeyCloakOIDCConfigFieldAllowedPrincipalIDs  = "allowedPrincipalIds"
	KeyCloakOIDCConfigFieldAnnotations          = "annotations"
	KeyCloakOIDCConfigFieldAuthEndpoint         = "authEndpoint"
	KeyCloakOIDCConfigFieldAzureAD              = "azuread"
	KeyCloakOIDCConfigFieldCertificate          = "certificate"
	KeyCloakOIDCConfigFieldClientID             = "clientId"
	KeyCloakOIDCConfigFieldClientSecret         = "clientSecret"
	KeyCloakOIDCConfigFieldCreated              = "created"
	KeyCloakOIDCConfigFieldCreatorID            = "creatorId"
	KeyCloakOIDCConfigFieldEmailClaim           = "emailClaim"
	KeyCloakOIDCConfigFieldEnabled              = "enabled"
	KeyCloakOIDCConfigFieldEndSessionEndpoint   = "endSessionEndpoint"
	KeyCloakOIDCConfigFieldFreeIPA              = "freeipa"
	KeyCloakOIDCConfigFieldGithub               = "github"
	KeyCloakOIDCConfigFieldGoogleOauth          = "googleoauth"
	KeyCloakOIDCConfigFieldGroupSearchEnabled   = "groupSearchEnabled"
	KeyCloakOIDCConfigFieldGroupsClaim          = "groupsClaim"
	KeyCloakOIDCConfigFieldIssuer               = "issuer"
	KeyCloakOIDCConfigFieldJWKSUrl              = "jwksUrl"
	KeyCloakOIDCConfigFieldLabels               = "labels"
	KeyCloakOIDCConfigFieldLocal                = "local"
	KeyCloakOIDCConfigFieldLogoutAllEnabled     = "logoutAllEnabled"
	KeyCloakOIDCConfigFieldLogoutAllForced      = "logoutAllForced"
	KeyCloakOIDCConfigFieldLogoutAllSupported   = "logoutAllSupported"
	KeyCloakOIDCConfigFieldName                 = "name"
	KeyCloakOIDCConfigFieldNameClaim            = "nameClaim"
	KeyCloakOIDCConfigFieldOpenLDAP             = "openldap"
	KeyCloakOIDCConfigFieldOwnerReferences      = "ownerReferences"
	KeyCloakOIDCConfigFieldPrivateKey           = "privateKey"
	KeyCloakOIDCConfigFieldRancherURL           = "rancherUrl"
	KeyCloakOIDCConfigFieldRemoved              = "removed"
	KeyCloakOIDCConfigFieldScopes               = "scope"
	KeyCloakOIDCConfigFieldState                = "state"
	KeyCloakOIDCConfigFieldStatus               = "status"
	KeyCloakOIDCConfigFieldTokenEndpoint        = "tokenEndpoint"
	KeyCloakOIDCConfigFieldTransitioning        = "transitioning"
	KeyCloakOIDCConfigFieldTransitioningMessage = "transitioningMessage"
	KeyCloakOIDCConfigFieldType                 = "type"
	KeyCloakOIDCConfigFieldUUID                 = "uuid"
	KeyCloakOIDCConfigFieldUserInfoEndpoint     = "userInfoEndpoint"
)

type KeyCloakOIDCConfig struct {
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
