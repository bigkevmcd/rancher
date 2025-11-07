package client

const (
	OIDCConfigType                      = "oidcConfig"
	OIDCConfigFieldAccessMode           = "accessMode"
	OIDCConfigFieldAcrValue             = "acrValue"
	OIDCConfigFieldAllowedPrincipalIDs  = "allowedPrincipalIds"
	OIDCConfigFieldAnnotations          = "annotations"
	OIDCConfigFieldAuthEndpoint         = "authEndpoint"
	OIDCConfigFieldCertificate          = "certificate"
	OIDCConfigFieldClientID             = "clientId"
	OIDCConfigFieldClientSecret         = "clientSecret"
	OIDCConfigFieldCreated              = "created"
	OIDCConfigFieldCreatorID            = "creatorId"
	OIDCConfigFieldEmailClaim           = "emailClaim"
	OIDCConfigFieldEnabled              = "enabled"
	OIDCConfigFieldEndSessionEndpoint   = "endSessionEndpoint"
	OIDCConfigFieldGithub               = "github"
	OIDCConfigFieldGroupSearchEnabled   = "groupSearchEnabled"
	OIDCConfigFieldGroupsClaim          = "groupsClaim"
	OIDCConfigFieldIssuer               = "issuer"
	OIDCConfigFieldJWKSUrl              = "jwksUrl"
	OIDCConfigFieldLabels               = "labels"
	OIDCConfigFieldLogoutAllEnabled     = "logoutAllEnabled"
	OIDCConfigFieldLogoutAllForced      = "logoutAllForced"
	OIDCConfigFieldLogoutAllSupported   = "logoutAllSupported"
	OIDCConfigFieldName                 = "name"
	OIDCConfigFieldNameClaim            = "nameClaim"
	OIDCConfigFieldOwnerReferences      = "ownerReferences"
	OIDCConfigFieldPrivateKey           = "privateKey"
	OIDCConfigFieldRancherURL           = "rancherUrl"
	OIDCConfigFieldRemoved              = "removed"
	OIDCConfigFieldScopes               = "scope"
	OIDCConfigFieldState                = "state"
	OIDCConfigFieldStatus               = "status"
	OIDCConfigFieldTokenEndpoint        = "tokenEndpoint"
	OIDCConfigFieldTransitioning        = "transitioning"
	OIDCConfigFieldTransitioningMessage = "transitioningMessage"
	OIDCConfigFieldType                 = "type"
	OIDCConfigFieldUUID                 = "uuid"
	OIDCConfigFieldUserInfoEndpoint     = "userInfoEndpoint"
)

type OIDCConfig struct {
	AccessMode           string            `json:"accessMode,omitempty" yaml:"accessMode,omitempty"`
	AcrValue             string            `json:"acrValue,omitempty" yaml:"acrValue,omitempty"`
	AllowedPrincipalIDs  []string          `json:"allowedPrincipalIds,omitempty" yaml:"allowedPrincipalIds,omitempty"`
	Annotations          map[string]string `json:"annotations,omitempty" yaml:"annotations,omitempty"`
	AuthEndpoint         string            `json:"authEndpoint,omitempty" yaml:"authEndpoint,omitempty"`
	Certificate          string            `json:"certificate,omitempty" yaml:"certificate,omitempty"`
	ClientID             string            `json:"clientId,omitempty" yaml:"clientId,omitempty"`
	ClientSecret         string            `json:"clientSecret,omitempty" yaml:"clientSecret,omitempty"`
	Created              string            `json:"created,omitempty" yaml:"created,omitempty"`
	CreatorID            string            `json:"creatorId,omitempty" yaml:"creatorId,omitempty"`
	EmailClaim           string            `json:"emailClaim,omitempty" yaml:"emailClaim,omitempty"`
	Enabled              bool              `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	EndSessionEndpoint   string            `json:"endSessionEndpoint,omitempty" yaml:"endSessionEndpoint,omitempty"`
	Github               *GithubConfig     `json:"github,omitempty" yaml:"github,omitempty"`
	GroupSearchEnabled   *bool             `json:"groupSearchEnabled,omitempty" yaml:"groupSearchEnabled,omitempty"`
	GroupsClaim          string            `json:"groupsClaim,omitempty" yaml:"groupsClaim,omitempty"`
	Issuer               string            `json:"issuer,omitempty" yaml:"issuer,omitempty"`
	JWKSUrl              string            `json:"jwksUrl,omitempty" yaml:"jwksUrl,omitempty"`
	Labels               map[string]string `json:"labels,omitempty" yaml:"labels,omitempty"`
	LogoutAllEnabled     bool              `json:"logoutAllEnabled,omitempty" yaml:"logoutAllEnabled,omitempty"`
	LogoutAllForced      bool              `json:"logoutAllForced,omitempty" yaml:"logoutAllForced,omitempty"`
	LogoutAllSupported   bool              `json:"logoutAllSupported,omitempty" yaml:"logoutAllSupported,omitempty"`
	Name                 string            `json:"name,omitempty" yaml:"name,omitempty"`
	NameClaim            string            `json:"nameClaim,omitempty" yaml:"nameClaim,omitempty"`
	OwnerReferences      []OwnerReference  `json:"ownerReferences,omitempty" yaml:"ownerReferences,omitempty"`
	PrivateKey           string            `json:"privateKey,omitempty" yaml:"privateKey,omitempty"`
	RancherURL           string            `json:"rancherUrl,omitempty" yaml:"rancherUrl,omitempty"`
	Removed              string            `json:"removed,omitempty" yaml:"removed,omitempty"`
	Scopes               string            `json:"scope,omitempty" yaml:"scope,omitempty"`
	State                string            `json:"state,omitempty" yaml:"state,omitempty"`
	Status               *AuthConfigStatus `json:"status,omitempty" yaml:"status,omitempty"`
	TokenEndpoint        string            `json:"tokenEndpoint,omitempty" yaml:"tokenEndpoint,omitempty"`
	Transitioning        string            `json:"transitioning,omitempty" yaml:"transitioning,omitempty"`
	TransitioningMessage string            `json:"transitioningMessage,omitempty" yaml:"transitioningMessage,omitempty"`
	Type                 string            `json:"type,omitempty" yaml:"type,omitempty"`
	UUID                 string            `json:"uuid,omitempty" yaml:"uuid,omitempty"`
	UserInfoEndpoint     string            `json:"userInfoEndpoint,omitempty" yaml:"userInfoEndpoint,omitempty"`
}
