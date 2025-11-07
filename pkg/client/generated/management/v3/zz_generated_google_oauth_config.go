package client

const (
	GoogleOauthConfigType                              = "googleOauthConfig"
	GoogleOauthConfigFieldAccessMode                   = "accessMode"
	GoogleOauthConfigFieldAdminEmail                   = "adminEmail"
	GoogleOauthConfigFieldAllowedPrincipalIDs          = "allowedPrincipalIds"
	GoogleOauthConfigFieldAnnotations                  = "annotations"
	GoogleOauthConfigFieldCreated                      = "created"
	GoogleOauthConfigFieldCreatorID                    = "creatorId"
	GoogleOauthConfigFieldEnabled                      = "enabled"
	GoogleOauthConfigFieldGithub                       = "github"
	GoogleOauthConfigFieldHostname                     = "hostname"
	GoogleOauthConfigFieldLabels                       = "labels"
	GoogleOauthConfigFieldLogoutAllSupported           = "logoutAllSupported"
	GoogleOauthConfigFieldName                         = "name"
	GoogleOauthConfigFieldNestedGroupMembershipEnabled = "nestedGroupMembershipEnabled"
	GoogleOauthConfigFieldOauthCredential              = "oauthCredential"
	GoogleOauthConfigFieldOwnerReferences              = "ownerReferences"
	GoogleOauthConfigFieldRemoved                      = "removed"
	GoogleOauthConfigFieldServiceAccountCredential     = "serviceAccountCredential"
	GoogleOauthConfigFieldState                        = "state"
	GoogleOauthConfigFieldStatus                       = "status"
	GoogleOauthConfigFieldTransitioning                = "transitioning"
	GoogleOauthConfigFieldTransitioningMessage         = "transitioningMessage"
	GoogleOauthConfigFieldType                         = "type"
	GoogleOauthConfigFieldUUID                         = "uuid"
	GoogleOauthConfigFieldUserInfoEndpoint             = "userInfoEndpoint"
)

type GoogleOauthConfig struct {
	AccessMode                   string            `json:"accessMode,omitempty" yaml:"accessMode,omitempty"`
	AdminEmail                   string            `json:"adminEmail,omitempty" yaml:"adminEmail,omitempty"`
	AllowedPrincipalIDs          []string          `json:"allowedPrincipalIds,omitempty" yaml:"allowedPrincipalIds,omitempty"`
	Annotations                  map[string]string `json:"annotations,omitempty" yaml:"annotations,omitempty"`
	Created                      string            `json:"created,omitempty" yaml:"created,omitempty"`
	CreatorID                    string            `json:"creatorId,omitempty" yaml:"creatorId,omitempty"`
	Enabled                      bool              `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	Github                       *GithubConfig     `json:"github,omitempty" yaml:"github,omitempty"`
	Hostname                     string            `json:"hostname,omitempty" yaml:"hostname,omitempty"`
	Labels                       map[string]string `json:"labels,omitempty" yaml:"labels,omitempty"`
	LogoutAllSupported           bool              `json:"logoutAllSupported,omitempty" yaml:"logoutAllSupported,omitempty"`
	Name                         string            `json:"name,omitempty" yaml:"name,omitempty"`
	NestedGroupMembershipEnabled bool              `json:"nestedGroupMembershipEnabled,omitempty" yaml:"nestedGroupMembershipEnabled,omitempty"`
	OauthCredential              string            `json:"oauthCredential,omitempty" yaml:"oauthCredential,omitempty"`
	OwnerReferences              []OwnerReference  `json:"ownerReferences,omitempty" yaml:"ownerReferences,omitempty"`
	Removed                      string            `json:"removed,omitempty" yaml:"removed,omitempty"`
	ServiceAccountCredential     string            `json:"serviceAccountCredential,omitempty" yaml:"serviceAccountCredential,omitempty"`
	State                        string            `json:"state,omitempty" yaml:"state,omitempty"`
	Status                       *AuthConfigStatus `json:"status,omitempty" yaml:"status,omitempty"`
	Transitioning                string            `json:"transitioning,omitempty" yaml:"transitioning,omitempty"`
	TransitioningMessage         string            `json:"transitioningMessage,omitempty" yaml:"transitioningMessage,omitempty"`
	Type                         string            `json:"type,omitempty" yaml:"type,omitempty"`
	UUID                         string            `json:"uuid,omitempty" yaml:"uuid,omitempty"`
	UserInfoEndpoint             string            `json:"userInfoEndpoint,omitempty" yaml:"userInfoEndpoint,omitempty"`
}
