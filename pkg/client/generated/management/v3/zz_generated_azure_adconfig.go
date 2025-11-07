package client

const (
	AzureADConfigType                       = "azureADConfig"
	AzureADConfigFieldAccessMode            = "accessMode"
	AzureADConfigFieldAllowedPrincipalIDs   = "allowedPrincipalIds"
	AzureADConfigFieldAnnotations           = "annotations"
	AzureADConfigFieldApplicationID         = "applicationId"
	AzureADConfigFieldApplicationSecret     = "applicationSecret"
	AzureADConfigFieldAuthEndpoint          = "authEndpoint"
	AzureADConfigFieldCreated               = "created"
	AzureADConfigFieldCreatorID             = "creatorId"
	AzureADConfigFieldDeviceAuthEndpoint    = "deviceAuthEndpoint"
	AzureADConfigFieldEnabled               = "enabled"
	AzureADConfigFieldEndpoint              = "endpoint"
	AzureADConfigFieldGithub                = "github"
	AzureADConfigFieldGraphEndpoint         = "graphEndpoint"
	AzureADConfigFieldGroupMembershipFilter = "groupMembershipFilter"
	AzureADConfigFieldLabels                = "labels"
	AzureADConfigFieldLogoutAllSupported    = "logoutAllSupported"
	AzureADConfigFieldName                  = "name"
	AzureADConfigFieldOwnerReferences       = "ownerReferences"
	AzureADConfigFieldRancherURL            = "rancherUrl"
	AzureADConfigFieldRemoved               = "removed"
	AzureADConfigFieldState                 = "state"
	AzureADConfigFieldStatus                = "status"
	AzureADConfigFieldTenantID              = "tenantId"
	AzureADConfigFieldTokenEndpoint         = "tokenEndpoint"
	AzureADConfigFieldTransitioning         = "transitioning"
	AzureADConfigFieldTransitioningMessage  = "transitioningMessage"
	AzureADConfigFieldType                  = "type"
	AzureADConfigFieldUUID                  = "uuid"
)

type AzureADConfig struct {
	AccessMode            string            `json:"accessMode,omitempty" yaml:"accessMode,omitempty"`
	AllowedPrincipalIDs   []string          `json:"allowedPrincipalIds,omitempty" yaml:"allowedPrincipalIds,omitempty"`
	Annotations           map[string]string `json:"annotations,omitempty" yaml:"annotations,omitempty"`
	ApplicationID         string            `json:"applicationId,omitempty" yaml:"applicationId,omitempty"`
	ApplicationSecret     string            `json:"applicationSecret,omitempty" yaml:"applicationSecret,omitempty"`
	AuthEndpoint          string            `json:"authEndpoint,omitempty" yaml:"authEndpoint,omitempty"`
	Created               string            `json:"created,omitempty" yaml:"created,omitempty"`
	CreatorID             string            `json:"creatorId,omitempty" yaml:"creatorId,omitempty"`
	DeviceAuthEndpoint    string            `json:"deviceAuthEndpoint,omitempty" yaml:"deviceAuthEndpoint,omitempty"`
	Enabled               bool              `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	Endpoint              string            `json:"endpoint,omitempty" yaml:"endpoint,omitempty"`
	Github                *GithubConfig     `json:"github,omitempty" yaml:"github,omitempty"`
	GraphEndpoint         string            `json:"graphEndpoint,omitempty" yaml:"graphEndpoint,omitempty"`
	GroupMembershipFilter string            `json:"groupMembershipFilter,omitempty" yaml:"groupMembershipFilter,omitempty"`
	Labels                map[string]string `json:"labels,omitempty" yaml:"labels,omitempty"`
	LogoutAllSupported    bool              `json:"logoutAllSupported,omitempty" yaml:"logoutAllSupported,omitempty"`
	Name                  string            `json:"name,omitempty" yaml:"name,omitempty"`
	OwnerReferences       []OwnerReference  `json:"ownerReferences,omitempty" yaml:"ownerReferences,omitempty"`
	RancherURL            string            `json:"rancherUrl,omitempty" yaml:"rancherUrl,omitempty"`
	Removed               string            `json:"removed,omitempty" yaml:"removed,omitempty"`
	State                 string            `json:"state,omitempty" yaml:"state,omitempty"`
	Status                *AuthConfigStatus `json:"status,omitempty" yaml:"status,omitempty"`
	TenantID              string            `json:"tenantId,omitempty" yaml:"tenantId,omitempty"`
	TokenEndpoint         string            `json:"tokenEndpoint,omitempty" yaml:"tokenEndpoint,omitempty"`
	Transitioning         string            `json:"transitioning,omitempty" yaml:"transitioning,omitempty"`
	TransitioningMessage  string            `json:"transitioningMessage,omitempty" yaml:"transitioningMessage,omitempty"`
	Type                  string            `json:"type,omitempty" yaml:"type,omitempty"`
	UUID                  string            `json:"uuid,omitempty" yaml:"uuid,omitempty"`
}
