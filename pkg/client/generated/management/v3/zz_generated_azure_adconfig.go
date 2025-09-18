package client

const (
	AzureADConfigType                       = "azureADConfig"
	AzureADConfigFieldApplicationID         = "applicationId"
	AzureADConfigFieldApplicationSecret     = "applicationSecret"
	AzureADConfigFieldAuthEndpoint          = "authEndpoint"
	AzureADConfigFieldDeviceAuthEndpoint    = "deviceAuthEndpoint"
	AzureADConfigFieldEndpoint              = "endpoint"
	AzureADConfigFieldGraphEndpoint         = "graphEndpoint"
	AzureADConfigFieldGroupMembershipFilter = "groupMembershipFilter"
	AzureADConfigFieldRancherURL            = "rancherUrl"
	AzureADConfigFieldTenantID              = "tenantId"
	AzureADConfigFieldTokenEndpoint         = "tokenEndpoint"
)

type AzureADConfig struct {
	ApplicationID         string `json:"applicationId,omitempty" yaml:"applicationId,omitempty"`
	ApplicationSecret     string `json:"applicationSecret,omitempty" yaml:"applicationSecret,omitempty"`
	AuthEndpoint          string `json:"authEndpoint,omitempty" yaml:"authEndpoint,omitempty"`
	DeviceAuthEndpoint    string `json:"deviceAuthEndpoint,omitempty" yaml:"deviceAuthEndpoint,omitempty"`
	Endpoint              string `json:"endpoint,omitempty" yaml:"endpoint,omitempty"`
	GraphEndpoint         string `json:"graphEndpoint,omitempty" yaml:"graphEndpoint,omitempty"`
	GroupMembershipFilter string `json:"groupMembershipFilter,omitempty" yaml:"groupMembershipFilter,omitempty"`
	RancherURL            string `json:"rancherUrl,omitempty" yaml:"rancherUrl,omitempty"`
	TenantID              string `json:"tenantId,omitempty" yaml:"tenantId,omitempty"`
	TokenEndpoint         string `json:"tokenEndpoint,omitempty" yaml:"tokenEndpoint,omitempty"`
}
