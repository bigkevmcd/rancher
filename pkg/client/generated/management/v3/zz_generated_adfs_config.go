package client

const (
	ADFSConfigType                      = "adfsConfig"
	ADFSConfigFieldAccessMode           = "accessMode"
	ADFSConfigFieldActiveDirectory      = "activedirectory"
	ADFSConfigFieldAllowedPrincipalIDs  = "allowedPrincipalIds"
	ADFSConfigFieldAnnotations          = "annotations"
	ADFSConfigFieldAzureAD              = "azuread"
	ADFSConfigFieldCreated              = "created"
	ADFSConfigFieldCreatorID            = "creatorId"
	ADFSConfigFieldDisplayNameField     = "displayNameField"
	ADFSConfigFieldEnabled              = "enabled"
	ADFSConfigFieldEntityID             = "entityID"
	ADFSConfigFieldFreeIPA              = "freeipa"
	ADFSConfigFieldGithub               = "github"
	ADFSConfigFieldGoogleOauth          = "googleoauth"
	ADFSConfigFieldGroupsField          = "groupsField"
	ADFSConfigFieldIDPMetadataContent   = "idpMetadataContent"
	ADFSConfigFieldLabels               = "labels"
	ADFSConfigFieldLocal                = "local"
	ADFSConfigFieldLogoutAllEnabled     = "logoutAllEnabled"
	ADFSConfigFieldLogoutAllForced      = "logoutAllForced"
	ADFSConfigFieldLogoutAllSupported   = "logoutAllSupported"
	ADFSConfigFieldName                 = "name"
	ADFSConfigFieldOpenLDAP             = "openldap"
	ADFSConfigFieldOwnerReferences      = "ownerReferences"
	ADFSConfigFieldRancherAPIHost       = "rancherApiHost"
	ADFSConfigFieldRemoved              = "removed"
	ADFSConfigFieldSpCert               = "spCert"
	ADFSConfigFieldSpKey                = "spKey"
	ADFSConfigFieldState                = "state"
	ADFSConfigFieldStatus               = "status"
	ADFSConfigFieldTransitioning        = "transitioning"
	ADFSConfigFieldTransitioningMessage = "transitioningMessage"
	ADFSConfigFieldType                 = "type"
	ADFSConfigFieldUIDField             = "uidField"
	ADFSConfigFieldUUID                 = "uuid"
	ADFSConfigFieldUserNameField        = "userNameField"
)

type ADFSConfig struct {
	AccessMode           string                 `json:"accessMode,omitempty" yaml:"accessMode,omitempty"`
	ActiveDirectory      *ActiveDirectoryConfig `json:"activedirectory,omitempty" yaml:"activedirectory,omitempty"`
	AllowedPrincipalIDs  []string               `json:"allowedPrincipalIds,omitempty" yaml:"allowedPrincipalIds,omitempty"`
	Annotations          map[string]string      `json:"annotations,omitempty" yaml:"annotations,omitempty"`
	AzureAD              *AzureADConfig         `json:"azuread,omitempty" yaml:"azuread,omitempty"`
	Created              string                 `json:"created,omitempty" yaml:"created,omitempty"`
	CreatorID            string                 `json:"creatorId,omitempty" yaml:"creatorId,omitempty"`
	DisplayNameField     string                 `json:"displayNameField,omitempty" yaml:"displayNameField,omitempty"`
	Enabled              bool                   `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	EntityID             string                 `json:"entityID,omitempty" yaml:"entityID,omitempty"`
	FreeIPA              *LdapFields            `json:"freeipa,omitempty" yaml:"freeipa,omitempty"`
	Github               *GithubConfig          `json:"github,omitempty" yaml:"github,omitempty"`
	GoogleOauth          *GoogleOauthConfig     `json:"googleoauth,omitempty" yaml:"googleoauth,omitempty"`
	GroupsField          string                 `json:"groupsField,omitempty" yaml:"groupsField,omitempty"`
	IDPMetadataContent   string                 `json:"idpMetadataContent,omitempty" yaml:"idpMetadataContent,omitempty"`
	Labels               map[string]string      `json:"labels,omitempty" yaml:"labels,omitempty"`
	Local                *LocalAuthConfig       `json:"local,omitempty" yaml:"local,omitempty"`
	LogoutAllEnabled     bool                   `json:"logoutAllEnabled,omitempty" yaml:"logoutAllEnabled,omitempty"`
	LogoutAllForced      bool                   `json:"logoutAllForced,omitempty" yaml:"logoutAllForced,omitempty"`
	LogoutAllSupported   bool                   `json:"logoutAllSupported,omitempty" yaml:"logoutAllSupported,omitempty"`
	Name                 string                 `json:"name,omitempty" yaml:"name,omitempty"`
	OpenLDAP             *LdapFields            `json:"openldap,omitempty" yaml:"openldap,omitempty"`
	OwnerReferences      []OwnerReference       `json:"ownerReferences,omitempty" yaml:"ownerReferences,omitempty"`
	RancherAPIHost       string                 `json:"rancherApiHost,omitempty" yaml:"rancherApiHost,omitempty"`
	Removed              string                 `json:"removed,omitempty" yaml:"removed,omitempty"`
	SpCert               string                 `json:"spCert,omitempty" yaml:"spCert,omitempty"`
	SpKey                string                 `json:"spKey,omitempty" yaml:"spKey,omitempty"`
	State                string                 `json:"state,omitempty" yaml:"state,omitempty"`
	Status               *AuthConfigStatus      `json:"status,omitempty" yaml:"status,omitempty"`
	Transitioning        string                 `json:"transitioning,omitempty" yaml:"transitioning,omitempty"`
	TransitioningMessage string                 `json:"transitioningMessage,omitempty" yaml:"transitioningMessage,omitempty"`
	Type                 string                 `json:"type,omitempty" yaml:"type,omitempty"`
	UIDField             string                 `json:"uidField,omitempty" yaml:"uidField,omitempty"`
	UUID                 string                 `json:"uuid,omitempty" yaml:"uuid,omitempty"`
	UserNameField        string                 `json:"userNameField,omitempty" yaml:"userNameField,omitempty"`
}
