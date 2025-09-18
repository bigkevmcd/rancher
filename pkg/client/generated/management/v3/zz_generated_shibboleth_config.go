package client

const (
	ShibbolethConfigType                      = "shibbolethConfig"
	ShibbolethConfigFieldAccessMode           = "accessMode"
	ShibbolethConfigFieldActiveDirectory      = "activedirectory"
	ShibbolethConfigFieldAllowedPrincipalIDs  = "allowedPrincipalIds"
	ShibbolethConfigFieldAnnotations          = "annotations"
	ShibbolethConfigFieldAzureAD              = "azuread"
	ShibbolethConfigFieldCreated              = "created"
	ShibbolethConfigFieldCreatorID            = "creatorId"
	ShibbolethConfigFieldDisplayNameField     = "displayNameField"
	ShibbolethConfigFieldEnabled              = "enabled"
	ShibbolethConfigFieldEntityID             = "entityID"
	ShibbolethConfigFieldFreeIPA              = "freeipa"
	ShibbolethConfigFieldGithub               = "github"
	ShibbolethConfigFieldGoogleOauth          = "googleoauth"
	ShibbolethConfigFieldGroupsField          = "groupsField"
	ShibbolethConfigFieldIDPMetadataContent   = "idpMetadataContent"
	ShibbolethConfigFieldLabels               = "labels"
	ShibbolethConfigFieldLocal                = "local"
	ShibbolethConfigFieldLogoutAllEnabled     = "logoutAllEnabled"
	ShibbolethConfigFieldLogoutAllForced      = "logoutAllForced"
	ShibbolethConfigFieldLogoutAllSupported   = "logoutAllSupported"
	ShibbolethConfigFieldName                 = "name"
	ShibbolethConfigFieldOpenLDAP             = "openldap"
	ShibbolethConfigFieldOpenLdapConfig       = "openLdapConfig"
	ShibbolethConfigFieldOwnerReferences      = "ownerReferences"
	ShibbolethConfigFieldRancherAPIHost       = "rancherApiHost"
	ShibbolethConfigFieldRemoved              = "removed"
	ShibbolethConfigFieldSpCert               = "spCert"
	ShibbolethConfigFieldSpKey                = "spKey"
	ShibbolethConfigFieldState                = "state"
	ShibbolethConfigFieldStatus               = "status"
	ShibbolethConfigFieldTransitioning        = "transitioning"
	ShibbolethConfigFieldTransitioningMessage = "transitioningMessage"
	ShibbolethConfigFieldType                 = "type"
	ShibbolethConfigFieldUIDField             = "uidField"
	ShibbolethConfigFieldUUID                 = "uuid"
	ShibbolethConfigFieldUserNameField        = "userNameField"
)

type ShibbolethConfig struct {
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
	OpenLdapConfig       *LdapFields            `json:"openLdapConfig,omitempty" yaml:"openLdapConfig,omitempty"`
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
