package v3

import (
	"strings"

	"github.com/rancher/norman/condition"
	"github.com/rancher/norman/types"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	UserConditionInitialRolesPopulated condition.Cond = "InitialRolesPopulated"
	AuthConfigConditionSecretsMigrated condition.Cond = "SecretsMigrated"
	// AuthConfigConditionShibbolethSecretFixed is applied to an AuthConfig when the
	// incorrect name for the shibboleth OpenLDAP secret has been fixed.
	AuthConfigConditionShibbolethSecretFixed condition.Cond = "ShibbolethSecretFixed"

	// AuthConfigOKTAPasswordMigrated is applied when an Okta password has been
	// moved to a Secret.
	AuthConfigOKTAPasswordMigrated condition.Cond = "OktaPasswordMigrated"
)

// +genclient
// +kubebuilder:skipversion
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type Token struct {
	metav1.TypeMeta    `json:",inline"`
	metav1.ObjectMeta  `json:"metadata,omitempty"`
	Token              string            `json:"token" norman:"writeOnly,noupdate"`
	UserPrincipal      Principal         `json:"userPrincipal" norman:"type=reference[principal]"`
	GroupPrincipals    []Principal       `json:"groupPrincipals,omitempty" norman:"type=array[reference[principal]]"`
	ProviderInfo       map[string]string `json:"providerInfo,omitempty"`
	UserID             string            `json:"userId" norman:"type=reference[user]"`
	AuthProvider       string            `json:"authProvider"`
	TTLMillis          int64             `json:"ttl"`
	LastUsedAt         *metav1.Time      `json:"lastUsedAt,omitempty"`
	ActivityLastSeenAt *metav1.Time      `json:"activityLastSeenAt,omitempty"`
	IsDerived          bool              `json:"isDerived"`
	Description        string            `json:"description"`
	Expired            bool              `json:"expired"`
	ExpiresAt          string            `json:"expiresAt"`
	Current            bool              `json:"current"`
	ClusterName        string            `json:"clusterName,omitempty" norman:"noupdate,type=reference[cluster]"`
	Enabled            *bool             `json:"enabled,omitempty" norman:"default=true"`
}

// Implement the TokenAccessor interface

func (t *Token) GetName() string {
	return t.ObjectMeta.Name
}

func (t *Token) GetIsEnabled() bool {
	return t.Enabled == nil || *t.Enabled
}

func (t *Token) GetIsDerived() bool {
	return t.IsDerived
}

func (t *Token) GetAuthProvider() string {
	return t.AuthProvider
}

func (t *Token) GetUserID() string {
	return t.UserID
}

func (t *Token) ObjClusterName() string {
	return t.ClusterName
}

func (t *Token) GetUserPrincipal() Principal {
	return t.UserPrincipal
}

func (t *Token) GetGroupPrincipals() []Principal {
	return t.GroupPrincipals
}

func (t *Token) GetProviderInfo() map[string]string {
	return t.ProviderInfo
}

func (t *Token) GetLastUsedAt() *metav1.Time {
	return t.LastUsedAt
}

func (t *Token) GetLastActivitySeen() *metav1.Time {
	return t.ActivityLastSeenAt
}

func (t *Token) GetCreationTime() metav1.Time {
	return t.CreationTimestamp
}

// +genclient
// +kubebuilder:skipversion
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type User struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	DisplayName string `json:"displayName,omitempty"`
	Description string `json:"description"`
	Username    string `json:"username,omitempty"`
	// Deprecated. Password are stored in secrets in the cattle-local-user-passwords namespace.
	Password           string   `json:"password,omitempty" norman:"writeOnly,noupdate"`
	MustChangePassword bool     `json:"mustChangePassword,omitempty"`
	PrincipalIDs       []string `json:"principalIds,omitempty" norman:"type=array[reference[principal]]"`
	// Deprecated. Me is an old field only used in the norman API.
	Me      bool       `json:"me,omitempty" norman:"nocreate,noupdate"`
	Enabled *bool      `json:"enabled,omitempty" norman:"default=true"`
	Spec    UserSpec   `json:"spec,omitempty"`
	Status  UserStatus `json:"status"`
}

// IsSystem returns true if the user is a system user.
func (u *User) IsSystem() bool {
	for _, principalID := range u.PrincipalIDs {
		if strings.HasPrefix(principalID, "system:") {
			return true
		}
	}

	return false
}

// IsDefaultAdmin returns true if the user is the default admin user.
func (u *User) IsDefaultAdmin() bool {
	return u.Username == "admin"
}

type UserStatus struct {
	Conditions []UserCondition `json:"conditions"`
}

type UserCondition struct {
	// Type of user condition.
	Type string `json:"type"`
	// Status of the condition, one of True, False, Unknown.
	Status v1.ConditionStatus `json:"status"`
	// The last time this condition was updated.
	LastUpdateTime string `json:"lastUpdateTime,omitempty"`
	// Last time the condition transitioned from one status to another.
	LastTransitionTime string `json:"lastTransitionTime,omitempty"`
	// The reason for the condition's last transition.
	Reason string `json:"reason,omitempty"`
	// Human-readable message indicating details about last transition
	Message string `json:"message,omitempty"`
}

type UserSpec struct{}

// +genclient
// +kubebuilder:skipversion
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// UserAttribute will have a CRD (and controller) generated for it, but will not be exposed in the API.
type UserAttribute struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	UserName        string
	GroupPrincipals map[string]Principals // the value is a []Principal, but code generator cannot handle slice as a value
	LastRefresh     string
	NeedsRefresh    bool
	ExtraByProvider map[string]map[string][]string // extra information for the user to print in audit logs, stored per authProvider. example: map[openldap:map[principalid:[openldap_user://uid=testuser1,ou=dev,dc=us-west-2,dc=compute,dc=internal]]]
	LastLogin       *metav1.Time                   `json:"lastLogin,omitempty"`
	DisableAfter    *metav1.Duration               `json:"disableAfter,omitempty"` // Overrides DisableInactiveUserAfter setting.
	DeleteAfter     *metav1.Duration               `json:"deleteAfter,omitempty"`  // Overrides DeleteInactiveUserAfter setting.
}

type Principals struct {
	Items []Principal
}

// +genclient
// +kubebuilder:skipversion
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type Group struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	DisplayName string `json:"displayName,omitempty"`
}

// +genclient
// +kubebuilder:skipversion
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type GroupMember struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	GroupName   string `json:"groupName,omitempty" norman:"type=reference[group]"`
	PrincipalID string `json:"principalId,omitempty" norman:"type=reference[principal]"`
}

// +genclient
// +kubebuilder:skipversion
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type Principal struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	DisplayName    string            `json:"displayName,omitempty"`
	LoginName      string            `json:"loginName,omitempty"`
	ProfilePicture string            `json:"profilePicture,omitempty"`
	ProfileURL     string            `json:"profileURL,omitempty"`
	PrincipalType  string            `json:"principalType,omitempty"`
	Me             bool              `json:"me,omitempty"`
	MemberOf       bool              `json:"memberOf,omitempty"`
	Provider       string            `json:"provider,omitempty"`
	ExtraInfo      map[string]string `json:"extraInfo,omitempty"`
}

type SearchPrincipalsInput struct {
	Name          string `json:"name" norman:"type=string,required,notnullable"`
	PrincipalType string `json:"principalType,omitempty" norman:"type=enum,options=user|group"`
}

type ChangePasswordInput struct {
	CurrentPassword string `json:"currentPassword" norman:"type=string,required"`
	NewPassword     string `json:"newPassword" norman:"type=string,required"`
}

type SetPasswordInput struct {
	NewPassword string `json:"newPassword" norman:"type=string,required"`
}

// +genclient
// +genclient:nonNamespaced
// +kubebuilder:resource:scope=Cluster
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type AuthConfig struct {
	metav1.TypeMeta   `json:",inline" mapstructure:",squash"`
	metav1.ObjectMeta `json:"metadata,omitempty" mapstructure:"metadata"`

	// TODO: deprecated
	Type string `json:"type" norman:"noupdate"`

	Spec AuthConfigSpec `json:"spec"`

	Status AuthConfigStatus `json:"status,omitempty"`
}

// AuthConfigStatus defines the observed state of AuthConfigStatus.
type AuthConfigStatus struct {
	// +listType=map
	// +listMapKey=type
	// +patchStrategy=merge
	// +patchMergeKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type" protobuf:"bytes,1,opt,name=conditions"`
}

// AuthConfigSpec defines the desired state of AuthConfig
type AuthConfigSpec struct {
	// enabled indicates that this AuthConfig is used for authenticating users.
	// +optional
	Enabled bool `json:"enabled,omitempty"`

	// accessMode controls which users can login to a Rancher installation:
	//
	// Possible enum values:
	// - `"unrestricted"` means that any valid user account within the configured authentication provider can log in.
	// - `"restricted"` means that access is limited to a predefined set of users and groups listed in the allowedPrincipalIDs parameter. Additionally, anyone who is also a member of a specific Environment (or project in the API) can log in.
	// - `"required"` is the strictest mode, requiring that users must be present in the allowedIdentities list to log in.
	//
	// +kubebuilder:validation:Enum=required;restricted;unrestricted
	// +required
	AccessMode string `json:"accessMode,omitempty"`

	// allowedPrincipalIDs works in conjunction with the accessMode.
	//
	// If populated the IDs must reference principals e.g. github_user://1
	//
	// +kubebuilder:example="github_user://1"
	// +optional
	AllowedPrincipalIDs []string `json:"allowedPrincipalIds,omitempty"`

	// logoutAllSupported should be true when the AuthConfig supports
	// logout-all.
	// +optional
	LogoutAllSupported bool `json:"logoutAllSupported,omitempty"`

	// local indicates that this should support local authentication.
	// +optional
	Local *LocalAuthConfig `json:"local,omitempty"`

	// github provides configuration for authenticating with GitHub OAuth.
	// +optional
	Github *GithubConfig `json:"github,omitempty"`

	// googleoauth provides configuration for authenticating with Google OAuth.
	// +optional
	GoogleOauth *GoogleOauthConfig `json:"googleoauth,omitempty"`

	// azuread provides configuration for authenticating with Microsoft Entra
	// (formerly Azure AD).
	// +optional
	AzureAD *AzureADConfig `json:"azuread,omitempty"`

	// activedirectory provides configuration for authenticating with Microsoft
	// Active Directory.
	// +optional
	ActiveDirectory *ActiveDirectoryConfig `json:"activedirectory,omitempty"`

	// openldap provides configuration for authenticating with OpenLDAP.
	// +optional
	OpenLDAP *LdapFields `json:"openldap,omitempty"`

	// freeipa provides configuration for authenticating with FreeIPA.
	//
	// TODO: This will need to be different for FreeIPA - the defaults are
	// different.
	//
	// +optional
	FreeIPA *LdapFields `json:"freeipa,omitempty"`
}

// LocalAuthConfig provides configuration the Local authentication.
type LocalAuthConfig struct {
}

// SecretReference points to a Secret with both a Namespace and Name.
type SecretReference struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

// GithubConfig provides configuration for authenticating via GitHub OAuth app.
type GithubConfig struct {
	// hostname is the host to communicate with for initiating the OAuth flow it
	// defaults to github.com.
	//
	// +kubebuilder:default="github.com"
	// +required
	Hostname string `json:"hostname,omitempty"`

	// tls indicates whether or not Rancher should use TLS to communicate with
	// the provided hostname.
	//
	// +kubebuilder:default=true
	// +required
	TLS bool `json:"tls,omitempty"`

	// clientId provides the GitHub OAuth App client ID.
	//
	// +kubebuilder:validation:Required
	ClientID string `json:"clientId,omitempty"`

	// clientSecretRef provides the name of a Secret that contains the OAuth App
	// client secret.
	//
	// The client secret must be in the clientsecret key in the Secret.
	//
	// +required
	ClientSecretRef *SecretReference `json:"clientSecretRef,omitempty"`

	// additionalClientIds is a map of clientID to client secrets
	//
	// +optional
	AdditionalClientIDs map[string]string `json:"additionalClientIds,omitempty"`

	// hostnameToClientId is a map of hostname to OAuth App client ID.
	//
	// +optional
	HostnameToClientID map[string]string `json:"hostnameToClientId,omitempty"`
}

// GoogleOauthConfig provides configuration for authenticating with Google
// OAuth.
type GoogleOauthConfig struct {
	// adminEmail is the email of an administrator account from your GSuite setup.
	//
	// In order to perform user and group lookups, Google apis require an
	// administrator's email in conjunction with the service account key.
	//
	// +required
	AdminEmail string `json:"adminEmail"`

	// hostName is the domain on which GSuite is configured.
	//
	// +kubebuilder:example="example.com"
	// +required
	Hostname string `json:"hostname"`

	// userInfoEndpoint is the API endpoint for getting user information it
	// defaults to https://openidconnect.googleapis.com/v1/userinfo.
	//
	// +kubebuilder:default="https://openidconnect.googleapis.com/v1/userinfo"
	// +kubebuilder:validation:Pattern="^(http|https)://.*$"
	// +required
	UserInfoEndpoint string `json:"userInfoEndpoint"`

	// nestedGroupMembershipEnabled if enabled indicates that all groups should
	// be queried in a nested manner.
	// +optional
	NestedGroupMembershipEnabled bool `json:"nestedGroupMembershipEnabled"`

	// oauthCredentialRef provides the name of a Secret that contains the OAuth
	// credentials provided when creating credentials in the Google Dashboard.
	//
	// The credentials must be in the oauthCredential key in the Secret.
	// +required
	OauthCredentialRef *SecretReference `json:"oauthCredentialRef,omitempty"`

	// serviceAccountCredentialRef provides the name of a Secret that contains
	// the Service Account credentials created in the Google Dashboard.
	//
	// The credentials must be in the serviceAccountCredential key in the Secret.
	// +required
	ServiceAccountCredentialRef string `json:"serviceAccountCredentialRef,omitempty"`
}

// AzureADConfig provides configuration for authenticating with Microsoft Entra
// (formerly Azure AD).
type AzureADConfig struct {
	// tenantID is a unique string of characters that identifies your
	// organization's tenant within the Microsoft Entra ID system.
	// +required
	TenantID string `json:"tenantId,omitempty"`

	// TODO: Write these up

	// +required
	ApplicationID string `json:"applicationId"`

	// TODO: Modify to a ref
	// +required
	ApplicationSecret string `json:"applicationSecret,omitempty" norman:"required,type=password"`

	// endpoint is the endpoint for communicating with Entra it defaults to
	// https://login.microsoftonline.com/.
	//
	// +kubebuilder:default="https://login.microsoftonline.com/"
	// +kubebuilder:validation:Pattern="^https://.*$"
	// +required
	Endpoint string `json:"endpoint,omitempty"`

	// graphEndpoint is the endpoint for communicating with the Entra Graph API
	// it defaults to https://graph.microsoft.com.
	//
	// +kubeuilder:default="https://graph.microsoft.com"
	// +kubebuilder:validation:Pattern="^https://.*$"
	// +required
	GraphEndpoint string `json:"graphEndpoint,omitempty"`

	// rancherUrl is the redirect URL sent to Entra to redirect the user to
	// after authentication.
	//
	// This must be an allowed redirect URL in Entra.
	//
	// +required
	RancherURL string `json:"rancherUrl,omitempty"`

	// groupMembershipFilter allows filtering of the groups that are returned by
	// Azure the filter is applied on the server-side.
	//
	// This uses the OData filtering language.
	//
	// +optional
	GroupMembershipFilter string `json:"groupMembershipFilter,omitempty"`

	// tokenEndpoint is used for custom endpoints.
	// +optional
	TokenEndpoint string `json:"tokenEndpoint,omitempty"`

	// authEndpoint is used for custom endpoints.
	// +optional
	AuthEndpoint string `json:"authEndpoint,omitempty"`

	// TODO: document
	DeviceAuthEndpoint string `json:"deviceAuthEndpoint,omitempty"`
}

// ActiveDirectoryConfig provides configuration for authenticating via an Active
// Directory LDAP Server.
type ActiveDirectoryConfig struct {
	// servers is a list of hosts to query
	//
	// +kubebuilder:validation:MinLength=1
	// +required
	Servers []string `json:"servers"`

	// port is the port to connect to the Active Directory server it defaults to
	// 389.
	//
	// Note that it is not possible to communicate with different servers on
	// different ports.
	// +kubebuilder:default=389
	// +required
	Port int64 `json:"port"`

	// tls enables LDAPS (LDAP over TLS) Rancher initiates a TLS connection to
	// the Active Directory server.
	//
	// +optional
	TLS bool `json:"tls,omitempty"`

	// starttls indicates that Rancher should initiate a plain-text connection
	// and negotiate a separate TLS connection with the Active Directory server.
	//
	// +optional
	StartTLS bool `json:"starttls,omitempty"`

	// certificate is a PEM-formatted certificate chain - this is needed if the server
	// you're connecting to presents a non-root-trusted certificate.
	//
	// +optional
	Certificate string `json:"certificate,omitempty"`

	// defaultLoginDomain can be configured with the NetBIOS name of your AD
	// domain, usernames entered without a domain (e.g. "jdoe") will
	// automatically be converted to a slashed, NetBIOS logon (e.g.
	// "LOGIN_DOMAIN\jdoe") when binding to the AD server.
	//
	// If your users authenticate with the UPN (e.g. "jdoe@acme.com") as username then this field must be left empty.
	//
	// +optional
	DefaultLoginDomain string `json:"defaultLoginDomain,omitempty"`

	ServiceAccountUsername string `json:"serviceAccountUsername,omitempty"      norman:"required"`
	ServiceAccountPassword string `json:"serviceAccountPassword,omitempty"      norman:"type=password,required"`

	// userEnabledAttribute is the attribute containing an integer value
	// representing a bitwise enumeration of user account flags.
	//
	// Rancher uses this to determine if a user account is disabled. You should
	// normally leave this set to the AD standard userAccountControl.
	//
	// +kubebuilder:default="userAccountControl"
	// +required
	UserEnabledAttribute string `json:"userEnabledAttribute"`

	// userDisabledBitmask configures a bitmask for the userEnabledAttribute to
	// detect when a user is disabled.
	//
	// +kubebuilder:default=2
	// +required
	UserDisabledBitMask int64 `json:"userDisabledBitMask"`

	// TODO
	//
	// +required
	UserSearchBase string `json:"userSearchBase"`

	// userSearchAttribute is used in the query for users as the fields to
	// search for query strings - the default is "sAMAccountName|sn|givenName"
	//
	// +kubebuilder:default="sAMAccountName|sn|givenName"
	// +required
	UserSearchAttribute string `json:"userSearchAttribute,omitempty"         norman:"default=sAMAccountName|sn|givenName,required"`

	// +optional
	UserSearchFilter string `json:"userSearchFilter"`

	// connectionTimeout is the maximum amount of time (in ms) to wait for a
	// connection to one of the servers to be established - the default is
	// 5000ms.
	//
	// +kubebuilder:default=5000
	// +required
	ConnectionTimeout int64 `json:"connectionTimeout,omitempty"`

	// TODO
	UserLoginAttribute           string `json:"userLoginAttribute,omitempty"          norman:"default=sAMAccountName,required"`
	UserObjectClass              string `json:"userObjectClass,omitempty"             norman:"default=person,required"`
	UserNameAttribute            string `json:"userNameAttribute,omitempty"           norman:"default=name,required"`
	UserLoginFilter              string `json:"userLoginFilter,omitempty"`
	GroupSearchBase              string `json:"groupSearchBase,omitempty"`
	GroupSearchAttribute         string `json:"groupSearchAttribute,omitempty"        norman:"default=sAMAccountName,required"`
	GroupSearchFilter            string `json:"groupSearchFilter,omitempty"`
	GroupObjectClass             string `json:"groupObjectClass,omitempty"            norman:"default=group,required"`
	GroupNameAttribute           string `json:"groupNameAttribute,omitempty"          norman:"default=name,required"`
	GroupDNAttribute             string `json:"groupDNAttribute,omitempty"            norman:"default=distinguishedName,required"`
	GroupMemberUserAttribute     string `json:"groupMemberUserAttribute,omitempty"    norman:"default=distinguishedName,required"`
	GroupMemberMappingAttribute  string `json:"groupMemberMappingAttribute,omitempty" norman:"default=member,required"`
	NestedGroupMembershipEnabled *bool  `json:"nestedGroupMembershipEnabled,omitempty" norman:"default=false"`
}

type LdapTestAndApplyInput struct {
	LdapConfig `json:"ldapConfig,omitempty"`
	Username   string `json:"username"`
	Password   string `json:"password" norman:"type=password,required"`
}

type OpenLdapTestAndApplyInput = LdapTestAndApplyInput
type FreeIpaTestAndApplyInput = LdapTestAndApplyInput

// +genclient
// +kubebuilder:skipversion
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type SamlToken struct {
	types.Namespaced
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Token     string `json:"token" norman:"writeOnly,noupdate"`
	ExpiresAt string `json:"expiresAt"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

func (c *ActiveDirectoryConfig) GetUserSearchAttributes(searchAttributes ...string) []string {
	userSearchAttributes := []string{
		c.UserObjectClass,
		c.UserLoginAttribute,
		c.UserNameAttribute,
		c.UserEnabledAttribute,
	}
	return append(userSearchAttributes, searchAttributes...)
}

func (c *ActiveDirectoryConfig) GetGroupSearchAttributes(searchAttributes ...string) []string {
	groupSeachAttributes := []string{
		c.GroupObjectClass,
		c.UserLoginAttribute,
		c.GroupNameAttribute,
		c.GroupSearchAttribute,
	}
	return append(groupSeachAttributes, searchAttributes...)
}

type ActiveDirectoryTestAndApplyInput struct {
	ActiveDirectoryConfig ActiveDirectoryConfig `json:"activeDirectoryConfig,omitempty"`
	Username              string                `json:"username"`
	Password              string                `json:"password"`
	Enabled               bool                  `json:"enabled,omitempty"`
}

type LdapFields struct {
	// servers is a list of hosts to query.
	//
	// +kubebuilder:validation:MinLength=1
	// +required
	Servers []string `json:"servers"`

	// port is the port to connect to the LDAP server it defaults to 389.
	//
	// Note that it is not possible to communicate with different servers on
	// different ports.
	// +kubebuilder:default=389
	// +required
	Port int64 `json:"port"`

	// tls enables LDAPS (LDAP over TLS) Rancher initiates a TLS connection to
	// the LDAP server.
	//
	// +optional
	TLS bool `json:"tls,omitempty"`

	// starttls indicates that Rancher should initiate a plain-text connection
	// and negotiate a separate TLS connection with the LDAP server.
	//
	// +optional
	StartTLS bool `json:"starttls,omitempty"`

	// certificate is a PEM-formatted certificate chain - this is needed if the server
	// you're connecting to presents a non-root-trusted certificate.
	//
	// +optional
	Certificate string `json:"certificate,omitempty"`

	// connectionTimeout is the maximum amount of time (in ms) to wait for a
	// connection to one of the servers to be established - the default is
	// 5000ms.
	//
	// +kubebuilder:default=5000
	// +required
	ConnectionTimeout int64 `json:"connectionTimeout,omitempty"`

	// serviceAccountDistinguishedName is the DN to connect to the LDAP server
	// with.
	//
	// +required
	ServiceAccountDistinguishedName string `json:"serviceAccountDistinguishedName,omitempty"`
	ServiceAccountPassword          string `json:"serviceAccountPassword,omitempty"          norman:"type=password,required"`

	UserDisabledBitMask int64 `json:"userDisabledBitMask,omitempty"`

	UserSearchBase               string `json:"userSearchBase,omitempty"                  norman:"notnullable,required"`
	UserSearchAttribute          string `json:"userSearchAttribute,omitempty"             norman:"default=uid|sn|givenName,notnullable,required"`
	UserSearchFilter             string `json:"userSearchFilter,omitempty"`
	UserLoginAttribute           string `json:"userLoginAttribute,omitempty"              norman:"default=uid,notnullable,required"`
	UserObjectClass              string `json:"userObjectClass,omitempty"                 norman:"default=inetOrgPerson,notnullable,required"`
	UserNameAttribute            string `json:"userNameAttribute,omitempty"               norman:"default=cn,notnullable,required"`
	UserMemberAttribute          string `json:"userMemberAttribute,omitempty"             norman:"default=memberOf,notnullable,required"`
	UserEnabledAttribute         string `json:"userEnabledAttribute,omitempty"`
	UserLoginFilter              string `json:"userLoginFilter,omitempty"`
	GroupSearchBase              string `json:"groupSearchBase,omitempty"`
	GroupSearchAttribute         string `json:"groupSearchAttribute,omitempty"            norman:"default=cn,notnullable,required"`
	GroupSearchFilter            string `json:"groupSearchFilter,omitempty"`
	GroupObjectClass             string `json:"groupObjectClass,omitempty"                norman:"default=groupOfNames,notnullable,required"`
	GroupNameAttribute           string `json:"groupNameAttribute,omitempty"              norman:"default=cn,notnullable,required"`
	GroupDNAttribute             string `json:"groupDNAttribute,omitempty"                norman:"default=entryDN,notnullable"`
	GroupMemberUserAttribute     string `json:"groupMemberUserAttribute,omitempty"        norman:"default=entryDN,notnullable"`
	GroupMemberMappingAttribute  string `json:"groupMemberMappingAttribute,omitempty"     norman:"default=member,notnullable,required"`
	NestedGroupMembershipEnabled bool   `json:"nestedGroupMembershipEnabled"              norman:"default=false"`
	SearchUsingServiceAccount    bool   `json:"searchUsingServiceAccount"       norman:"default=false"`
}

type LdapConfig struct {
	LdapFields `json:",inline" mapstructure:",squash"`
}

func (c *LdapConfig) GetUserSearchAttributes(searchAttributes ...string) []string {
	userSearchAttributes := []string{
		"dn",
		c.UserMemberAttribute,
		c.UserObjectClass,
		c.UserLoginAttribute,
		c.UserNameAttribute,
		c.UserEnabledAttribute,
	}
	return append(userSearchAttributes, searchAttributes...)
}

func (c *LdapConfig) GetGroupSearchAttributes(searchAttributes ...string) []string {
	groupSeachAttributes := []string{
		c.GroupMemberUserAttribute,
		c.GroupObjectClass,
		c.UserLoginAttribute,
		c.GroupNameAttribute,
		c.GroupSearchAttribute,
	}
	return append(groupSeachAttributes, searchAttributes...)
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type SamlConfig struct {
	AuthConfig `json:",inline" mapstructure:",squash"`

	// Flag. True when the auth provider is configured to accept a `Logout All`
	// operation. Can be set if and only if the provider supports `Logout All`
	// (see AuthConfig.LogoutAllSupported).
	LogoutAllEnabled bool `json:"logoutAllEnabled,omitempty"`

	// Flag. Can be set if and only if `LogoutAllEnabled` (above) is set.
	// When set `Logout All` is the only kind of logout accepted. A regular
	// logout request will be rejected.
	LogoutAllForced bool `json:"logoutAllForced,omitempty"`

	IDPMetadataContent string `json:"idpMetadataContent" norman:"required"`
	SpCert             string `json:"spCert"             norman:"required"`
	SpKey              string `json:"spKey"              norman:"required,type=password"`
	GroupsField        string `json:"groupsField"        norman:"required"`
	DisplayNameField   string `json:"displayNameField"   norman:"required"`
	UserNameField      string `json:"userNameField"      norman:"required"`
	UIDField           string `json:"uidField"           norman:"required"`
	RancherAPIHost     string `json:"rancherApiHost"     norman:"required"`
	EntityID           string `json:"entityID"`
}

type GithubConfigTestOutput struct {
	RedirectURL string `json:"redirectUrl"`
}

type GithubConfigApplyInput struct {
	GithubConfig GithubConfig `json:"githubConfig,omitempty"`
	Code         string       `json:"code,omitempty"`
	Enabled      bool         `json:"enabled,omitempty"`
}

type GoogleOauthConfigTestOutput struct {
	RedirectURL string `json:"redirectUrl"`
}

type GoogleOauthConfigApplyInput struct {
	GoogleOauthConfig GoogleOauthConfig `json:"googleOauthConfig,omitempty"`
	Code              string            `json:"code,omitempty"`
	Enabled           bool              `json:"enabled,omitempty"`
}

type AzureADConfigTestOutput struct {
	RedirectURL string `json:"redirectUrl"`
}

type AzureADConfigApplyInput struct {
	Config AzureADConfig `json:"config,omitempty"`
	Code   string        `json:"code,omitempty"`
}

type SamlConfigTestInput struct {
	FinalRedirectURL string `json:"finalRedirectUrl"`
}

type SamlConfigTestOutput struct {
	IdpRedirectURL string `json:"idpRedirectUrl"`
}

type AuthConfigLogoutInput struct {
	FinalRedirectURL string `json:"finalRedirectUrl"`
}

type AuthConfigLogoutOutput struct {
	IdpRedirectURL string `json:"idpRedirectUrl"`
}

type PingConfig struct {
	SamlConfig `json:",inline" mapstructure:",squash"`
}

type ADFSConfig struct {
	SamlConfig `json:",inline" mapstructure:",squash"`
}

type KeyCloakConfig struct {
	SamlConfig `json:",inline" mapstructure:",squash"`
}

type OKTAConfig struct {
	SamlConfig     `json:",inline" mapstructure:",squash"`
	OpenLdapConfig LdapFields `json:"openLdapConfig"`
}

type ShibbolethConfig struct {
	SamlConfig     `json:",inline" mapstructure:",squash"`
	OpenLdapConfig LdapFields `json:"openLdapConfig"`
}

type AuthSystemImages struct {
	KubeAPIAuth string `json:"kubeAPIAuth,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type OIDCConfig struct {
	AuthConfig `json:",inline" mapstructure:",squash"`

	ClientID           string `json:"clientId" norman:"required"`
	ClientSecret       string `json:"clientSecret,omitempty" norman:"required,type=password"`
	RancherURL         string `json:"rancherUrl" norman:"required,notnullable"`
	Issuer             string `json:"issuer" norman:"required,notnullable"`
	AuthEndpoint       string `json:"authEndpoint,omitempty"`
	TokenEndpoint      string `json:"tokenEndpoint,omitempty"`
	UserInfoEndpoint   string `json:"userInfoEndpoint,omitempty"`
	JWKSUrl            string `json:"jwksUrl,omitempty"`
	Certificate        string `json:"certificate,omitempty"`
	PrivateKey         string `json:"privateKey,omitempty" norman:"type=password"`
	GroupSearchEnabled *bool  `json:"groupSearchEnabled"`
	// Scopes is expected to be a space delimited list of scopes
	Scopes string `json:"scope,omitempty"`
	// AcrValue is expected to be string containing the required ACR value
	AcrValue string `json:"acrValue,omitempty"`

	// This is provided by the OIDC Provider - it is the `end_session_uri` from
	// the discovery data.
	EndSessionEndpoint string `json:"endSessionEndpoint,omitempty"`
	// Flag. True when the auth provider is configured to accept a `Logout All`
	// operation. Can be set if and only if the provider supports `Logout All`
	// (see AuthConfig.LogoutAllSupported).
	LogoutAllEnabled bool `json:"logoutAllEnabled,omitempty"`

	// Flag. Can be set if and only if `LogoutAllEnabled` (above) is set.
	// When set `Logout All` is the only kind of logout accepted. A regular
	// logout request will be rejected.
	LogoutAllForced bool `json:"logoutAllForced,omitempty"`

	// GroupsClaim is used instead of groups
	GroupsClaim string `json:"groupsClaim,omitempty"`

	// NameClaim is used instead instead of the name claim.
	NameClaim string `json:"nameClaim,omitempty"`

	// EmailClaim is used instead of email
	EmailClaim string `json:"emailClaim,omitempty"`
}

type OIDCTestOutput struct {
	RedirectURL string `json:"redirectUrl"`
}

type OIDCApplyInput struct {
	OIDCConfig OIDCConfig `json:"oidcConfig,omitempty"`
	Code       string     `json:"code,omitempty"`
	Enabled    bool       `json:"enabled,omitempty"`
}

type KeyCloakOIDCConfig struct {
	OIDCConfig `json:",inline" mapstructure:",squash"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ClusterProxyConfig determines which downstream requests will be proxied to the downstream cluster for requests that contain service account tokens.
// Objects of this type are created in the namespace of the target cluster.  If no object exists, the feature will be disabled by default.
type ClusterProxyConfig struct {
	types.Namespaced  `json:",inline"`
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Enabled indicates whether downstream proxy requests for service account tokens is enabled.
	Enabled bool `json:"enabled"`
}

// GenericOIDCConfig is the wrapper for the Generic OIDC provider to hold the OIDC Configuration
type GenericOIDCConfig struct {
	OIDCConfig `json:",inline" mapstructure:",squash"`
}

// GenericOIDCTestOutput is the wrapper for the Generic OIDC provider to hold the OIDC test output object, which
// in turn holds the RedirectURL
type GenericOIDCTestOutput struct {
	OIDCTestOutput `json:",inline" mapstructure:",squash"`
}

// GenericOIDCApplyInput is the wrapper for the input used to enable/activate the Generic OIDC auth provider.  It holds
// the configuration for the OIDC provider as well as an auth code.
type GenericOIDCApplyInput struct {
	OIDCApplyInput `json:",inline" mapstructure:",squash"`
}

// GenericOIDCConfig is a wrapper for the AWS Cognito provider holding the OIDC Configuration
type CognitoConfig struct {
	OIDCConfig `json:",inline" mapstructure:",squash"`
}
