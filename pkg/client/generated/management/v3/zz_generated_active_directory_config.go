package client

const (
	ActiveDirectoryConfigType                              = "activeDirectoryConfig"
	ActiveDirectoryConfigFieldCertificate                  = "certificate"
	ActiveDirectoryConfigFieldConnectionTimeout            = "connectionTimeout"
	ActiveDirectoryConfigFieldDefaultLoginDomain           = "defaultLoginDomain"
	ActiveDirectoryConfigFieldGroupDNAttribute             = "groupDNAttribute"
	ActiveDirectoryConfigFieldGroupMemberMappingAttribute  = "groupMemberMappingAttribute"
	ActiveDirectoryConfigFieldGroupMemberUserAttribute     = "groupMemberUserAttribute"
	ActiveDirectoryConfigFieldGroupNameAttribute           = "groupNameAttribute"
	ActiveDirectoryConfigFieldGroupObjectClass             = "groupObjectClass"
	ActiveDirectoryConfigFieldGroupSearchAttribute         = "groupSearchAttribute"
	ActiveDirectoryConfigFieldGroupSearchBase              = "groupSearchBase"
	ActiveDirectoryConfigFieldGroupSearchFilter            = "groupSearchFilter"
	ActiveDirectoryConfigFieldNestedGroupMembershipEnabled = "nestedGroupMembershipEnabled"
	ActiveDirectoryConfigFieldPort                         = "port"
	ActiveDirectoryConfigFieldServers                      = "servers"
	ActiveDirectoryConfigFieldServiceAccountPassword       = "serviceAccountPassword"
	ActiveDirectoryConfigFieldServiceAccountUsername       = "serviceAccountUsername"
	ActiveDirectoryConfigFieldStartTLS                     = "starttls"
	ActiveDirectoryConfigFieldTLS                          = "tls"
	ActiveDirectoryConfigFieldUserDisabledBitMask          = "userDisabledBitMask"
	ActiveDirectoryConfigFieldUserEnabledAttribute         = "userEnabledAttribute"
	ActiveDirectoryConfigFieldUserLoginAttribute           = "userLoginAttribute"
	ActiveDirectoryConfigFieldUserLoginFilter              = "userLoginFilter"
	ActiveDirectoryConfigFieldUserNameAttribute            = "userNameAttribute"
	ActiveDirectoryConfigFieldUserObjectClass              = "userObjectClass"
	ActiveDirectoryConfigFieldUserSearchAttribute          = "userSearchAttribute"
	ActiveDirectoryConfigFieldUserSearchBase               = "userSearchBase"
	ActiveDirectoryConfigFieldUserSearchFilter             = "userSearchFilter"
)

type ActiveDirectoryConfig struct {
	Certificate                  string   `json:"certificate,omitempty" yaml:"certificate,omitempty"`
	ConnectionTimeout            int64    `json:"connectionTimeout,omitempty" yaml:"connectionTimeout,omitempty"`
	DefaultLoginDomain           string   `json:"defaultLoginDomain,omitempty" yaml:"defaultLoginDomain,omitempty"`
	GroupDNAttribute             string   `json:"groupDNAttribute,omitempty" yaml:"groupDNAttribute,omitempty"`
	GroupMemberMappingAttribute  string   `json:"groupMemberMappingAttribute,omitempty" yaml:"groupMemberMappingAttribute,omitempty"`
	GroupMemberUserAttribute     string   `json:"groupMemberUserAttribute,omitempty" yaml:"groupMemberUserAttribute,omitempty"`
	GroupNameAttribute           string   `json:"groupNameAttribute,omitempty" yaml:"groupNameAttribute,omitempty"`
	GroupObjectClass             string   `json:"groupObjectClass,omitempty" yaml:"groupObjectClass,omitempty"`
	GroupSearchAttribute         string   `json:"groupSearchAttribute,omitempty" yaml:"groupSearchAttribute,omitempty"`
	GroupSearchBase              string   `json:"groupSearchBase,omitempty" yaml:"groupSearchBase,omitempty"`
	GroupSearchFilter            string   `json:"groupSearchFilter,omitempty" yaml:"groupSearchFilter,omitempty"`
	NestedGroupMembershipEnabled *bool    `json:"nestedGroupMembershipEnabled,omitempty" yaml:"nestedGroupMembershipEnabled,omitempty"`
	Port                         int64    `json:"port,omitempty" yaml:"port,omitempty"`
	Servers                      []string `json:"servers,omitempty" yaml:"servers,omitempty"`
	ServiceAccountPassword       string   `json:"serviceAccountPassword,omitempty" yaml:"serviceAccountPassword,omitempty"`
	ServiceAccountUsername       string   `json:"serviceAccountUsername,omitempty" yaml:"serviceAccountUsername,omitempty"`
	StartTLS                     bool     `json:"starttls,omitempty" yaml:"starttls,omitempty"`
	TLS                          bool     `json:"tls,omitempty" yaml:"tls,omitempty"`
	UserDisabledBitMask          int64    `json:"userDisabledBitMask,omitempty" yaml:"userDisabledBitMask,omitempty"`
	UserEnabledAttribute         string   `json:"userEnabledAttribute,omitempty" yaml:"userEnabledAttribute,omitempty"`
	UserLoginAttribute           string   `json:"userLoginAttribute,omitempty" yaml:"userLoginAttribute,omitempty"`
	UserLoginFilter              string   `json:"userLoginFilter,omitempty" yaml:"userLoginFilter,omitempty"`
	UserNameAttribute            string   `json:"userNameAttribute,omitempty" yaml:"userNameAttribute,omitempty"`
	UserObjectClass              string   `json:"userObjectClass,omitempty" yaml:"userObjectClass,omitempty"`
	UserSearchAttribute          string   `json:"userSearchAttribute,omitempty" yaml:"userSearchAttribute,omitempty"`
	UserSearchBase               string   `json:"userSearchBase,omitempty" yaml:"userSearchBase,omitempty"`
	UserSearchFilter             string   `json:"userSearchFilter,omitempty" yaml:"userSearchFilter,omitempty"`
}
