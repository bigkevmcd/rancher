package client

const (
	LdapConfigType                                 = "ldapConfig"
	LdapConfigFieldCertificate                     = "certificate"
	LdapConfigFieldConnectionTimeout               = "connectionTimeout"
	LdapConfigFieldGroupDNAttribute                = "groupDNAttribute"
	LdapConfigFieldGroupMemberMappingAttribute     = "groupMemberMappingAttribute"
	LdapConfigFieldGroupMemberUserAttribute        = "groupMemberUserAttribute"
	LdapConfigFieldGroupNameAttribute              = "groupNameAttribute"
	LdapConfigFieldGroupObjectClass                = "groupObjectClass"
	LdapConfigFieldGroupSearchAttribute            = "groupSearchAttribute"
	LdapConfigFieldGroupSearchBase                 = "groupSearchBase"
	LdapConfigFieldGroupSearchFilter               = "groupSearchFilter"
	LdapConfigFieldNestedGroupMembershipEnabled    = "nestedGroupMembershipEnabled"
	LdapConfigFieldPort                            = "port"
	LdapConfigFieldSearchUsingServiceAccount       = "searchUsingServiceAccount"
	LdapConfigFieldServers                         = "servers"
	LdapConfigFieldServiceAccountDistinguishedName = "serviceAccountDistinguishedName"
	LdapConfigFieldServiceAccountPassword          = "serviceAccountPassword"
	LdapConfigFieldStartTLS                        = "starttls"
	LdapConfigFieldTLS                             = "tls"
	LdapConfigFieldUserDisabledBitMask             = "userDisabledBitMask"
	LdapConfigFieldUserEnabledAttribute            = "userEnabledAttribute"
	LdapConfigFieldUserLoginAttribute              = "userLoginAttribute"
	LdapConfigFieldUserLoginFilter                 = "userLoginFilter"
	LdapConfigFieldUserMemberAttribute             = "userMemberAttribute"
	LdapConfigFieldUserNameAttribute               = "userNameAttribute"
	LdapConfigFieldUserObjectClass                 = "userObjectClass"
	LdapConfigFieldUserSearchAttribute             = "userSearchAttribute"
	LdapConfigFieldUserSearchBase                  = "userSearchBase"
	LdapConfigFieldUserSearchFilter                = "userSearchFilter"
)

type LdapConfig struct {
	Certificate                     string   `json:"certificate,omitempty" yaml:"certificate,omitempty"`
	ConnectionTimeout               int64    `json:"connectionTimeout,omitempty" yaml:"connectionTimeout,omitempty"`
	GroupDNAttribute                string   `json:"groupDNAttribute,omitempty" yaml:"groupDNAttribute,omitempty"`
	GroupMemberMappingAttribute     string   `json:"groupMemberMappingAttribute,omitempty" yaml:"groupMemberMappingAttribute,omitempty"`
	GroupMemberUserAttribute        string   `json:"groupMemberUserAttribute,omitempty" yaml:"groupMemberUserAttribute,omitempty"`
	GroupNameAttribute              string   `json:"groupNameAttribute,omitempty" yaml:"groupNameAttribute,omitempty"`
	GroupObjectClass                string   `json:"groupObjectClass,omitempty" yaml:"groupObjectClass,omitempty"`
	GroupSearchAttribute            string   `json:"groupSearchAttribute,omitempty" yaml:"groupSearchAttribute,omitempty"`
	GroupSearchBase                 string   `json:"groupSearchBase,omitempty" yaml:"groupSearchBase,omitempty"`
	GroupSearchFilter               string   `json:"groupSearchFilter,omitempty" yaml:"groupSearchFilter,omitempty"`
	NestedGroupMembershipEnabled    bool     `json:"nestedGroupMembershipEnabled,omitempty" yaml:"nestedGroupMembershipEnabled,omitempty"`
	Port                            int64    `json:"port,omitempty" yaml:"port,omitempty"`
	SearchUsingServiceAccount       bool     `json:"searchUsingServiceAccount,omitempty" yaml:"searchUsingServiceAccount,omitempty"`
	Servers                         []string `json:"servers,omitempty" yaml:"servers,omitempty"`
	ServiceAccountDistinguishedName string   `json:"serviceAccountDistinguishedName,omitempty" yaml:"serviceAccountDistinguishedName,omitempty"`
	ServiceAccountPassword          string   `json:"serviceAccountPassword,omitempty" yaml:"serviceAccountPassword,omitempty"`
	StartTLS                        bool     `json:"starttls,omitempty" yaml:"starttls,omitempty"`
	TLS                             bool     `json:"tls,omitempty" yaml:"tls,omitempty"`
	UserDisabledBitMask             int64    `json:"userDisabledBitMask,omitempty" yaml:"userDisabledBitMask,omitempty"`
	UserEnabledAttribute            string   `json:"userEnabledAttribute,omitempty" yaml:"userEnabledAttribute,omitempty"`
	UserLoginAttribute              string   `json:"userLoginAttribute,omitempty" yaml:"userLoginAttribute,omitempty"`
	UserLoginFilter                 string   `json:"userLoginFilter,omitempty" yaml:"userLoginFilter,omitempty"`
	UserMemberAttribute             string   `json:"userMemberAttribute,omitempty" yaml:"userMemberAttribute,omitempty"`
	UserNameAttribute               string   `json:"userNameAttribute,omitempty" yaml:"userNameAttribute,omitempty"`
	UserObjectClass                 string   `json:"userObjectClass,omitempty" yaml:"userObjectClass,omitempty"`
	UserSearchAttribute             string   `json:"userSearchAttribute,omitempty" yaml:"userSearchAttribute,omitempty"`
	UserSearchBase                  string   `json:"userSearchBase,omitempty" yaml:"userSearchBase,omitempty"`
	UserSearchFilter                string   `json:"userSearchFilter,omitempty" yaml:"userSearchFilter,omitempty"`
}
