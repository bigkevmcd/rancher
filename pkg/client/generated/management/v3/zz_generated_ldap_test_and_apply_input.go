package client

const (
	LdapTestAndApplyInputType            = "ldapTestAndApplyInput"
	LdapTestAndApplyInputFieldLdapConfig = "ldapConfig"
	LdapTestAndApplyInputFieldPassword   = "password"
	LdapTestAndApplyInputFieldUsername   = "username"
)

type LdapTestAndApplyInput struct {
	LdapConfig *LdapConfig `json:"ldapConfig,omitempty" yaml:"ldapConfig,omitempty"`
	Password   string      `json:"password,omitempty" yaml:"password,omitempty"`
	Username   string      `json:"username,omitempty" yaml:"username,omitempty"`
}
