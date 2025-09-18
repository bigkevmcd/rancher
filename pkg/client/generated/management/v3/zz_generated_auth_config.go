package client

import (
	"github.com/rancher/norman/types"
)

const (
	AuthConfigType                      = "authConfig"
	AuthConfigFieldAccessMode           = "accessMode"
	AuthConfigFieldActiveDirectory      = "activedirectory"
	AuthConfigFieldAllowedPrincipalIDs  = "allowedPrincipalIds"
	AuthConfigFieldAnnotations          = "annotations"
	AuthConfigFieldAzureAD              = "azuread"
	AuthConfigFieldCreated              = "created"
	AuthConfigFieldCreatorID            = "creatorId"
	AuthConfigFieldEnabled              = "enabled"
	AuthConfigFieldFreeIPA              = "freeipa"
	AuthConfigFieldGithub               = "github"
	AuthConfigFieldGoogleOauth          = "googleoauth"
	AuthConfigFieldLabels               = "labels"
	AuthConfigFieldLocal                = "local"
	AuthConfigFieldLogoutAllSupported   = "logoutAllSupported"
	AuthConfigFieldName                 = "name"
	AuthConfigFieldOpenLDAP             = "openldap"
	AuthConfigFieldOwnerReferences      = "ownerReferences"
	AuthConfigFieldRemoved              = "removed"
	AuthConfigFieldState                = "state"
	AuthConfigFieldStatus               = "status"
	AuthConfigFieldTransitioning        = "transitioning"
	AuthConfigFieldTransitioningMessage = "transitioningMessage"
	AuthConfigFieldType                 = "type"
	AuthConfigFieldUUID                 = "uuid"
)

type AuthConfig struct {
	types.Resource
	AccessMode           string                 `json:"accessMode,omitempty" yaml:"accessMode,omitempty"`
	ActiveDirectory      *ActiveDirectoryConfig `json:"activedirectory,omitempty" yaml:"activedirectory,omitempty"`
	AllowedPrincipalIDs  []string               `json:"allowedPrincipalIds,omitempty" yaml:"allowedPrincipalIds,omitempty"`
	Annotations          map[string]string      `json:"annotations,omitempty" yaml:"annotations,omitempty"`
	AzureAD              *AzureADConfig         `json:"azuread,omitempty" yaml:"azuread,omitempty"`
	Created              string                 `json:"created,omitempty" yaml:"created,omitempty"`
	CreatorID            string                 `json:"creatorId,omitempty" yaml:"creatorId,omitempty"`
	Enabled              bool                   `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	FreeIPA              *LdapFields            `json:"freeipa,omitempty" yaml:"freeipa,omitempty"`
	Github               *GithubConfig          `json:"github,omitempty" yaml:"github,omitempty"`
	GoogleOauth          *GoogleOauthConfig     `json:"googleoauth,omitempty" yaml:"googleoauth,omitempty"`
	Labels               map[string]string      `json:"labels,omitempty" yaml:"labels,omitempty"`
	Local                *LocalAuthConfig       `json:"local,omitempty" yaml:"local,omitempty"`
	LogoutAllSupported   bool                   `json:"logoutAllSupported,omitempty" yaml:"logoutAllSupported,omitempty"`
	Name                 string                 `json:"name,omitempty" yaml:"name,omitempty"`
	OpenLDAP             *LdapFields            `json:"openldap,omitempty" yaml:"openldap,omitempty"`
	OwnerReferences      []OwnerReference       `json:"ownerReferences,omitempty" yaml:"ownerReferences,omitempty"`
	Removed              string                 `json:"removed,omitempty" yaml:"removed,omitempty"`
	State                string                 `json:"state,omitempty" yaml:"state,omitempty"`
	Status               *AuthConfigStatus      `json:"status,omitempty" yaml:"status,omitempty"`
	Transitioning        string                 `json:"transitioning,omitempty" yaml:"transitioning,omitempty"`
	TransitioningMessage string                 `json:"transitioningMessage,omitempty" yaml:"transitioningMessage,omitempty"`
	Type                 string                 `json:"type,omitempty" yaml:"type,omitempty"`
	UUID                 string                 `json:"uuid,omitempty" yaml:"uuid,omitempty"`
}

type AuthConfigCollection struct {
	types.Collection
	Data   []AuthConfig `json:"data,omitempty"`
	client *AuthConfigClient
}

type AuthConfigClient struct {
	apiClient *Client
}

type AuthConfigOperations interface {
	List(opts *types.ListOpts) (*AuthConfigCollection, error)
	ListAll(opts *types.ListOpts) (*AuthConfigCollection, error)
	Create(opts *AuthConfig) (*AuthConfig, error)
	Update(existing *AuthConfig, updates interface{}) (*AuthConfig, error)
	Replace(existing *AuthConfig) (*AuthConfig, error)
	ByID(id string) (*AuthConfig, error)
	Delete(container *AuthConfig) error
}

func newAuthConfigClient(apiClient *Client) *AuthConfigClient {
	return &AuthConfigClient{
		apiClient: apiClient,
	}
}

func (c *AuthConfigClient) Create(container *AuthConfig) (*AuthConfig, error) {
	resp := &AuthConfig{}
	err := c.apiClient.Ops.DoCreate(AuthConfigType, container, resp)
	return resp, err
}

func (c *AuthConfigClient) Update(existing *AuthConfig, updates interface{}) (*AuthConfig, error) {
	resp := &AuthConfig{}
	err := c.apiClient.Ops.DoUpdate(AuthConfigType, &existing.Resource, updates, resp)
	return resp, err
}

func (c *AuthConfigClient) Replace(obj *AuthConfig) (*AuthConfig, error) {
	resp := &AuthConfig{}
	err := c.apiClient.Ops.DoReplace(AuthConfigType, &obj.Resource, obj, resp)
	return resp, err
}

func (c *AuthConfigClient) List(opts *types.ListOpts) (*AuthConfigCollection, error) {
	resp := &AuthConfigCollection{}
	err := c.apiClient.Ops.DoList(AuthConfigType, opts, resp)
	resp.client = c
	return resp, err
}

func (c *AuthConfigClient) ListAll(opts *types.ListOpts) (*AuthConfigCollection, error) {
	resp := &AuthConfigCollection{}
	resp, err := c.List(opts)
	if err != nil {
		return resp, err
	}
	data := resp.Data
	for next, err := resp.Next(); next != nil && err == nil; next, err = next.Next() {
		data = append(data, next.Data...)
		resp = next
		resp.Data = data
	}
	if err != nil {
		return resp, err
	}
	return resp, err
}

func (cc *AuthConfigCollection) Next() (*AuthConfigCollection, error) {
	if cc != nil && cc.Pagination != nil && cc.Pagination.Next != "" {
		resp := &AuthConfigCollection{}
		err := cc.client.apiClient.Ops.DoNext(cc.Pagination.Next, resp)
		resp.client = cc.client
		return resp, err
	}
	return nil, nil
}

func (c *AuthConfigClient) ByID(id string) (*AuthConfig, error) {
	resp := &AuthConfig{}
	err := c.apiClient.Ops.DoByID(AuthConfigType, id, resp)
	return resp, err
}

func (c *AuthConfigClient) Delete(container *AuthConfig) error {
	return c.apiClient.Ops.DoResourceDelete(AuthConfigType, &container.Resource)
}
