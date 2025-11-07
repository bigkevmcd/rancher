package client

const (
	AuthConfigSpecType        = "authConfigSpec"
	AuthConfigSpecFieldGithub = "github"
)

type AuthConfigSpec struct {
	Github *GithubConfig `json:"github,omitempty" yaml:"github,omitempty"`
}
