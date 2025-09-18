package client

const (
	AuthConfigStatusType            = "authConfigStatus"
	AuthConfigStatusFieldConditions = "conditions"
)

type AuthConfigStatus struct {
	Conditions []Condition `json:"conditions,omitempty" yaml:"conditions,omitempty"`
}
