package tokens

import (
	"fmt"

	ext "github.com/rancher/rancher/pkg/apis/ext.cattle.io/v1"
	"k8s.io/apimachinery/pkg/util/validation"
)

const (
	maxAgentRules      = 32
	maxAgentRuleValues = 64
)

// ValidateAgent checks the agent part of a token spec against its kind. Tokens of kind "agent"
// require a well-formed agent, every other kind must not have one.
func ValidateAgent(kind string, agent *ext.TokenAgent) error {
	if kind != KindAgent {
		if agent != nil {
			return fmt.Errorf("spec.agent is only allowed for tokens of kind %q", KindAgent)
		}
		return nil
	}
	if agent == nil {
		return fmt.Errorf("spec.agent is required for tokens of kind %q", KindAgent)
	}
	if errs := validation.IsDNS1123Label(agent.Name); len(errs) > 0 {
		return fmt.Errorf("spec.agent.name %q is invalid: %s", agent.Name, errs[0])
	}
	if len(agent.Rules) == 0 {
		return fmt.Errorf("spec.agent.rules requires at least one rule")
	}
	if len(agent.Rules) > maxAgentRules {
		return fmt.Errorf("spec.agent.rules allows at most %d rules", maxAgentRules)
	}
	for i, rule := range agent.Rules {
		for field, values := range map[string][]string{
			"verbs":     rule.Verbs,
			"apiGroups": rule.APIGroups,
			"resources": rule.Resources,
		} {
			if len(values) == 0 {
				return fmt.Errorf("spec.agent.rules[%d].%s must not be empty", i, field)
			}
			if len(values) > maxAgentRuleValues {
				return fmt.Errorf("spec.agent.rules[%d].%s allows at most %d entries", i, field, maxAgentRuleValues)
			}
			for _, v := range values {
				// The empty string is only meaningful for apiGroups, as the core group.
				if v == "" && field != "apiGroups" {
					return fmt.Errorf("spec.agent.rules[%d].%s must not contain empty entries", i, field)
				}
				if len(v) > 253 {
					return fmt.Errorf("spec.agent.rules[%d].%s has an entry which is too long", i, field)
				}
			}
		}
	}
	return nil
}
