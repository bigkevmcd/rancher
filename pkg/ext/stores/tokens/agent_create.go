package tokens

import (
	"fmt"

	ext "github.com/rancher/rancher/pkg/apis/ext.cattle.io/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/registry/rest"
)

// AgentTokenRequest describes an agent token to be created by Rancher itself, on behalf of a user,
// without a request token to derive anything from. The user's consent or the admin's trust
// configuration that justifies the token is the caller's to establish.
type AgentTokenRequest struct {
	// UserID is the Rancher user the agent acts for.
	UserID string
	// Agent names the agent and limits the token.
	Agent ext.TokenAgent
	// TTL is the time to live in milliseconds, 0 for the default. It is limited to the agent token
	// max TTL.
	TTL int64
	// Description is shown with the token.
	Description string
	// Labels are added to the token, e.g. to find the tokens issued for a trust.
	Labels map[string]string
}

// CreateAgentToken creates an agent token for the user and returns it with its value, which is only
// ever available here. The token is owned by the user's local principal. Disabled and system users
// are refused.
func (t *SystemStore) CreateAgentToken(req AgentTokenRequest) (*ext.Token, error) {
	if err := ValidateAgent(KindAgent, &req.Agent); err != nil {
		return nil, apierrors.NewBadRequest(err.Error())
	}

	user, err := t.userClient.Get(req.UserID)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil, apierrors.NewBadRequest(fmt.Sprintf("user %s not found", req.UserID))
		}
		return nil, apierrors.NewInternalError(fmt.Errorf("failed to retrieve user %s: %w", req.UserID, err))
	}
	if user.Enabled != nil && !*user.Enabled {
		return nil, apierrors.NewBadRequest("operation references a disabled user")
	}
	if user.IsSystem() {
		return nil, apierrors.NewBadRequest("agent tokens can't be created for system users")
	}

	tokenValue, hashedValue, err := t.hasher.MakeAndHashSecret()
	if err != nil {
		return nil, err
	}

	token := &ext.Token{
		ObjectMeta: metav1.ObjectMeta{Labels: req.Labels},
		Spec: ext.TokenSpec{
			UserID: req.UserID,
			UserPrincipal: ext.TokenPrincipal{
				Name:          "local://" + req.UserID,
				DisplayName:   user.DisplayName,
				LoginName:     user.Username,
				PrincipalType: "user",
				Provider:      "local",
			},
			Kind:        KindAgent,
			Description: req.Description,
			TTL:         req.TTL,
			Agent:       &req.Agent,
		},
		Status: ext.TokenStatus{
			Hash:           hashedValue,
			LastUpdateTime: t.timer.Now(),
		},
	}
	rest.FillObjectMetaSystemFields(token)

	secret, err := toSecret(token)
	if err != nil {
		return nil, apierrors.NewInternalError(fmt.Errorf("failed to convert token for storage: %w", err))
	}
	secret.ObjectMeta.Name = ""
	secret.ObjectMeta.GenerateName = GeneratePrefix

	if err := t.ensureNamespace(); err != nil {
		return nil, apierrors.NewInternalError(fmt.Errorf("error ensuring namespace %s: %w", TokenNamespace, err))
	}

	newSecret, err := t.secretClient.Create(secret)
	if err != nil {
		return nil, mapBackingError(err, GeneratePrefix)
	}

	newToken, err := fromSecret(newSecret)
	if err != nil {
		// Do not leave something broken behind.
		_ = t.secretClient.Delete(TokenNamespace, newSecret.Name, &metav1.DeleteOptions{})
		return nil, apierrors.NewInternalError(fmt.Errorf("failed to regenerate token %s: %w", newSecret.Name, err))
	}

	newToken.Status.Hash = ""
	newToken.Status.Value = tokenValue
	newToken.Status.BearerToken = fmt.Sprintf("ext/%s:%s", newToken.Name, tokenValue)

	return newToken, nil
}
