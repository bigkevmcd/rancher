package clusterauthtoken

import (
	"testing"

	extv1 "github.com/rancher/rancher/pkg/apis/ext.cattle.io/v1"
	"github.com/rancher/wrangler/v3/pkg/generic"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Agent tokens must not be synced downstream: the downstream cluster verifies a ClusterAuthToken
// alone, without the token's rules, so the token would have its owner's full permissions there.
func TestAgentTokensAreNotSynced(t *testing.T) {
	agent := &extv1.TokenAgent{Name: "a"}
	tests := map[string]*extv1.Token{
		"kind agent": {Spec: extv1.TokenSpec{UserID: "u-1", Kind: "agent", Agent: agent}},
		"kind only":  {Spec: extv1.TokenSpec{UserID: "u-1", Kind: "agent"}},
		"agent only": {Spec: extv1.TokenSpec{UserID: "u-1", Agent: agent}},
	}
	for name, token := range tests {
		t.Run(name, func(t *testing.T) {
			require.True(t, skipAgentToken(token))

			// No client is used: the handler returns before touching anything.
			h := &tokenHandler{}
			_, err := h.extCreate(token)
			assert.ErrorIs(t, err, generic.ErrSkip)
			_, err = h.ExtUpdated(token)
			assert.ErrorIs(t, err, generic.ErrSkip)
		})
	}

	assert.False(t, skipAgentToken(&extv1.Token{Spec: extv1.TokenSpec{UserID: "u-1", Kind: "kubeconfig"}}))
}
