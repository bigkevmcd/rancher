package requests

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	ext "github.com/rancher/rancher/pkg/apis/ext.cattle.io/v1"
	apiv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/rancher/pkg/auth/providers"
	"github.com/rancher/rancher/pkg/auth/providers/common"
	"github.com/rancher/rancher/pkg/auth/tokens/hashers"
	"github.com/rancher/rancher/pkg/clusterrouter"
	exttokenstore "github.com/rancher/rancher/pkg/ext/stores/tokens"
	mgmtFakes "github.com/rancher/rancher/pkg/generated/norman/management.cattle.io/v3/fakes"
	"github.com/rancher/wrangler/v3/pkg/generic/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"
)

// TestAuthenticateAgentToken checks that Authenticate applies the rules of agent tokens, for the
// token read back from its backing secret, and reports the agent in the audit identity.
func TestAuthenticateAgentToken(t *testing.T) {
	defer providers.SetProviders(nil)
	fakeProvider := &fakeProvider{name: "fake"}
	providers.SetProviders(map[string]common.AuthProvider{fakeProvider.name: fakeProvider})

	now := time.Now()
	userID := "u-abcdef"
	principalID := fakeProvider.name + "_user://12345"
	user := &apiv3.User{ObjectMeta: metav1.ObjectMeta{Name: userID}, Username: "fake-user", PrincipalIDs: []string{principalID}}

	tokenValue := "jnb9tksmnctvgbn92ngbkptblcjwg4pmfp98wqj29wk5kv85ktg59s"
	tokenHash, err := hashers.GetHasher().CreateHash(tokenValue)
	require.NoError(t, err)

	principalBytes, err := json.Marshal(ext.TokenPrincipal{Name: principalID, Provider: fakeProvider.name, LoginName: user.Username})
	require.NoError(t, err)
	agentBytes, err := json.Marshal(ext.TokenAgent{Name: "pod-reader", Rules: []ext.TokenAgentRule{
		{Verbs: []string{"get", "list"}, APIGroups: []string{""}, Resources: []string{"pods"}},
	}})
	require.NoError(t, err)

	newSecret := func(kind string, agent []byte) *corev1.Secret {
		data := map[string][]byte{
			exttokenstore.FieldEnabled:        []byte("true"),
			exttokenstore.FieldHash:           []byte(tokenHash),
			exttokenstore.FieldKind:           []byte(kind),
			exttokenstore.FieldLastUpdateTime: []byte("13:00"),
			exttokenstore.FieldPrincipal:      principalBytes,
			exttokenstore.FieldTTL:            []byte("3600000"),
			exttokenstore.FieldUID:            []byte("2905498-kafld-lkad"),
			exttokenstore.FieldUserID:         []byte(userID),
		}
		if agent != nil {
			data[exttokenstore.FieldAgent] = agent
		}
		return &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "token-agent1",
				CreationTimestamp: metav1.NewTime(now),
				Labels: map[string]string{
					exttokenstore.UserIDLabel:     userID,
					exttokenstore.SecretKindLabel: exttokenstore.SecretKindLabelValue,
				},
			},
			Data: data,
		}
	}

	newAuthenticator := func(t *testing.T, secret *corev1.Secret) *tokenAuthenticator {
		ctrl := gomock.NewController(t)
		secrets := fake.NewMockControllerInterface[*corev1.Secret, *corev1.SecretList](ctrl)
		scache := fake.NewMockCacheInterface[*corev1.Secret](ctrl)
		users := fake.NewMockNonNamespacedControllerInterface[*apiv3.User, *apiv3.UserList](ctrl)
		users.EXPECT().Cache().Return(nil).AnyTimes()
		secrets.EXPECT().Cache().Return(scache)
		scache.EXPECT().Get("cattle-tokens", secret.Name).Return(secret, nil).AnyTimes()
		secrets.EXPECT().Patch("cattle-tokens", secret.Name, k8stypes.JSONPatchType, gomock.Any()).
			Return(nil, nil).AnyTimes()

		return &tokenAuthenticator{
			ctx: context.Background(),
			userAttributeLister: &mgmtFakes.UserAttributeListerMock{
				GetFunc: func(_, _ string) (*apiv3.UserAttribute, error) { return nil, nil },
			},
			userLister: &mgmtFakes.UserListerMock{
				GetFunc: func(_, _ string) (*apiv3.User, error) { return user, nil },
			},
			clusterRouter: clusterrouter.GetClusterID,
			refreshUser:   (&fakeUserRefresher{}).refreshUser,
			now:           func() time.Time { return now },
			extTokenStore: exttokenstore.NewSystem(nil, nil, secrets, users, nil, nil, nil, nil, nil),
		}
	}

	request := func(method, url string) *http.Request {
		req := httptest.NewRequest(method, url, nil)
		req.Header.Set("Authorization", "Bearer ext/token-agent1:"+tokenValue)
		return req
	}

	t.Run("allowed request authenticates and names the agent", func(t *testing.T) {
		a := newAuthenticator(t, newSecret(exttokenstore.KindAgent, agentBytes))
		resp, err := a.Authenticate(request(http.MethodGet, "/v1/pods"))
		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.True(t, resp.IsAuthed)
		assert.Equal(t, userID, resp.User)
		assert.Equal(t, "fake-user", resp.Identity.Username)
		assert.Equal(t, "pod-reader", resp.Identity.Agent)
	})

	for _, tc := range []struct{ name, method, url string }{
		{"resource outside the rules", http.MethodGet, "/v1/secrets"},
		{"verb outside the rules", http.MethodDelete, "/v1/pods/default/p1"},
		{"api not available to agents", http.MethodGet, "/v3/users"},
		{"login api", http.MethodGet, "/v3-public/authProviders"},
		{"cluster proxy outside the rules", http.MethodGet, "/k8s/clusters/c-m-abc/api/v1/namespaces/default/secrets"},
	} {
		t.Run("denied: "+tc.name, func(t *testing.T) {
			a := newAuthenticator(t, newSecret(exttokenstore.KindAgent, agentBytes))
			resp, err := a.Authenticate(request(tc.method, tc.url))
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrMustAuthenticate)
			assert.Nil(t, resp)
		})
	}

	t.Run("denied: kind agent without an agent is malformed", func(t *testing.T) {
		a := newAuthenticator(t, newSecret(exttokenstore.KindAgent, nil))
		resp, err := a.Authenticate(request(http.MethodGet, "/v1/pods"))
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrMustAuthenticate)
		assert.Nil(t, resp)
	})

	t.Run("denied: an agent on a token of another kind is still limited", func(t *testing.T) {
		a := newAuthenticator(t, newSecret("", agentBytes))
		_, err := a.Authenticate(request(http.MethodGet, "/v3/users"))
		require.Error(t, err)
	})

	t.Run("other tokens are not limited", func(t *testing.T) {
		a := newAuthenticator(t, newSecret("", nil))
		resp, err := a.Authenticate(request(http.MethodGet, "/v3/users"))
		require.NoError(t, err)
		assert.True(t, resp.IsAuthed)
		assert.Empty(t, resp.Identity.Agent)
	})
}
