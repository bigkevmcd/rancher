package tokens

import (
	"strings"
	"testing"
	"time"

	ext "github.com/rancher/rancher/pkg/apis/ext.cattle.io/v1"
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/rancher/pkg/settings"
	"github.com/rancher/wrangler/v3/pkg/generic/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/utils/ptr"
)

func validAgent() *ext.TokenAgent {
	return &ext.TokenAgent{
		Name: "scaler-1",
		Rules: []ext.TokenAgentRule{{
			Verbs:     []string{"get", "list"},
			APIGroups: []string{""},
			Resources: []string{"pods", "pods/log"},
		}},
	}
}

func TestValidateAgent(t *testing.T) {
	tooMany := validAgent()
	for range maxAgentRules {
		tooMany.Rules = append(tooMany.Rules, tooMany.Rules[0])
	}

	tests := []struct {
		name    string
		kind    string
		mutate  func(a *ext.TokenAgent) *ext.TokenAgent
		wantErr string
	}{
		{name: "valid", kind: KindAgent, mutate: func(a *ext.TokenAgent) *ext.TokenAgent { return a }},
		{name: "core group is the empty string", kind: KindAgent, mutate: func(a *ext.TokenAgent) *ext.TokenAgent {
			a.Rules[0].APIGroups = []string{""}
			return a
		}},
		{name: "wildcards are accepted", kind: KindAgent, mutate: func(a *ext.TokenAgent) *ext.TokenAgent {
			a.Rules[0] = ext.TokenAgentRule{Verbs: []string{"*"}, APIGroups: []string{"*"}, Resources: []string{"*"}}
			return a
		}},
		{name: "agent on a token of another kind", kind: "", mutate: func(a *ext.TokenAgent) *ext.TokenAgent { return a },
			wantErr: "only allowed for tokens of kind"},
		{name: "no agent on a token of another kind", kind: "", mutate: func(*ext.TokenAgent) *ext.TokenAgent { return nil }},
		{name: "kind agent requires an agent", kind: KindAgent, mutate: func(*ext.TokenAgent) *ext.TokenAgent { return nil },
			wantErr: "required"},
		{name: "name is required", kind: KindAgent, mutate: func(a *ext.TokenAgent) *ext.TokenAgent {
			a.Name = ""
			return a
		}, wantErr: "spec.agent.name"},
		{name: "name must be a dns label", kind: KindAgent, mutate: func(a *ext.TokenAgent) *ext.TokenAgent {
			a.Name = "Not_A_Label"
			return a
		}, wantErr: "spec.agent.name"},
		{name: "rules are required", kind: KindAgent, mutate: func(a *ext.TokenAgent) *ext.TokenAgent {
			a.Rules = nil
			return a
		}, wantErr: "at least one rule"},
		{name: "too many rules", kind: KindAgent, mutate: func(*ext.TokenAgent) *ext.TokenAgent { return tooMany },
			wantErr: "at most"},
		{name: "verbs are required", kind: KindAgent, mutate: func(a *ext.TokenAgent) *ext.TokenAgent {
			a.Rules[0].Verbs = nil
			return a
		}, wantErr: "verbs must not be empty"},
		{name: "api groups are required", kind: KindAgent, mutate: func(a *ext.TokenAgent) *ext.TokenAgent {
			a.Rules[0].APIGroups = nil
			return a
		}, wantErr: "apiGroups must not be empty"},
		{name: "resources are required", kind: KindAgent, mutate: func(a *ext.TokenAgent) *ext.TokenAgent {
			a.Rules[0].Resources = nil
			return a
		}, wantErr: "resources must not be empty"},
		{name: "empty verb", kind: KindAgent, mutate: func(a *ext.TokenAgent) *ext.TokenAgent {
			a.Rules[0].Verbs = []string{""}
			return a
		}, wantErr: "empty entries"},
		{name: "empty resource", kind: KindAgent, mutate: func(a *ext.TokenAgent) *ext.TokenAgent {
			a.Rules[0].Resources = []string{""}
			return a
		}, wantErr: "empty entries"},
		{name: "overlong entry", kind: KindAgent, mutate: func(a *ext.TokenAgent) *ext.TokenAgent {
			a.Rules[0].Resources = []string{strings.Repeat("a", 254)}
			return a
		}, wantErr: "too long"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateAgent(test.kind, test.mutate(validAgent()))
			if test.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			assert.ErrorContains(t, err, test.wantErr)
		})
	}
}

func TestAgentTTLLimits(t *testing.T) {
	const (
		hour  = int64(time.Hour / time.Millisecond)
		day   = 24 * hour
		never = int64(-1)
	)

	tests := []struct {
		name           string
		agentMax       string
		agentDefault   string
		authMax        string
		wantDefault    int64
		wantMax        int64
		requested      int64
		wantIngested   int64
		skipIngestTest bool
	}{
		{name: "defaults", agentMax: "1440", agentDefault: "60", authMax: "129600",
			wantDefault: hour, wantMax: day, requested: 0, wantIngested: hour},
		{name: "request above the agent max is capped", agentMax: "1440", agentDefault: "60", authMax: "129600",
			wantDefault: hour, wantMax: day, requested: 30 * day, wantIngested: day},
		{name: "never expires is capped", agentMax: "1440", agentDefault: "60", authMax: "129600",
			wantDefault: hour, wantMax: day, requested: never, wantIngested: day},
		{name: "request below the max is kept", agentMax: "1440", agentDefault: "60", authMax: "129600",
			wantDefault: hour, wantMax: day, requested: 5 * 60 * 1000, wantIngested: 5 * 60 * 1000},
		{name: "the general token max also applies", agentMax: "1440", agentDefault: "60", authMax: "30",
			wantDefault: hour / 2, wantMax: hour / 2, requested: day, wantIngested: hour / 2},
		{name: "default zero is the max", agentMax: "1440", agentDefault: "0", authMax: "129600",
			wantDefault: day, wantMax: day, requested: 0, wantIngested: day},
		{name: "no limit at any level", agentMax: "0", agentDefault: "0", authMax: "0",
			wantDefault: never, wantMax: never, requested: 0, wantIngested: never},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			setTTLSettings(t, test.authMax, "129600", "960")
			for setting, value := range map[*settings.Setting]string{
				&settings.AgentTokenMaxTTLMinutes:     test.agentMax,
				&settings.AgentTokenDefaultTTLMinutes: test.agentDefault,
			} {
				prior := setting.Get()
				require.NoError(t, setting.Set(value))
				t.Cleanup(func() { assert.NoError(t, setting.Set(prior)) })
			}

			defaultTTL, maxTTL, err := TTLLimits(KindAgent)
			require.NoError(t, err)
			assert.Equal(t, test.wantDefault, defaultTTL, "default")
			assert.Equal(t, test.wantMax, maxTTL, "max")

			ttl, err := IngestTTL(test.requested, KindAgent)
			require.NoError(t, err)
			assert.Equal(t, test.wantIngested, ttl, "ingested")
		})
	}
}

func TestAgentSecretRoundTrip(t *testing.T) {
	setTTLSettings(t, "129600", "129600", "960")

	token := &ext.Token{
		Spec: ext.TokenSpec{
			UserID: "u-abc",
			UserPrincipal: ext.TokenPrincipal{
				Name:     "local://u-abc",
				Provider: "local",
			},
			Kind:  KindAgent,
			Agent: validAgent(),
		},
		Status: ext.TokenStatus{Hash: "hash", LastUpdateTime: "2026-11-24T00:00:00Z"},
	}
	token.Name = "token-xyz"
	token.UID = "uid-1"

	secret, err := toSecret(token)
	require.NoError(t, err)
	// The test fixtures expect Data, which the API server derives from StringData.
	secret.Data = map[string][]byte{}
	for k, v := range secret.StringData {
		secret.Data[k] = []byte(v)
	}

	got, err := fromSecret(secret)
	require.NoError(t, err)
	assert.Equal(t, token.Spec.Agent, got.Spec.Agent)
	assert.Equal(t, KindAgent, got.Spec.Kind)

	// A token without an agent stores no agent and reads back without one.
	token.Spec.Kind = ""
	token.Spec.Agent = nil
	secret, err = toSecret(token)
	require.NoError(t, err)
	secret.Data = map[string][]byte{}
	for k, v := range secret.StringData {
		secret.Data[k] = []byte(v)
	}
	got, err = fromSecret(secret)
	require.NoError(t, err)
	assert.Nil(t, got.Spec.Agent)
}

// An agent token must not be able to create tokens: one of another kind would not be limited by
// the agent's rules.
func TestSystemStoreCreateRejectsAgentRequestToken(t *testing.T) {
	setTTLSettings(t, "129600", "129600", "960")
	ctrl := gomock.NewController(t)

	agentToken := &ext.Token{
		Spec: ext.TokenSpec{
			UserID:        "world",
			UserPrincipal: ext.TokenPrincipal{Name: "local://world", Provider: "local"},
			Kind:          KindAgent,
			Agent:         validAgent(),
		},
		Status: ext.TokenStatus{Hash: "hash", LastUpdateTime: "2026-11-24T00:00:00Z"},
	}
	agentToken.Name = "agent-token"
	agentToken.UID = "uid-1"
	agentSecret, err := toSecret(agentToken)
	require.NoError(t, err)
	agentSecret.Data = map[string][]byte{}
	for k, v := range agentSecret.StringData {
		agentSecret.Data[k] = []byte(v)
	}

	// No secret is expected to be created.
	secrets := fake.NewMockControllerInterface[*corev1.Secret, *corev1.SecretList](ctrl)
	scache := fake.NewMockCacheInterface[*corev1.Secret](ctrl)
	secrets.EXPECT().Cache().Return(scache)
	scache.EXPECT().Get(TokenNamespace, "agent-token").Return(agentSecret, nil)

	users := fake.NewMockNonNamespacedControllerInterface[*v3.User, *v3.UserList](ctrl)
	ucache := fake.NewMockNonNamespacedCacheInterface[*v3.User](ctrl)
	users.EXPECT().Cache().Return(ucache)
	ucache.EXPECT().Get("world").Return(&v3.User{Enabled: ptr.To(true)}, nil)

	nsCache := fake.NewMockNonNamespacedCacheInterface[*corev1.Namespace](ctrl)
	tcache := fake.NewMockNonNamespacedCacheInterface[*v3.Token](ctrl)
	ccache := fake.NewMockNonNamespacedCacheInterface[*v3.Cluster](ctrl)
	auth := NewMockauthHandler(ctrl)
	auth.EXPECT().SessionID(gomock.Any()).Return("ext/agent-token", nil)

	store := NewSystem(nil, nsCache, secrets, users, tcache, ccache, NewMocktimeHandler(ctrl), NewMockhashHandler(ctrl), auth, nil)

	token := &ext.Token{Spec: ext.TokenSpec{UserID: "world"}}
	_, err = store.Create(t.Context(), GVR.GroupResource(), token, &metav1.CreateOptions{}, &mockUser{name: "world"})
	require.Error(t, err)
	assert.True(t, apierrors.IsForbidden(err), "expected forbidden, got %v", err)
	assert.Contains(t, err.Error(), "agent tokens can't create tokens")
}

func TestSystemStoreCreateRejectsInvalidAgent(t *testing.T) {
	ctrl := gomock.NewController(t)
	secrets := fake.NewMockControllerInterface[*corev1.Secret, *corev1.SecretList](ctrl)
	secrets.EXPECT().Cache().Return(fake.NewMockCacheInterface[*corev1.Secret](ctrl))
	users := fake.NewMockNonNamespacedControllerInterface[*v3.User, *v3.UserList](ctrl)
	users.EXPECT().Cache().Return(fake.NewMockNonNamespacedCacheInterface[*v3.User](ctrl))

	store := NewSystem(nil, fake.NewMockNonNamespacedCacheInterface[*corev1.Namespace](ctrl), secrets, users,
		fake.NewMockNonNamespacedCacheInterface[*v3.Token](ctrl), fake.NewMockNonNamespacedCacheInterface[*v3.Cluster](ctrl),
		NewMocktimeHandler(ctrl), NewMockhashHandler(ctrl), NewMockauthHandler(ctrl), nil)

	for name, token := range map[string]*ext.Token{
		"kind agent without agent": {Spec: ext.TokenSpec{UserID: "world", Kind: KindAgent}},
		"agent without kind agent": {Spec: ext.TokenSpec{UserID: "world", Agent: validAgent()}},
		"agent without rules":      {Spec: ext.TokenSpec{UserID: "world", Kind: KindAgent, Agent: &ext.TokenAgent{Name: "a"}}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := store.Create(t.Context(), GVR.GroupResource(), token, &metav1.CreateOptions{}, &mockUser{name: "world"})
			require.Error(t, err)
			assert.True(t, apierrors.IsBadRequest(err), "expected bad request, got %v", err)
		})
	}
}

func TestSystemStoreCreateAgentToken(t *testing.T) {
	const day = int64(24 * time.Hour / time.Millisecond)

	newStore := func(t *testing.T, user *v3.User, created *corev1.Secret) *SystemStore {
		setTTLSettings(t, "129600", "129600", "960")
		ctrl := gomock.NewController(t)

		secrets := fake.NewMockControllerInterface[*corev1.Secret, *corev1.SecretList](ctrl)
		secrets.EXPECT().Cache().Return(fake.NewMockCacheInterface[*corev1.Secret](ctrl))
		secrets.EXPECT().Create(gomock.Any()).DoAndReturn(func(s *corev1.Secret) (*corev1.Secret, error) {
			s = s.DeepCopy()
			s.Name = "token-abcde"
			s.Data = map[string][]byte{}
			for k, v := range s.StringData {
				s.Data[k] = []byte(v)
			}
			*created = *s
			return s, nil
		}).AnyTimes()

		users := fake.NewMockNonNamespacedControllerInterface[*v3.User, *v3.UserList](ctrl)
		ucache := fake.NewMockNonNamespacedCacheInterface[*v3.User](ctrl)
		users.EXPECT().Cache().Return(ucache)
		ucache.EXPECT().Get("u-1").DoAndReturn(func(string) (*v3.User, error) {
			if user == nil {
				return nil, apierrors.NewNotFound(schema.GroupResource{}, "u-1")
			}
			return user, nil
		}).AnyTimes()

		nsCache := fake.NewMockNonNamespacedCacheInterface[*corev1.Namespace](ctrl)
		nsCache.EXPECT().Get(TokenNamespace).Return(&corev1.Namespace{}, nil).AnyTimes()

		timer := NewMocktimeHandler(ctrl)
		timer.EXPECT().Now().Return("2026-11-24T00:00:00Z").AnyTimes()
		hasher := NewMockhashHandler(ctrl)
		hasher.EXPECT().MakeAndHashSecret().Return("the-secret", "the-hash", nil).AnyTimes()

		return NewSystem(nil, nsCache, secrets, users,
			fake.NewMockNonNamespacedCacheInterface[*v3.Token](ctrl),
			fake.NewMockNonNamespacedCacheInterface[*v3.Cluster](ctrl),
			timer, hasher, NewMockauthHandler(ctrl))
	}

	t.Run("uses the principal of the request", func(t *testing.T) {
		var created corev1.Secret
		store := newStore(t, &v3.User{Username: "alice", DisplayName: "Alice"}, &created)
		token, err := store.CreateAgentToken(AgentTokenRequest{
			UserID: "u-1",
			Agent:  *validAgent(),
			Principal: &ext.TokenPrincipal{Name: "github_user://42", Provider: "github", LoginName: "alice",
				PrincipalType: "user"},
		})
		require.NoError(t, err)
		assert.Equal(t, "github_user://42", token.Spec.UserPrincipal.Name)
		assert.Equal(t, "github", token.Spec.UserPrincipal.Provider)
	})

	t.Run("a principal without name or provider is refused", func(t *testing.T) {
		var created corev1.Secret
		store := newStore(t, &v3.User{Username: "alice"}, &created)
		for _, p := range []ext.TokenPrincipal{{Name: "x"}, {Provider: "github"}} {
			_, err := store.CreateAgentToken(AgentTokenRequest{UserID: "u-1", Agent: *validAgent(), Principal: &p})
			require.Error(t, err)
			assert.True(t, apierrors.IsBadRequest(err))
		}
	})

	t.Run("creates a token owned by the user's local principal", func(t *testing.T) {
		var created corev1.Secret
		store := newStore(t, &v3.User{Username: "alice", DisplayName: "Alice"}, &created)

		token, err := store.CreateAgentToken(AgentTokenRequest{
			UserID:      "u-1",
			Agent:       *validAgent(),
			TTL:         30 * day,
			Description: "from a trust",
			Labels:      map[string]string{"cattle.io/agent-trust": "ci"},
		})
		require.NoError(t, err)

		assert.Equal(t, "ext/token-abcde:the-secret", token.Status.BearerToken)
		assert.Equal(t, "the-secret", token.Status.Value)
		assert.Empty(t, token.Status.Hash)
		assert.Equal(t, KindAgent, token.Spec.Kind)
		assert.Equal(t, "u-1", token.Spec.UserID)
		assert.Equal(t, validAgent(), token.Spec.Agent)
		assert.Equal(t, "local://u-1", token.Spec.UserPrincipal.Name)
		assert.Equal(t, "local", token.Spec.UserPrincipal.Provider)
		assert.Equal(t, "alice", token.Spec.UserPrincipal.LoginName)
		assert.Equal(t, "ci", token.Labels["cattle.io/agent-trust"])
		// 30 days requested, the agent max applies.
		assert.Equal(t, day, token.Spec.TTL)
		assert.Equal(t, KindAgent, created.Labels[KindLabel])
	})

	for name, test := range map[string]struct {
		user    *v3.User
		mutate  func(r *AgentTokenRequest)
		wantErr func(error) bool
	}{
		"unknown user":  {user: nil, wantErr: apierrors.IsBadRequest},
		"disabled user": {user: &v3.User{Enabled: ptr.To(false)}, wantErr: apierrors.IsBadRequest},
		"system user":   {user: &v3.User{PrincipalIDs: []string{"system://provisioning"}}, wantErr: apierrors.IsBadRequest},
		"invalid agent": {user: &v3.User{}, wantErr: apierrors.IsBadRequest,
			mutate: func(r *AgentTokenRequest) { r.Agent.Rules = nil }},
	} {
		t.Run("rejects "+name, func(t *testing.T) {
			var created corev1.Secret
			store := newStore(t, test.user, &created)
			req := AgentTokenRequest{UserID: "u-1", Agent: *validAgent()}
			if test.mutate != nil {
				test.mutate(&req)
			}
			_, err := store.CreateAgentToken(req)
			require.Error(t, err)
			assert.True(t, test.wantErr(err), "unexpected error %v", err)
			assert.Empty(t, created.Name, "no secret may be created")
		})
	}
}
