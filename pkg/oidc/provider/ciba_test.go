package provider

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	ext "github.com/rancher/rancher/pkg/apis/ext.cattle.io/v1"
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/rancher/pkg/auth/accessor"
	"github.com/rancher/rancher/pkg/oidc/provider/ciba"
	"github.com/rancher/rancher/pkg/oidc/provider/ciba/cibatest"
	oidcerror "github.com/rancher/rancher/pkg/oidc/provider/error"
	"github.com/rancher/wrangler/v3/pkg/generic/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"golang.org/x/time/rate"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
)

const (
	cibaClientID     = "client-1"
	cibaClientSecret = "s3cret"
)

type fakeClients struct {
	clients map[string]*v3.OIDCClient // by client ID
	secrets map[string]string
	used    int
}

func (f *fakeClients) authenticateClient(r *http.Request, recordUse bool) (*v3.OIDCClient, *oidcerror.Error) {
	id, secret, ok := r.BasicAuth()
	if !ok {
		id, secret = r.FormValue("client_id"), r.FormValue("client_secret")
	}
	client, found := f.clients[id]
	if !found || secret == "" || f.secrets[id] != secret {
		return nil, oidcerror.New(oidcerror.InvalidClient, "client authentication failed")
	}
	if recordUse {
		f.used++
	}
	return client, nil
}

type cibaFixture struct {
	handler  *cibaHandler
	secrets  *cibatest.Secrets
	store    *ciba.Store
	clients  *fakeClients
	creator  *fakeTokenCreator
	clock    time.Time
	tokenSrv *tokenHandler
}

func backchannelClient(name, clientID string) *v3.OIDCClient {
	return &v3.OIDCClient{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Status:     v3.OIDCClientStatus{ClientID: clientID},
		Spec: v3.OIDCClientSpec{
			Description: "the ops agent",
			Backchannel: &v3.OIDCClientBackchannel{
				AgentName:                "ops-agent",
				TokenExpirationSeconds:   600,
				RequestExpirationSeconds: 120,
				Scopes: []v3.OIDCClientBackchannelScope{
					{Name: "read-pods", Rules: []v3.AgentRule{{Verbs: []string{"get", "list"}, APIGroups: []string{""}, Resources: []string{"pods"}}}},
					{Name: "scale", Rules: []v3.AgentRule{{Verbs: []string{"patch"}, APIGroups: []string{"apps"}, Resources: []string{"deployments"}}}},
				},
			},
		},
	}
}

func newCIBAFixture(t *testing.T, mutateClient func(c *v3.OIDCClient)) *cibaFixture {
	t.Helper()
	ctrl := gomock.NewController(t)

	client := backchannelClient("ops", cibaClientID)
	if mutateClient != nil {
		mutateClient(client)
	}
	clients := &fakeClients{
		clients: map[string]*v3.OIDCClient{cibaClientID: client},
		secrets: map[string]string{cibaClientID: cibaClientSecret},
	}

	users := fake.NewMockNonNamespacedCacheInterface[*v3.User](ctrl)
	users.EXPECT().List(gomock.Any()).Return([]*v3.User{
		{ObjectMeta: metav1.ObjectMeta{Name: "u-1"}, Username: "alice"},
		{ObjectMeta: metav1.ObjectMeta{Name: "u-2"}, Username: "bob"},
		{ObjectMeta: metav1.ObjectMeta{Name: "u-3"}, Username: "carol", Enabled: ptr.To(false)},
		{ObjectMeta: metav1.ObjectMeta{Name: "u-4"}, Username: "sys", PrincipalIDs: []string{"system://x"}},
		{ObjectMeta: metav1.ObjectMeta{Name: "u-5"}, Username: "dup"},
		{ObjectMeta: metav1.ObjectMeta{Name: "u-6"}, Username: "dup"},
	}, nil).AnyTimes()

	oidcCache := fake.NewMockNonNamespacedCacheInterface[*v3.OIDCClient](ctrl)
	oidcCache.EXPECT().List(gomock.Any()).DoAndReturn(func(any) ([]*v3.OIDCClient, error) {
		return []*v3.OIDCClient{client}, nil
	}).AnyTimes()

	f := &cibaFixture{
		secrets: cibatest.NewSecrets(),
		clients: clients,
		creator: &fakeTokenCreator{},
		clock:   time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC),
	}
	clock := func() time.Time { return f.clock }
	f.store = ciba.NewStoreWithClock(f.secrets, f.secrets, clock)

	// Like the real check, this takes the token from the Authorization header, whatever its scheme,
	// or from the cookie. It is up to the handler to accept only a bearer token in the header.
	verify := func(r *http.Request) (accessor.TokenAccessor, error) {
		token := ""
		if _, value, ok := strings.Cut(r.Header.Get("Authorization"), " "); ok {
			token = value
		} else if c, err := r.Cookie("R_SESS"); err == nil {
			token = c.Value
		}
		switch token {
		case "user-1":
			return &ext.Token{Spec: ext.TokenSpec{UserID: "u-1"}}, nil
		case "user-2":
			return &ext.Token{Spec: ext.TokenSpec{UserID: "u-2"}}, nil
		}
		return nil, fmt.Errorf("invalid token")
	}
	f.handler = newCIBAHandler(f.store, clients, users, oidcCache, f.creator, verify)
	f.handler.limiter = rate.NewLimiter(rate.Inf, 1)
	f.handler.now = clock
	f.tokenSrv = &tokenHandler{ciba: f.handler}
	return f
}

func basic(r *http.Request, id, secret string) {
	r.SetBasicAuth(id, secret)
}

func (f *cibaFixture) authorize(form url.Values) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/oidc/bc-authorize", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	basic(r, cibaClientID, cibaClientSecret)
	w := httptest.NewRecorder()
	f.handler.authorizeEndpoint(w, r)
	return w
}

func authForm(hint string, extra ...string) url.Values {
	form := url.Values{"scope": {"read-pods"}, "login_hint": {hint}}
	for i := 0; i+1 < len(extra); i += 2 {
		form.Set(extra[i], extra[i+1])
	}
	return form
}

func (f *cibaFixture) start(t *testing.T, hint string, extra ...string) (authReqID string) {
	t.Helper()
	w := f.authorize(authForm(hint, extra...))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var resp authorizeResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	return resp.AuthReqID
}

func (f *cibaFixture) poll(authReqID string) *httptest.ResponseRecorder {
	return f.pollAs(authReqID, cibaClientID, cibaClientSecret)
}

func (f *cibaFixture) pollAs(authReqID, id, secret string) *httptest.ResponseRecorder {
	form := url.Values{"grant_type": {grantTypeCIBA}, "auth_req_id": {authReqID}}
	r := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	basic(r, id, secret)
	w := httptest.NewRecorder()
	f.tokenSrv.tokenEndpoint(w, r)
	return w
}

func (f *cibaFixture) decide(bearer, id, contentType, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/oidc/ciba/requests/"+id, strings.NewReader(body))
	r.SetPathValue("id", id)
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	w := httptest.NewRecorder()
	f.handler.decideEndpoint(w, r)
	return w
}

func (f *cibaFixture) approve(bearer, id string) *httptest.ResponseRecorder {
	return f.decide(bearer, id, "application/json", `{"decision":"approve"}`)
}

func (f *cibaFixture) list(authorization string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, "/oidc/ciba/requests", nil)
	if authorization != "" {
		r.Header.Set("Authorization", authorization)
	}
	w := httptest.NewRecorder()
	f.handler.listEndpoint(w, r)
	return w
}

func idOf(authReqID string) string {
	id, _, _ := ciba.ParseAuthReqID(authReqID)
	return id
}

func (f *cibaFixture) request(t *testing.T, authReqID string) *ciba.Request {
	t.Helper()
	req, err := f.store.Get(idOf(authReqID))
	require.NoError(t, err)
	return req
}

func TestBackchannelAuthorize(t *testing.T) {
	t.Run("creates a pending request", func(t *testing.T) {
		f := newCIBAFixture(t, nil)
		w := f.authorize(authForm("alice", "binding_message", "Scale prod to 5", "scope", "read-pods scale read-pods"))
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))

		var resp authorizeResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Equal(t, int64(120), resp.ExpiresIn)
		assert.Equal(t, 5, resp.Interval)

		req := f.request(t, resp.AuthReqID)
		assert.Equal(t, ciba.Pending, req.Status)
		assert.Equal(t, "u-1", req.UserID)
		assert.Equal(t, cibaClientID, req.ClientID)
		assert.Equal(t, []string{"read-pods", "scale"}, req.Scopes, "duplicates are dropped")
		assert.Equal(t, "ops-agent", req.AgentName)
		assert.Equal(t, int64(600), req.TokenTTLSeconds)
		assert.Equal(t, "Scale prod to 5", req.BindingMessage)
		assert.Equal(t, f.clock.Add(120*time.Second), req.ExpiresAt)
		assert.Equal(t, []ext.TokenAgentRule{
			{Verbs: []string{"get", "list"}, APIGroups: []string{""}, Resources: []string{"pods"}},
			{Verbs: []string{"patch"}, APIGroups: []string{"apps"}, Resources: []string{"deployments"}},
		}, req.Rules, "the rules of the scopes, as the user will see them")
		assert.Equal(t, 1, f.clients.used, "the use of the client secret is recorded")

		// The secret part of the auth_req_id is stored hashed.
		_, secret, _ := ciba.ParseAuthReqID(resp.AuthReqID)
		assert.True(t, req.SecretMatches(secret))
		for _, s := range f.secrets.Items {
			assert.NotContains(t, string(s.Data["request"]), secret)
		}
	})

	t.Run("the user is named by id or username", func(t *testing.T) {
		f := newCIBAFixture(t, nil)
		assert.Equal(t, "u-2", f.request(t, f.start(t, "bob")).UserID)
		assert.Equal(t, "u-2", f.request(t, f.start(t, "u-2")).UserID)
	})

	t.Run("a requested expiry can only shorten the time", func(t *testing.T) {
		f := newCIBAFixture(t, nil)
		assert.Equal(t, f.clock.Add(30*time.Second), f.request(t, f.start(t, "alice", "requested_expiry", "30")).ExpiresAt)
		assert.Equal(t, f.clock.Add(120*time.Second), f.request(t, f.start(t, "bob", "requested_expiry", "9999")).ExpiresAt)
	})

	t.Run("an unusable user is not told from a usable one", func(t *testing.T) {
		f := newCIBAFixture(t, nil)
		known := f.authorize(authForm("alice"))
		require.Equal(t, http.StatusOK, known.Code)
		var knownResp authorizeResponse
		require.NoError(t, json.Unmarshal(known.Body.Bytes(), &knownResp))

		for name, hint := range map[string]string{
			"unknown":           "nobody",
			"disabled":          "carol",
			"system":            "sys",
			"ambiguous":         "dup",
			"disabled by id":    "u-3",
			"system by id":      "u-4",
			"duplicate by name": "u-5-and-more",
		} {
			t.Run(name, func(t *testing.T) {
				w := f.authorize(authForm(hint))
				require.Equal(t, http.StatusOK, w.Code, w.Body.String())
				var resp authorizeResponse
				require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
				// Same shape as for a known user.
				assert.Equal(t, knownResp.ExpiresIn, resp.ExpiresIn)
				assert.Equal(t, knownResp.Interval, resp.Interval)
				assert.Len(t, resp.AuthReqID, len(knownResp.AuthReqID))
				// But it can never be approved.
				assert.Empty(t, f.request(t, resp.AuthReqID).UserID)
			})
		}
	})

	t.Run("duplicate usernames are refused, ids still work", func(t *testing.T) {
		f := newCIBAFixture(t, nil)
		assert.Equal(t, "u-5", f.request(t, f.start(t, "u-5")).UserID)
		assert.Empty(t, f.request(t, f.start(t, "dup")).UserID)
	})

	t.Run("authenticates the client", func(t *testing.T) {
		f := newCIBAFixture(t, nil)
		for name, mutate := range map[string]func(r *http.Request){
			"wrong secret": func(r *http.Request) { basic(r, cibaClientID, "wrong") },
			"unknown":      func(r *http.Request) { basic(r, "client-9", cibaClientSecret) },
			"none":         func(r *http.Request) { r.Header.Del("Authorization") },
		} {
			t.Run(name, func(t *testing.T) {
				r := httptest.NewRequest(http.MethodPost, "/oidc/bc-authorize", strings.NewReader(authForm("alice").Encode()))
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				mutate(r)
				w := httptest.NewRecorder()
				f.handler.authorizeEndpoint(w, r)
				assert.Equal(t, http.StatusUnauthorized, w.Code)
				assert.Equal(t, "invalid_client", errorCode(t, w))
				assert.Empty(t, f.secrets.Items)
			})
		}
	})

	t.Run("a client without backchannel configuration is refused", func(t *testing.T) {
		f := newCIBAFixture(t, func(c *v3.OIDCClient) { c.Spec.Backchannel = nil })
		w := f.authorize(authForm("alice"))
		assert.Equal(t, http.StatusForbidden, w.Code)
		assert.Equal(t, "unauthorized_client", errorCode(t, w))
		assert.Empty(t, f.secrets.Items)
	})

	t.Run("an unusable client configuration is a server error", func(t *testing.T) {
		f := newCIBAFixture(t, func(c *v3.OIDCClient) { c.Spec.Backchannel.AgentName = "Not A Label" })
		w := f.authorize(authForm("alice"))
		assert.Equal(t, http.StatusInternalServerError, w.Code)
		assert.Equal(t, "server_error", errorCode(t, w))
		assert.Empty(t, f.secrets.Items)
	})

	t.Run("the agent name defaults to the client name", func(t *testing.T) {
		f := newCIBAFixture(t, func(c *v3.OIDCClient) { c.Spec.Backchannel.AgentName = "" })
		assert.Equal(t, "ops", f.request(t, f.start(t, "alice")).AgentName)
	})

	for name, test := range map[string]struct {
		form url.Values
		code string
	}{
		"no login_hint":       {url.Values{"scope": {"read-pods"}}, "invalid_request"},
		"overlong login_hint": {authForm(strings.Repeat("a", cibaMaxLoginHint+1)), "invalid_request"},
		"id_token_hint":       {authForm("alice", "id_token_hint", "x"), "invalid_request"},
		"login_hint_token":    {authForm("alice", "login_hint_token", "x"), "invalid_request"},
		"user_code":           {authForm("alice", "user_code", "x"), "invalid_request"},
		"notification token":  {authForm("alice", "client_notification_token", "x"), "invalid_request"},
		"no scope":            {url.Values{"login_hint": {"alice"}}, "invalid_scope"},
		"unknown scope":       {authForm("alice", "scope", "read-pods admin"), "invalid_scope"},
		"scope of the user":   {authForm("alice", "scope", "openid"), "invalid_scope"},
		"overlong binding":    {authForm("alice", "binding_message", strings.Repeat("a", cibaMaxBindingMessage+1)), "invalid_binding_message"},
		"newline in binding":  {authForm("alice", "binding_message", "ok\nApprove for admin"), "invalid_binding_message"},
		"control in binding":  {authForm("alice", "binding_message", "bell\a"), "invalid_binding_message"},
		"bidi override":       {authForm("alice", "binding_message", "abc‮def"), "invalid_binding_message"},
		"invalid expiry":      {authForm("alice", "requested_expiry", "soon"), "invalid_request"},
		"zero expiry":         {authForm("alice", "requested_expiry", "0"), "invalid_request"},
		"negative expiry":     {authForm("alice", "requested_expiry", "-5"), "invalid_request"},
	} {
		t.Run("rejects "+name, func(t *testing.T) {
			f := newCIBAFixture(t, nil)
			w := f.authorize(test.form)
			assert.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
			assert.Equal(t, test.code, errorCode(t, w))
			assert.Empty(t, f.secrets.Items, "nothing may be stored")
		})
	}

	t.Run("limits the requests waiting for one user from one client", func(t *testing.T) {
		f := newCIBAFixture(t, nil)
		for range cibaMaxPendingPerPair {
			f.start(t, "alice")
		}
		w := f.authorize(authForm("alice"))
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "too many pending requests")
		// Another user is not affected.
		f.start(t, "bob")
	})

	t.Run("limits the requests of a client for unknown users", func(t *testing.T) {
		f := newCIBAFixture(t, nil)
		for range cibaMaxPendingPerClient {
			f.start(t, "nobody")
		}
		w := f.authorize(authForm("nobody"))
		assert.Contains(t, w.Body.String(), "too many pending requests")
		assert.Contains(t, w.Body.String(), "invalid_request")
	})

	t.Run("expired requests do not count towards the limit", func(t *testing.T) {
		f := newCIBAFixture(t, nil)
		for range cibaMaxPendingPerPair {
			f.start(t, "alice")
		}
		f.clock = f.clock.Add(121 * time.Second)
		f.start(t, "alice")
	})

	t.Run("is rate limited", func(t *testing.T) {
		f := newCIBAFixture(t, nil)
		f.handler.limiter = rate.NewLimiter(rate.Every(time.Hour), 1)
		assert.Equal(t, http.StatusOK, f.authorize(authForm("alice")).Code)
		assert.Equal(t, http.StatusTooManyRequests, f.authorize(authForm("bob")).Code)
	})
}

func TestBackchannelPoll(t *testing.T) {
	t.Run("pending, then approved, then the token once", func(t *testing.T) {
		f := newCIBAFixture(t, nil)
		authReqID := f.start(t, "alice", "scope", "read-pods scale")

		w := f.poll(authReqID)
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Equal(t, "authorization_pending", errorCode(t, w))
		assert.Empty(t, f.creator.requests)

		require.Equal(t, http.StatusNoContent, f.approve("user-1", idOf(authReqID)).Code)
		f.clock = f.clock.Add(6 * time.Second)

		w = f.poll(authReqID)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
		var resp cibaTokenResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Equal(t, "ext/token-abc:secret", resp.AccessToken)
		assert.Equal(t, "Bearer", resp.TokenType)
		assert.Equal(t, int64(600), resp.ExpiresIn)
		assert.Equal(t, "read-pods scale", resp.Scope)

		require.Len(t, f.creator.requests, 1)
		req := f.creator.requests[0]
		assert.Equal(t, "u-1", req.UserID, "the token is for the user who approved")
		assert.Equal(t, int64(600_000), req.TTL)
		assert.Equal(t, "ops-agent", req.Agent.Name)
		assert.Len(t, req.Agent.Rules, 2)

		// The request is used up.
		w = f.poll(authReqID)
		assert.Equal(t, "invalid_grant", errorCode(t, w))
		assert.Len(t, f.creator.requests, 1)
	})

	t.Run("the token has the rules shown to the user, even if the client changes", func(t *testing.T) {
		f := newCIBAFixture(t, nil)
		authReqID := f.start(t, "alice")
		require.Equal(t, http.StatusNoContent, f.approve("user-1", idOf(authReqID)).Code)

		// The administrator widens the scope after the user approved.
		f.clients.clients[cibaClientID].Spec.Backchannel.Scopes[0].Rules[0].Resources = []string{"*"}
		f.clock = f.clock.Add(6 * time.Second)
		require.Equal(t, http.StatusOK, f.poll(authReqID).Code)
		assert.Equal(t, []string{"pods"}, f.creator.requests[0].Agent.Rules[0].Resources)
	})

	t.Run("denied", func(t *testing.T) {
		f := newCIBAFixture(t, nil)
		authReqID := f.start(t, "alice")
		require.Equal(t, http.StatusNoContent, f.decide("user-1", idOf(authReqID), "application/json", `{"decision":"deny"}`).Code)

		w := f.poll(authReqID)
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Equal(t, "access_denied", errorCode(t, w))
		assert.Empty(t, f.creator.requests)
		assert.Equal(t, "invalid_grant", errorCode(t, f.poll(authReqID)), "a denial is told once")
	})

	t.Run("expired", func(t *testing.T) {
		f := newCIBAFixture(t, nil)
		authReqID := f.start(t, "alice")
		f.clock = f.clock.Add(121 * time.Second)

		w := f.poll(authReqID)
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Equal(t, "expired_token", errorCode(t, w))
		assert.Equal(t, "invalid_grant", errorCode(t, f.poll(authReqID)))
	})

	t.Run("an approval after expiry is refused", func(t *testing.T) {
		f := newCIBAFixture(t, nil)
		authReqID := f.start(t, "alice")
		f.clock = f.clock.Add(121 * time.Second)
		assert.Equal(t, http.StatusNotFound, f.approve("user-1", idOf(authReqID)).Code)
		assert.Equal(t, "expired_token", errorCode(t, f.poll(authReqID)))
		assert.Empty(t, f.creator.requests)
	})

	t.Run("a request for an unknown user stays pending until it expires", func(t *testing.T) {
		f := newCIBAFixture(t, nil)
		authReqID := f.start(t, "nobody")
		assert.Equal(t, "authorization_pending", errorCode(t, f.poll(authReqID)))
		f.clock = f.clock.Add(121 * time.Second)
		assert.Equal(t, "expired_token", errorCode(t, f.poll(authReqID)))
	})

	t.Run("polling too fast is told to slow down and the interval grows to a limit", func(t *testing.T) {
		f := newCIBAFixture(t, nil)
		authReqID := f.start(t, "alice")
		assert.Equal(t, "authorization_pending", errorCode(t, f.poll(authReqID)))

		// Polls at the same moment are too fast.
		for i := 1; i <= 20; i++ {
			w := f.poll(authReqID)
			assert.Equal(t, http.StatusBadRequest, w.Code)
			assert.Equal(t, "slow_down", errorCode(t, w))
			assert.LessOrEqual(t, f.request(t, authReqID).IntervalSeconds, cibaMaxInterval)
		}
		assert.Equal(t, cibaMaxInterval, f.request(t, authReqID).IntervalSeconds)

		// After the interval, the poll is fine again.
		f.clock = f.clock.Add(time.Duration(cibaMaxInterval) * time.Second)
		assert.Equal(t, "authorization_pending", errorCode(t, f.poll(authReqID)))
	})

	t.Run("polling after the interval is not too fast", func(t *testing.T) {
		f := newCIBAFixture(t, nil)
		authReqID := f.start(t, "alice")
		assert.Equal(t, "authorization_pending", errorCode(t, f.poll(authReqID)))
		f.clock = f.clock.Add(5 * time.Second)
		assert.Equal(t, "authorization_pending", errorCode(t, f.poll(authReqID)))
		f.clock = f.clock.Add(4 * time.Second)
		assert.Equal(t, "slow_down", errorCode(t, f.poll(authReqID)))
	})

	t.Run("a request is only the client's own, with its secret", func(t *testing.T) {
		f := newCIBAFixture(t, nil)
		f.clients.clients["client-2"] = backchannelClient("other", "client-2")
		f.clients.secrets["client-2"] = "other-secret"
		authReqID := f.start(t, "alice")
		require.Equal(t, http.StatusNoContent, f.approve("user-1", idOf(authReqID)).Code)
		f.clock = f.clock.Add(6 * time.Second)

		_, secret, _ := ciba.ParseAuthReqID(authReqID)
		for name, id := range map[string]string{
			"another client":        f.pollAs(authReqID, "client-2", "other-secret").Body.String(),
			"wrong secret part":     f.poll(idOf(authReqID) + ".wrong" + secret).Body.String(),
			"no secret part":        f.poll(idOf(authReqID)).Body.String(),
			"empty":                 f.poll("").Body.String(),
			"unknown request":       f.poll("ciba-0000000000000000." + secret).Body.String(),
			"id that is not a ciba": f.poll("token-abc." + secret).Body.String(),
			"overlong":              f.poll(strings.Repeat("a", 500)).Body.String(),
		} {
			assert.Contains(t, id, "invalid_grant", name)
			assert.NotContains(t, id, "ext/", name)
		}
		assert.Empty(t, f.creator.requests, "none of these may get a token")

		// The owner still can.
		assert.Equal(t, http.StatusOK, f.poll(authReqID).Code)
	})

	t.Run("authenticates the client", func(t *testing.T) {
		f := newCIBAFixture(t, nil)
		authReqID := f.start(t, "alice")
		w := f.pollAs(authReqID, cibaClientID, "wrong")
		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Equal(t, "invalid_client", errorCode(t, w))
		assert.Equal(t, 1, f.clients.used, "polling does not write the use of the secret")
	})

	t.Run("a user disabled since approving is refused", func(t *testing.T) {
		f := newCIBAFixture(t, nil)
		authReqID := f.start(t, "alice")
		require.Equal(t, http.StatusNoContent, f.approve("user-1", idOf(authReqID)).Code)
		f.creator.err = apierrors.NewBadRequest("operation references a disabled user")

		w := f.poll(authReqID)
		assert.Equal(t, "access_denied", errorCode(t, w))
		assert.NotContains(t, w.Body.String(), "disabled")
	})

	t.Run("an internal failure is a server error without details", func(t *testing.T) {
		f := newCIBAFixture(t, nil)
		authReqID := f.start(t, "alice")
		require.Equal(t, http.StatusNoContent, f.approve("user-1", idOf(authReqID)).Code)
		f.creator.err = apierrors.NewInternalError(fmt.Errorf("secret store exploded"))

		w := f.poll(authReqID)
		assert.Equal(t, http.StatusInternalServerError, w.Code)
		assert.Equal(t, "server_error", errorCode(t, w))
		assert.NotContains(t, w.Body.String(), "exploded")
	})

	t.Run("of many polls at once exactly one gets the token", func(t *testing.T) {
		f := newCIBAFixture(t, nil)
		authReqID := f.start(t, "alice")
		require.Equal(t, http.StatusNoContent, f.approve("user-1", idOf(authReqID)).Code)
		f.clock = f.clock.Add(6 * time.Second)

		const polls = 25
		var wg sync.WaitGroup
		codes := make(chan int, polls)
		for range polls {
			wg.Add(1)
			go func() {
				defer wg.Done()
				codes <- f.poll(authReqID).Code
			}()
		}
		wg.Wait()
		close(codes)

		ok := 0
		for code := range codes {
			if code == http.StatusOK {
				ok++
			}
		}
		assert.Equal(t, 1, ok)
		assert.Len(t, f.creator.requests, 1, "a single token is created")
	})

	t.Run("the grant is unsupported without a handler", func(t *testing.T) {
		h := &tokenHandler{}
		form := url.Values{"grant_type": {grantTypeCIBA}, "auth_req_id": {"x"}}
		r := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		h.tokenEndpoint(w, r)
		assert.Equal(t, "unsupported_grant_type", errorCode(t, w))
	})
}

func TestBackchannelApproval(t *testing.T) {
	t.Run("lists the requests waiting for the user who asks", func(t *testing.T) {
		f := newCIBAFixture(t, nil)
		mine := f.start(t, "alice", "binding_message", "Scale prod to 5", "scope", "read-pods scale")
		f.start(t, "bob")
		f.start(t, "nobody")
		decided := f.start(t, "alice")
		require.Equal(t, http.StatusNoContent, f.approve("user-1", idOf(decided)).Code)
		f.clock = f.clock.Add(time.Second)

		w := f.list("Bearer user-1")
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		var views []requestView
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &views))
		require.Len(t, views, 1)
		v := views[0]
		assert.Equal(t, idOf(mine), v.ID)
		assert.Equal(t, "ops", v.Client, "the client is shown by name")
		assert.Equal(t, "the ops agent", v.Description)
		assert.Equal(t, "ops-agent", v.Agent)
		assert.Equal(t, []string{"read-pods", "scale"}, v.Scopes)
		assert.Len(t, v.Rules, 2)
		assert.Equal(t, "Scale prod to 5", v.BindingMessage)
		assert.Equal(t, int64(600), v.TokenTTL)

		// The auth_req_id, which collects the token, is never shown.
		_, secret, _ := ciba.ParseAuthReqID(mine)
		assert.NotContains(t, w.Body.String(), secret)
		assert.NotContains(t, w.Body.String(), "secretHash")
	})

	t.Run("an empty list is an empty array", func(t *testing.T) {
		f := newCIBAFixture(t, nil)
		w := f.list("Bearer user-1")
		assert.Equal(t, http.StatusOK, w.Code)
		assert.JSONEq(t, "[]", w.Body.String())
	})

	t.Run("expired requests are not listed", func(t *testing.T) {
		f := newCIBAFixture(t, nil)
		f.start(t, "alice")
		f.clock = f.clock.Add(121 * time.Second)
		assert.JSONEq(t, "[]", f.list("Bearer user-1").Body.String())
	})

	t.Run("must be authenticated with a bearer token", func(t *testing.T) {
		f := newCIBAFixture(t, nil)
		f.start(t, "alice")
		for name, authorization := range map[string]string{
			"none":                            "",
			"basic with a valid token":        "Basic user-1",
			"token scheme with a valid token": "Token user-1",
			"basic":                           "Basic dXNlcjpwYXNz",
			"unknown bearer":                  "Bearer nobody",
			"bearer without token":            "Bearer ",
			"short":                           "Bear",
		} {
			t.Run(name, func(t *testing.T) {
				assert.Equal(t, http.StatusUnauthorized, f.list(authorization).Code)
				assert.Equal(t, http.StatusUnauthorized, f.decide("", "x", "application/json", `{"decision":"approve"}`).Code)
			})
		}

		// A cookie alone, which a site could make the browser send, is not enough.
		r := httptest.NewRequest(http.MethodGet, "/oidc/ciba/requests", nil)
		r.AddCookie(&http.Cookie{Name: "R_SESS", Value: "user-1"})
		w := httptest.NewRecorder()
		f.handler.listEndpoint(w, r)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("only the user asked can decide", func(t *testing.T) {
		f := newCIBAFixture(t, nil)
		authReqID := f.start(t, "alice")
		id := idOf(authReqID)

		// Another user, an unknown request and a request for an unknown user all look the same.
		assert.Equal(t, http.StatusNotFound, f.approve("user-2", id).Code)
		assert.Equal(t, http.StatusNotFound, f.approve("user-1", "ciba-0000000000000000").Code)
		unknown := f.start(t, "nobody")
		assert.Equal(t, http.StatusNotFound, f.approve("user-1", idOf(unknown)).Code)
		assert.Equal(t, "authorization_pending", errorCode(t, f.poll(authReqID)), "still undecided")

		assert.Equal(t, http.StatusNoContent, f.approve("user-1", id).Code)
	})

	t.Run("a request is decided once", func(t *testing.T) {
		f := newCIBAFixture(t, nil)
		authReqID := f.start(t, "alice")
		id := idOf(authReqID)
		require.Equal(t, http.StatusNoContent, f.decide("user-1", id, "application/json", `{"decision":"deny"}`).Code)
		assert.Equal(t, http.StatusNotFound, f.approve("user-1", id).Code, "a denial can't be turned into an approval")
		assert.Equal(t, "access_denied", errorCode(t, f.poll(authReqID)))
	})

	for name, test := range map[string]struct {
		contentType, body string
		status            int
	}{
		"form content type": {"application/x-www-form-urlencoded", `decision=approve`, http.StatusUnsupportedMediaType},
		"text content type": {"text/plain", `{"decision":"approve"}`, http.StatusUnsupportedMediaType},
		"no content type":   {"", `{"decision":"approve"}`, http.StatusUnsupportedMediaType},
		"not json":          {"application/json", `approve`, http.StatusBadRequest},
		"unknown decision":  {"application/json", `{"decision":"maybe"}`, http.StatusBadRequest},
		"no decision":       {"application/json", `{}`, http.StatusBadRequest},
		"oversized body":    {"application/json", `{"decision":"` + strings.Repeat("a", cibaMaxDecisionBody) + `"}`, http.StatusBadRequest},
	} {
		t.Run("rejects "+name, func(t *testing.T) {
			f := newCIBAFixture(t, nil)
			id := idOf(f.start(t, "alice"))
			w := f.decide("user-1", id, test.contentType, test.body)
			assert.Equal(t, test.status, w.Code, w.Body.String())
			assert.Equal(t, ciba.Pending, func() ciba.Status { r, _ := f.store.Get(id); return r.Status }())
		})
	}

	t.Run("accepts a json content type with parameters", func(t *testing.T) {
		f := newCIBAFixture(t, nil)
		id := idOf(f.start(t, "alice"))
		assert.Equal(t, http.StatusNoContent, f.decide("user-1", id, "application/json; charset=utf-8", `{"decision":"approve"}`).Code)
	})
}

func TestOnlyLoginTokensApprove(t *testing.T) {
	// The approval endpoints use the authorize endpoint's token check, which refuses derived tokens.
	// An agent token is one, so an agent can't approve its own request.
	user := &v3.User{}
	agent := &ext.Token{Spec: ext.TokenSpec{Kind: "agent", Agent: &ext.TokenAgent{Name: "a"}}}
	assert.False(t, canLogInToOIDCClients(agent, user))
	assert.False(t, canLogInToOIDCClients(&ext.Token{Spec: ext.TokenSpec{Kind: "kubeconfig"}}, user))
}

func TestValidBindingMessage(t *testing.T) {
	for message, want := range map[string]bool{
		"":                                  true,
		"Scale prod to 5":                   true,
		"Déployer sur le cluster de prod ✓": true,
		strings.Repeat("a", 100):            true,
		strings.Repeat("a", 101):            false,
		"line\nbreak":                       false,
		"tab\there":                         false,
		"nul\x00":                           false,
		"rtl‮override":                      false,
		"zero​width":                        false,
		"invalid \xff utf8":                 false,
	} {
		assert.Equal(t, want, validBindingMessage(message), "%q", message)
	}
}
