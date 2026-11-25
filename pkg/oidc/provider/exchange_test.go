package provider

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	ext "github.com/rancher/rancher/pkg/apis/ext.cattle.io/v1"
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	exttokenstore "github.com/rancher/rancher/pkg/ext/stores/tokens"
	"github.com/rancher/wrangler/v3/pkg/generic/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"golang.org/x/time/rate"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// fakeIssuer is an OIDC issuer serving discovery and keys over TLS.
type fakeIssuer struct {
	server *httptest.Server
	key    *rsa.PrivateKey
	kid    string
	hits   atomic.Int64
}

func newFakeIssuer(t *testing.T) *fakeIssuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	f := &fakeIssuer{key: key, kid: "key-1"}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		f.hits.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                f.server.URL,
			"jwks_uri":                              f.server.URL + "/keys",
			"authorization_endpoint":                f.server.URL + "/authorize",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		f.hits.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "alg": "RS256", "use": "sig", "kid": f.kid,
			"n": base64.RawURLEncoding.EncodeToString(f.key.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(f.key.E)).Bytes()),
		}}})
	})
	f.server = httptest.NewTLSServer(mux)
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeIssuer) sign(t *testing.T, key *rsa.PrivateKey, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = f.kid
	s, err := tok.SignedString(key)
	require.NoError(t, err)
	return s
}

func (f *fakeIssuer) token(t *testing.T, mutate func(c jwt.MapClaims)) string {
	t.Helper()
	claims := jwt.MapClaims{
		"iss": f.server.URL,
		"aud": "rancher",
		"sub": "system:serviceaccount:agents:scaler",
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(10 * time.Minute).Unix(),
	}
	if mutate != nil {
		mutate(claims)
	}
	return f.sign(t, f.key, claims)
}

type fakeTokenCreator struct {
	requests []exttokenstore.AgentTokenRequest
	err      error
}

func (c *fakeTokenCreator) CreateAgentToken(req exttokenstore.AgentTokenRequest) (*ext.Token, error) {
	c.requests = append(c.requests, req)
	if c.err != nil {
		return nil, c.err
	}
	return &ext.Token{
		ObjectMeta: metav1.ObjectMeta{Name: "token-abc"},
		Spec:       ext.TokenSpec{TTL: req.TTL},
		Status:     ext.TokenStatus{BearerToken: "ext/token-abc:secret"},
	}, nil
}

func trustFor(issuer string, mutate func(t *v3.AgentTrust)) *v3.AgentTrust {
	trust := &v3.AgentTrust{
		ObjectMeta: metav1.ObjectMeta{Name: "scaler"},
		Spec: v3.AgentTrustSpec{
			Issuer:   issuer,
			Audience: "rancher",
			Subjects: []string{"system:serviceaccount:agents:scaler"},
			UserID:   "u-1",
			Rules: []v3.AgentRule{{
				Verbs: []string{"get", "list"}, APIGroups: []string{"apps"}, Resources: []string{"deployments"},
			}},
			MaxTTLSeconds: 900,
		},
	}
	if mutate != nil {
		mutate(trust)
	}
	return trust
}

type exchangeFixture struct {
	handler *exchangeHandler
	creator *fakeTokenCreator
	issuer  *fakeIssuer
}

func newExchangeFixture(t *testing.T, trusts func(issuerURL string) []*v3.AgentTrust) *exchangeFixture {
	t.Helper()
	issuer := newFakeIssuer(t)
	ctrl := gomock.NewController(t)
	cache := fake.NewMockNonNamespacedCacheInterface[*v3.AgentTrust](ctrl)
	cache.EXPECT().List(gomock.Any()).DoAndReturn(func(any) ([]*v3.AgentTrust, error) {
		return trusts(issuer.server.URL), nil
	}).AnyTimes()

	creator := &fakeTokenCreator{}
	return &exchangeFixture{
		issuer:  issuer,
		creator: creator,
		handler: &exchangeHandler{
			trusts: cache,
			tokens: creator,
			// The test server's certificate is trusted by its own client.
			verifiers: newVerifierCache(context.Background(), issuer.server.Client()),
			limiter:   rate.NewLimiter(rate.Inf, 1),
			now:       time.Now,
		},
	}
}

func exchangeForm(subjectToken string, extra ...string) url.Values {
	form := url.Values{
		"grant_type":         {grantTypeTokenExchange},
		"subject_token":      {subjectToken},
		"subject_token_type": {tokenTypeJWT},
	}
	for i := 0; i+1 < len(extra); i += 2 {
		form.Set(extra[i], extra[i+1])
	}
	return form
}

func (f *exchangeFixture) post(form url.Values) *httptest.ResponseRecorder {
	// Go through the token endpoint, to check the grant is routed.
	h := &tokenHandler{exchange: f.handler}
	r := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.tokenEndpoint(w, r)
	return w
}

func errorCode(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		Error string `json:"error"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	return body.Error
}

func TestTokenExchange(t *testing.T) {
	single := func(mutate func(t *v3.AgentTrust)) func(string) []*v3.AgentTrust {
		return func(issuer string) []*v3.AgentTrust { return []*v3.AgentTrust{trustFor(issuer, mutate)} }
	}

	t.Run("exchanges a trusted identity token for an agent token", func(t *testing.T) {
		f := newExchangeFixture(t, single(nil))
		w := f.post(exchangeForm(f.issuer.token(t, nil)))

		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
		var resp exchangeResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Equal(t, "ext/token-abc:secret", resp.AccessToken)
		assert.Equal(t, tokenTypeAccessToken, resp.IssuedTokenType)
		assert.Equal(t, "Bearer", resp.TokenType)
		assert.Equal(t, int64(900), resp.ExpiresIn)

		require.Len(t, f.creator.requests, 1)
		req := f.creator.requests[0]
		assert.Equal(t, "u-1", req.UserID)
		assert.Equal(t, int64(900_000), req.TTL)
		assert.Equal(t, "scaler", req.Agent.Name, "agent name defaults to the trust name")
		assert.Equal(t, []ext.TokenAgentRule{{
			Verbs: []string{"get", "list"}, APIGroups: []string{"apps"}, Resources: []string{"deployments"},
		}}, req.Agent.Rules)
		assert.Equal(t, "scaler", req.Labels[AgentTrustLabel])
	})

	t.Run("agent name and default ttl come from the trust", func(t *testing.T) {
		f := newExchangeFixture(t, single(func(tr *v3.AgentTrust) {
			tr.Spec.AgentName = "pod-scaler"
			tr.Spec.MaxTTLSeconds = 0
		}))
		w := f.post(exchangeForm(f.issuer.token(t, nil), "requested_token_type", tokenTypeAccessToken))
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		assert.Equal(t, "pod-scaler", f.creator.requests[0].Agent.Name)
		assert.Equal(t, int64(defaultAgentTrustTTLSeconds*1000), f.creator.requests[0].TTL)
	})

	t.Run("an id_token subject token type is accepted", func(t *testing.T) {
		f := newExchangeFixture(t, single(nil))
		form := exchangeForm(f.issuer.token(t, nil), "subject_token_type", tokenTypeIDToken)
		require.Equal(t, http.StatusOK, f.post(form).Code)
	})

	t.Run("the second of several trusts for an issuer can match", func(t *testing.T) {
		f := newExchangeFixture(t, func(issuer string) []*v3.AgentTrust {
			return []*v3.AgentTrust{
				trustFor(issuer, func(tr *v3.AgentTrust) {
					tr.Name = "a-other"
					tr.Spec.Subjects = []string{"someone-else"}
				}),
				trustFor(issuer, func(tr *v3.AgentTrust) {
					tr.Name = "b-scaler"
					tr.Spec.UserID = "u-2"
				}),
			}
		})
		require.Equal(t, http.StatusOK, f.post(exchangeForm(f.issuer.token(t, nil))).Code)
		assert.Equal(t, "u-2", f.creator.requests[0].UserID)
	})

	rejected := map[string]struct {
		trust  func(t *v3.AgentTrust)
		form   func(f *exchangeFixture) url.Values
		status int
		code   string
	}{
		"audience not trusted": {
			form: func(f *exchangeFixture) url.Values {
				return exchangeForm(f.issuer.token(t, func(c jwt.MapClaims) { c["aud"] = "another-service" }))
			},
			status: http.StatusBadRequest, code: "invalid_grant",
		},
		"subject not trusted": {
			form: func(f *exchangeFixture) url.Values {
				return exchangeForm(f.issuer.token(t, func(c jwt.MapClaims) { c["sub"] = "system:serviceaccount:agents:evil" }))
			},
			status: http.StatusBadRequest, code: "invalid_grant",
		},
		"subject is not matched by prefix": {
			form: func(f *exchangeFixture) url.Values {
				return exchangeForm(f.issuer.token(t, func(c jwt.MapClaims) { c["sub"] = "system:serviceaccount:agents:scaler-2" }))
			},
			status: http.StatusBadRequest, code: "invalid_grant",
		},
		"expired token": {
			form: func(f *exchangeFixture) url.Values {
				return exchangeForm(f.issuer.token(t, func(c jwt.MapClaims) { c["exp"] = time.Now().Add(-time.Hour).Unix() }))
			},
			status: http.StatusBadRequest, code: "invalid_grant",
		},
		"signed with another key": {
			form: func(f *exchangeFixture) url.Values {
				other, err := rsa.GenerateKey(rand.Reader, 2048)
				require.NoError(t, err)
				return exchangeForm(f.issuer.sign(t, other, jwt.MapClaims{
					"iss": f.issuer.server.URL, "aud": "rancher", "sub": "system:serviceaccount:agents:scaler",
					"exp": time.Now().Add(time.Hour).Unix(),
				}))
			},
			status: http.StatusBadRequest, code: "invalid_grant",
		},
		"unsigned token": {
			form: func(f *exchangeFixture) url.Values {
				tok := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{
					"iss": f.issuer.server.URL, "aud": "rancher", "sub": "system:serviceaccount:agents:scaler",
					"exp": time.Now().Add(time.Hour).Unix(),
				})
				s, err := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
				require.NoError(t, err)
				return exchangeForm(s)
			},
			status: http.StatusBadRequest, code: "invalid_grant",
		},
		"not a jwt": {
			form:   func(*exchangeFixture) url.Values { return exchangeForm("garbage") },
			status: http.StatusBadRequest, code: "invalid_grant",
		},
		"missing subject_token": {
			form:   func(*exchangeFixture) url.Values { return exchangeForm("") },
			status: http.StatusBadRequest, code: "invalid_request",
		},
		"oversized subject_token": {
			form: func(*exchangeFixture) url.Values {
				return exchangeForm(strings.Repeat("a", maxSubjectTokenBytes+1))
			},
			status: http.StatusBadRequest, code: "invalid_request",
		},
		"wrong subject_token_type": {
			form: func(f *exchangeFixture) url.Values {
				return exchangeForm(f.issuer.token(t, nil), "subject_token_type", tokenTypeAccessToken)
			},
			status: http.StatusBadRequest, code: "invalid_request",
		},
		"unsupported requested_token_type": {
			form: func(f *exchangeFixture) url.Values {
				return exchangeForm(f.issuer.token(t, nil), "requested_token_type", tokenTypeJWT)
			},
			status: http.StatusBadRequest, code: "invalid_request",
		},
		"scope requested": {
			form: func(f *exchangeFixture) url.Values {
				return exchangeForm(f.issuer.token(t, nil), "scope", "admin")
			},
			status: http.StatusBadRequest, code: "invalid_scope",
		},
		"actor token": {
			form: func(f *exchangeFixture) url.Values {
				return exchangeForm(f.issuer.token(t, nil), "actor_token", "x")
			},
			status: http.StatusBadRequest, code: "invalid_request",
		},
	}
	for name, test := range rejected {
		t.Run("rejects: "+name, func(t *testing.T) {
			f := newExchangeFixture(t, single(test.trust))
			w := f.post(test.form(f))
			assert.Equal(t, test.status, w.Code, w.Body.String())
			assert.Equal(t, test.code, errorCode(t, w))
			assert.Empty(t, f.creator.requests, "no token may be created")
			assert.NotContains(t, w.Body.String(), "ext/", "no token in the response")
		})
	}

	t.Run("an unknown issuer is not contacted and not revealed", func(t *testing.T) {
		f := newExchangeFixture(t, single(nil))
		other := newFakeIssuer(t)
		w := f.post(exchangeForm(other.token(t, nil)))
		assert.Equal(t, "invalid_grant", errorCode(t, w))
		assert.Zero(t, other.hits.Load(), "the unknown issuer must not be contacted")
		assert.Zero(t, f.issuer.hits.Load(), "no trusted issuer is contacted either")
		assert.Empty(t, f.creator.requests)
	})

	t.Run("ignores trusts which are not valid", func(t *testing.T) {
		for name, mutate := range map[string]func(tr *v3.AgentTrust){
			"no subjects":        func(tr *v3.AgentTrust) { tr.Spec.Subjects = nil },
			"empty subject":      func(tr *v3.AgentTrust) { tr.Spec.Subjects = []string{""} },
			"no audience":        func(tr *v3.AgentTrust) { tr.Spec.Audience = "" },
			"no user":            func(tr *v3.AgentTrust) { tr.Spec.UserID = "" },
			"no rules":           func(tr *v3.AgentTrust) { tr.Spec.Rules = nil },
			"bad agent name":     func(tr *v3.AgentTrust) { tr.Spec.AgentName = "Not A Label" },
			"plain http":         func(tr *v3.AgentTrust) { tr.Spec.Issuer = strings.Replace(tr.Spec.Issuer, "https", "http", 1) },
			"rule without verbs": func(tr *v3.AgentTrust) { tr.Spec.Rules[0].Verbs = nil },
		} {
			t.Run(name, func(t *testing.T) {
				f := newExchangeFixture(t, single(mutate))
				w := f.post(exchangeForm(f.issuer.token(t, nil)))
				assert.Equal(t, "invalid_grant", errorCode(t, w))
				assert.Empty(t, f.creator.requests)
			})
		}
	})

	t.Run("a trust whose user is gone is not revealed", func(t *testing.T) {
		f := newExchangeFixture(t, single(nil))
		f.creator.err = apierrors.NewBadRequest("user u-1 not found")
		w := f.post(exchangeForm(f.issuer.token(t, nil)))
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Equal(t, "invalid_grant", errorCode(t, w))
		assert.NotContains(t, w.Body.String(), "u-1")
	})

	t.Run("an internal failure is a server error without details", func(t *testing.T) {
		f := newExchangeFixture(t, single(nil))
		f.creator.err = apierrors.NewInternalError(fmt.Errorf("secret store exploded"))
		w := f.post(exchangeForm(f.issuer.token(t, nil)))
		assert.Equal(t, http.StatusInternalServerError, w.Code)
		assert.Equal(t, "server_error", errorCode(t, w))
		assert.NotContains(t, w.Body.String(), "exploded")
	})

	t.Run("an unreachable issuer fails the exchange and is retried later", func(t *testing.T) {
		f := newExchangeFixture(t, single(nil))
		token := f.issuer.token(t, nil)
		f.issuer.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "down", http.StatusServiceUnavailable)
		})
		assert.Equal(t, "invalid_grant", errorCode(t, f.post(exchangeForm(token))))
		assert.Empty(t, f.creator.requests)
		assert.Empty(t, f.handler.verifiers.providers, "a failed discovery must not be cached")
	})

	t.Run("the endpoint is rate limited", func(t *testing.T) {
		f := newExchangeFixture(t, single(nil))
		f.handler.limiter = rate.NewLimiter(rate.Every(time.Hour), 1)
		token := f.issuer.token(t, nil)
		assert.Equal(t, http.StatusOK, f.post(exchangeForm(token)).Code)
		w := f.post(exchangeForm(token))
		assert.Equal(t, http.StatusTooManyRequests, w.Code)
		assert.Len(t, f.creator.requests, 1)
	})

	t.Run("the grant is unsupported without a handler", func(t *testing.T) {
		h := &tokenHandler{}
		r := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(exchangeForm("x").Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		h.tokenEndpoint(w, r)
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Equal(t, "unsupported_grant_type", errorCode(t, w))
	})
}

func TestIssuerHTTPClient(t *testing.T) {
	t.Run("refuses plain http", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
		defer srv.Close()
		_, err := newIssuerHTTPClient().Get(srv.URL)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "https")
	})

	t.Run("refuses a redirect to http", func(t *testing.T) {
		plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
		defer plain.Close()
		secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, plain.URL, http.StatusFound)
		}))
		defer secure.Close()

		client := newIssuerHTTPClient()
		client.Transport.(*limitedTransport).next = secure.Client().Transport
		_, err := client.Get(secure.URL)
		require.Error(t, err)
	})

	t.Run("fails reads past the size limit", func(t *testing.T) {
		secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(strings.Repeat("a", maxIssuerResponseBytes+10)))
		}))
		defer secure.Close()

		client := newIssuerHTTPClient()
		client.Transport.(*limitedTransport).next = secure.Client().Transport
		resp, err := client.Get(secure.URL)
		require.NoError(t, err)
		defer resp.Body.Close()
		buf := make([]byte, 0, 4096)
		var readErr error
		for readErr == nil {
			chunk := make([]byte, 4096)
			var n int
			n, readErr = resp.Body.Read(chunk)
			buf = append(buf, chunk[:n]...)
		}
		require.Error(t, readErr)
		assert.Contains(t, readErr.Error(), "larger than")
		assert.LessOrEqual(t, len(buf), maxIssuerResponseBytes)
	})
}

func TestValidateTrustIssuer(t *testing.T) {
	trust := func(issuer string) *v3.AgentTrust {
		return &v3.AgentTrust{
			ObjectMeta: metav1.ObjectMeta{Name: "scaler"},
			Spec: v3.AgentTrustSpec{
				Issuer: issuer, Audience: "rancher", Subjects: []string{"sub"}, UserID: "u-1",
				Rules: []v3.AgentRule{{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"pods"}}},
			},
		}
	}
	assert.NoError(t, validateTrust(trust("https://issuer.example/path")))
	for _, issuer := range []string{"https://issuer.example/#frag", "https://user@issuer.example", "https://user:pw@issuer.example", "http://issuer.example", "https:///x"} {
		assert.Error(t, validateTrust(trust(issuer)), issuer)
	}
}
