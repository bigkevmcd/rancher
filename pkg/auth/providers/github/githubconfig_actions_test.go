package github

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"

	"github.com/rancher/norman/types"
	normantypes "github.com/rancher/norman/types"
	v32 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/rancher/pkg/auth/accessor"
	v3 "github.com/rancher/rancher/pkg/generated/norman/management.cattle.io/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestGitHubProvider(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "POST /login/oauth/access_token":
			w.Write([]byte(`{"access_token": "this-is-a-test-token"}`))
		case "GET /api/v3/user":
			w.Write([]byte(`{"id": 1}`))
		case "GET /api/v3/user/orgs":
			w.Write([]byte(`[]`))
		case "GET /api/v3/user/teams":
			w.Write([]byte(`[]`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	srvURL, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("testAndApply", func(t *testing.T) {
		fakeTokens := &fakeTokensManager{
			isMemberOfFunc: func(token accessor.TokenAccessor, group v3.Principal) bool {
				return true
			},
			createTokenAndSetCookieFunc: func(userID string, userPrincipal v3.Principal, groupPrincipals []v3.Principal, providerToken string, ttl int, description string, request *types.APIContext) error {
				if userID != "testing" {
					t.Errorf("createTokenAndSetCookieFunc() got userID %s, want %s", userID, "testing")
				}

				wantUserPrincipal := v3.Principal{
					ObjectMeta: metav1.ObjectMeta{
						Name: "github_user://1",
					},
					PrincipalType: "user", Me: true,
					Provider: "github",
				}
				if !reflect.DeepEqual(userPrincipal, wantUserPrincipal) {
					t.Errorf("createTokenAndSetCookieFunc() got userPrincipal %#v, want %#v", userPrincipal, wantUserPrincipal)
				}

				if groupPrincipals != nil {
					t.Errorf("createTokenAndSetCookieFunc() got groupPrincipals %#v, want nil", groupPrincipals)
				}

				if providerToken != "this-is-a-test-token" {
					t.Errorf("createTokenAndSetCookieFunc() got providerToken %q, want %q", providerToken, "this-is-a-test-token")
				}

				return nil
			},
		}

		config := v32.GithubConfig{
			Hostname: srvURL.Host,
		}

		provider := ghProvider{
			githubClient: &GClient{httpClient: srv.Client()},
			ctx:          context.Background(),
			getConfig:    func() (*v32.GithubConfig, error) { return &config, nil },
			saveConfig:   func(*v32.GithubConfig) error { return nil },
			tokenMGR:     fakeTokens,
			userMGR:      stubUserManager{hasAccess: true, username: "testing"},
		}

		input := &v32.GithubConfigApplyInput{
			GithubConfig: config,
			Code:         "testing",
			Enabled:      true,
		}
		httpReq := httptest.NewRequest(http.MethodGet, "/not-used", jsonReader(t, input))
		req := &normantypes.APIContext{Request: httpReq}

		if err := provider.testAndApply(req); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("LoginUser", func(t *testing.T) {
		config := &v32.GithubConfig{
			Hostname: srvURL.Host,
		}

		provider := ghProvider{
			githubClient: &GClient{httpClient: srv.Client()},
			ctx:          context.Background(),
			getConfig:    func() (*v32.GithubConfig, error) { return config, nil },
			saveConfig:   func(*v32.GithubConfig) error { return nil },
			userMGR:      stubUserManager{hasAccess: true, username: "testing"},
		}

		_, _, token, err := provider.LoginUser("", &v32.GithubLogin{}, config, false)
		if err != nil {
			t.Fatal(err)
		}

		if token != "this-is-a-test-token" {
			t.Errorf("got provider token %v, want %v", token, "this-is-a-test-token")
		}
	})
}

func jsonReader(t *testing.T, v any) *bytes.Buffer {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}

	return bytes.NewBuffer(b)
}

type stubUserManager struct {
	username  string
	hasAccess bool
}

func (m stubUserManager) CheckAccess(accessMode string, allowedPrincipalIDs []string, userPrincipalID string, groups []v3.Principal) (bool, error) {
	return m.hasAccess, nil
}

func (m stubUserManager) SetPrincipalOnCurrentUser(apiContext *normantypes.APIContext, principal v3.Principal) (*v3.User, error) {
	return &v3.User{ObjectMeta: metav1.ObjectMeta{Name: m.username}}, nil
}
