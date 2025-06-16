package githubapp

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	mgmtv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"
)

func TestGithubAppClientGetAccessToken(t *testing.T) {
	srv := httptest.NewServer(newFakeGitHubServer(t,
		withTestCode("test_client_id", "1234567", "http://localhost:3000/callback", "testing")))
	defer srv.Close()

	appClient := githubAppClient{httpClient: http.DefaultClient}
	token, err := appClient.getAccessToken("1234567", &mgmtv3.GithubAppConfig{
		Hostname:     stripScheme(t, srv),
		ClientID:     "test_client_id",
		ClientSecret: "test_client_secret",
	})
	if err != nil {
		t.Fatal(err)
	}

	if token == "" {
		t.Error("did not get a token")
	}
}

// TODO: Test with invalid token
func TestGithubAppClientGetUser(t *testing.T) {
	srv := httptest.NewServer(newFakeGitHubServer(t,
		withTestCode("test_client_id", "1234567", "http://localhost:3000/callback", "testing")))
	defer srv.Close()
	cfg := &mgmtv3.GithubAppConfig{
		Hostname:     stripScheme(t, srv),
		ClientID:     "test_client_id",
		ClientSecret: "test_client_secret",
	}

	appClient := githubAppClient{httpClient: http.DefaultClient}
	token, err := appClient.getAccessToken("1234567", cfg)
	if err != nil {
		t.Fatal(err)
	}
	account, err := appClient.getUser(token, cfg)
	if err != nil {
		t.Fatal(err)
	}

	want := Account{
		ID:        1,
		Login:     "octocat",
		Name:      "monalisa octocat",
		AvatarURL: "https://github.com/images/error/octocat_happy.gif",
		HTMLURL:   "https://github.com/octocat",
		Type:      "User",
	}

	assert.Equal(t, want, account)
}

func TestGithubAppClientGetOrgs(t *testing.T) {
	srv := httptest.NewServer(newFakeGitHubServer(t,
		withTestCode("test_client_id", "1234567", "http://localhost:3000/callback", "testing")))
	defer srv.Close()
	cfg := &mgmtv3.GithubAppConfig{
		Hostname:     stripScheme(t, srv),
		ClientID:     "test_client_id",
		ClientSecret: "test_client_secret",
	}

	appClient := githubAppClient{httpClient: http.DefaultClient}
	orgs, err := appClient.getOrgs(cfg)
	if err != nil {
		t.Fatal(err)
	}
	want := []Account{}

	assert.Equal(t, want, orgs)
}

func stripScheme(t *testing.T, ts *httptest.Server) string {
	parsed, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}

	return parsed.Host
}

func newOAuthConf(url string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     "test_client_id",
		ClientSecret: "test_client_secret",
		RedirectURL:  "http://localhost:3000/callback",
		Scopes:       []string{"email", "profile"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  url + "/auth",
			TokenURL: url + "/token",
		},
	}
}
