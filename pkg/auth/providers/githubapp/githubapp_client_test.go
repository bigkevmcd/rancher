package githubapp

import (
	"cmp"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
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
	privateKey := newTestCertificate(t)
	srv := httptest.NewServer(newFakeGitHubServer(t,
		withTestCode("test_client_id", "1234567", "http://localhost:3000/callback", "testing"),
		withPrivateKey("23456", privateKey),
	))
	defer srv.Close()
	cfg := &mgmtv3.GithubAppConfig{
		Hostname:     stripScheme(t, srv),
		ClientID:     "test_client_id",
		ClientSecret: "test_client_secret",
		AppID:        "23456",
		PrivateKey:   string(privateKey),
	}

	appClient := githubAppClient{httpClient: http.DefaultClient}
	orgs, err := appClient.getOrgs(cfg)
	if err != nil {
		t.Fatal(err)
	}
	want := []Account{
		{
			ID:        1,
			Login:     "example-org-1",
			Name:      "Example Org 1",
			AvatarURL: "https://example.com/avatar.jpg",
		},
		{
			ID:        2,
			Login:     "example-org-2",
			Name:      "Example Org 2",
			AvatarURL: "https://example.com/avatar.jpg",
		},
	}
	slices.SortFunc(orgs, func(a, b Account) int {
		return strings.Compare(a.Login, b.Login)
	})
	assert.Equal(t, want, orgs)
}

func TestGithubAppClientGetOrgsNotProvidingInstallationID(t *testing.T) {
	cert := newTestCertificate(t)
	srv := httptest.NewServer(newFakeGitHubServer(t,
		withTestCode("test_client_id", "1234567", "http://localhost:3000/callback", "testing"),
		withPrivateKey("1234567", cert)))
	defer srv.Close()
	cfg := &mgmtv3.GithubAppConfig{
		Hostname:     stripScheme(t, srv),
		ClientID:     "test_client_id",
		ClientSecret: "test_client_secret",
		AppID:        "1234567",
		PrivateKey:   string(cert),
	}

	appClient := githubAppClient{httpClient: http.DefaultClient}
	orgs, err := appClient.getOrgs(cfg)
	slices.SortFunc(orgs, func(a, b Account) int {
		return strings.Compare(a.Login, b.Login)
	})

	if err != nil {
		t.Fatal(err)
	}
	want := []Account{
		{
			ID:        1,
			Login:     "example-org-1",
			Name:      "Example Org 1",
			AvatarURL: "https://example.com/avatar.jpg",
		},
		{
			ID:        2,
			Login:     "example-org-2",
			Name:      "Example Org 2",
			AvatarURL: "https://example.com/avatar.jpg",
		},
	}
	assert.Equal(t, want, orgs)
}

func TestGithubAppClientGetOrgsProvidingInstallationID(t *testing.T) {
	cert := newTestCertificate(t)
	srv := httptest.NewServer(newFakeGitHubServer(t,
		withTestCode("test_client_id", "1234567", "http://localhost:3000/callback", "testing"),
		withPrivateKey("1234567", cert)))
	defer srv.Close()
	cfg := &mgmtv3.GithubAppConfig{
		Hostname:       stripScheme(t, srv),
		ClientID:       "test_client_id",
		ClientSecret:   "test_client_secret",
		AppID:          "1234567",
		PrivateKey:     string(cert),
		InstallationID: "1",
	}

	appClient := githubAppClient{httpClient: http.DefaultClient}
	orgs, err := appClient.getOrgs(cfg)
	if err != nil {
		t.Fatal(err)
	}
	want := []Account{
		{
			ID:        1,
			Login:     "example-org-1",
			Name:      "Example Org 1",
			AvatarURL: "https://example.com/avatar.jpg",
			HTMLURL:   "",
			Type:      "",
		},
	}
	assert.Equal(t, want, orgs)
}

func TestGithubAppClientGetTeamsNotProvidingInstallationID(t *testing.T) {
	cert := newTestCertificate(t)
	srv := httptest.NewServer(newFakeGitHubServer(t,
		withTestCode("test_client_id", "1234567", "http://localhost:3000/callback", "testing"),
		withPrivateKey("1234567", cert)))
	defer srv.Close()
	cfg := &mgmtv3.GithubAppConfig{
		Hostname:     stripScheme(t, srv),
		ClientID:     "test_client_id",
		ClientSecret: "test_client_secret",
		AppID:        "1234567",
		PrivateKey:   string(cert),
	}

	appClient := githubAppClient{httpClient: http.DefaultClient}
	orgs, err := appClient.getTeams(cfg)
	if err != nil {
		t.Fatal(err)
	}

	want := []Account{
		{
			ID:        1215,
			Login:     "dev-team",
			Name:      "dev-team",
			AvatarURL: "https://example.com/avatar.jpg",
			HTMLURL:   "https://github.com/orgs/example-org-1/dev-team"},
		{
			ID:        1216,
			Login:     "dev-team",
			Name:      "dev-team",
			AvatarURL: "https://example.com/avatar.jpg",
			HTMLURL:   "https://github.com/orgs/example-org-2/dev-team",
		},
	}
	slices.SortFunc(orgs, func(a, b Account) int {
		return cmp.Compare(a.ID, b.ID)
	})
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
