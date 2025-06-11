package githubapp

import (
	"net/http"
	"net/http/httptest"
	"testing"

	mgmtv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"golang.org/x/oauth2"
)

func TestMockOAuth(t *testing.T) {
	srv := httptest.NewServer(newFakeOAuthServer(t,
		withTestCode("test_client_id", "1234567", "http://localhost:3000/callback", "testing")))
	defer srv.Close()

	appClient := githubAppClient{httpClient: http.DefaultClient}
	token, err := appClient.getAccessToken("1234567", &mgmtv3.GithubAppConfig{})
	if err != nil {
		t.Fatal(err)
	}

	// token, err := newOAuthConf(srv.URL).Exchange(context.TODO(), "1234567")

	if token == "" {
		t.Error("did not get a token")
	}

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
