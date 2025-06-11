package githubapp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"golang.org/x/oauth2"
)

func TestMockOAuth(t *testing.T) {
	srv := httptest.NewServer(newFakeOAuthServer())
	defer srv.Close()

	token, err := newOAuthConf(srv.URL).Exchange(context.TODO(), "testing")
	if err != nil {
		t.Fatal(err)
	}

	if token != nil {
		t.Errorf("did not get a token %#v", token)
	}

}

func newOAuthConf(url string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     "CLIENT_ID",
		ClientSecret: "CLIENT_SECRET",
		RedirectURL:  "REDIRECT_URL",
		Scopes:       []string{"email", "profile"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  url + "/auth",
			TokenURL: url + "/token",
		},
	}
}

func newFakeOAuthServer() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		// Should return acccess token back to the user
		w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
		formBody := url.Values{
			"access_token": []string{"fake_token"},
			"scope":        []string{"user profile"},
			"token_type":   []string{"bearer"},
		}
		w.Write([]byte(formBody.Encode()))
	})

	return mux
}
