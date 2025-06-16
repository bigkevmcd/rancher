package githubapp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid" // For generating unique IDs for codes/tokens
)

const (
	oauthPort           = ":8080"
	authCodeLifetime    = 5 * time.Minute
	accessTokenLifetime = 1 * time.Hour
)

type fakeClientDetails struct {
	Secret       string
	RedirectURIs []string
}

type fakeAuthCode struct {
	ClientID    string
	RedirectURI string
	UserID      string
	Expiry      time.Time
}

type fakeAccessToken struct {
	ClientID string
	UserID   string
	Expiry   time.Time
}

type fakeGitHubServer struct {
	*http.ServeMux
	t *testing.T
	// Registered clients: clientID -> clientSecret, redirectURIs
	registeredClients map[string]fakeClientDetails
	// Stored authorization codes: code -> {clientID, redirectURI, userID, expiry}
	authCodes map[string]fakeAuthCode
	// Stored access tokens: token -> {clientID, userID, expiry}
	accessTokens map[string]fakeAccessToken
}

func withTestCode(clientID, code, redirectURI, userID string) func(*fakeGitHubServer) {
	return func(s *fakeGitHubServer) {
		s.authCodes[code] = fakeAuthCode{
			ClientID:    clientID,
			RedirectURI: redirectURI,
			UserID:      userID,
			Expiry:      time.Now().Add(authCodeLifetime),
		}
	}
}

// func verifyAPIVersion(t *testing.T, next http.Handler) http.Handler {
// 	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 		if apiVersion := r.Header.Get("X-GitHub-Api-Version"); apiVersion != "2022-11-28" {
// 			t.Errorf("invalid X-GitHub-Api-Version: %s", apiVersion)
// 			return
// 		}

// 		next.ServeHTTP(w, r)
// 	})
// }

func newFakeGitHubServer(t *testing.T, opts ...func(*fakeGitHubServer)) *fakeGitHubServer {
	mux := http.NewServeMux()

	srv := &fakeGitHubServer{
		ServeMux: mux,
		registeredClients: map[string]fakeClientDetails{
			"test_client_id": {
				Secret: "test_client_secret",
				RedirectURIs: []string{
					"http://localhost:3000/callback",
					"http://127.0.0.1:3000/callback"},
			},
		},
		authCodes:    map[string]fakeAuthCode{},
		accessTokens: map[string]fakeAccessToken{},
		t:            t,
	}
	for _, opt := range opts {
		opt(srv)
	}

	srv.HandleFunc("/authorize", srv.authorizeHandler)
	srv.HandleFunc("/login/oauth/access_token", srv.tokenHandler)
	srv.HandleFunc("/userinfo", srv.userinfoHandler)
	srv.HandleFunc("/api/v3/user", srv.userHandler)

	return srv
}

// authorizeHandler simulates the user consent and redirects back to the client.
// Expected query parameters: response_type, client_id, redirect_uri, scope, state
func (s *fakeGitHubServer) authorizeHandler(w http.ResponseWriter, r *http.Request) {
	s.t.Logf("Received /authorize request from %s", r.RemoteAddr)
	query := r.URL.Query()

	responseType := query.Get("response_type")
	clientID := query.Get("client_id")
	redirectURI := query.Get("redirect_uri")
	// scope := query.Get("scope")
	state := query.Get("state")

	if responseType != "code" {
		http.Error(w, "Unsupported response_type. Only 'code' is supported.", http.StatusBadRequest)
		return
	}
	if clientID == "" {
		http.Error(w, "Missing client_id", http.StatusBadRequest)
		return
	}
	if redirectURI == "" {
		http.Error(w, "Missing redirect_uri", http.StatusBadRequest)
		return
	}
	if !s.isValidRedirectURI(clientID, redirectURI) {
		http.Error(w, "Invalid redirect_uri for the provided client_id", http.StatusBadRequest)
		return
	}

	userID := "fake_user_123"
	// Generate a unique authorization code
	authCode := uuid.New().String()
	s.authCodes[authCode] = fakeAuthCode{
		ClientID:    clientID,
		RedirectURI: redirectURI,
		UserID:      userID,
		Expiry:      time.Now().Add(authCodeLifetime),
	}
	s.t.Logf("Generated auth code: %s for client %s, user %s", authCode, clientID, userID)

	// Build the redirect URL with the authorization code and state
	redirectURL, err := url.Parse(redirectURI)
	if err != nil {
		s.t.Logf("Error parsing redirect URI: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	params := redirectURL.Query()
	params.Add("code", authCode)
	if state != "" {
		params.Add("state", state)
	}
	redirectURL.RawQuery = params.Encode()

	s.t.Logf("Redirecting to: %s", redirectURL.String())
	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}

// tokenHandler exchanges an authorization code for an access token.
// Expected form parameters: client_id, client_secret, code, redirect_uri
// https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps#2-users-are-redirected-back-to-your-site-by-github
func (s *fakeGitHubServer) tokenHandler(w http.ResponseWriter, r *http.Request) {
	s.t.Logf("Received /token request from %s", r.RemoteAddr)
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	clientID := r.Form.Get("client_id")
	clientSecret := r.Form.Get("client_secret")
	code := r.Form.Get("code")

	registeredClient, ok := s.registeredClients[clientID]
	if !ok || registeredClient.Secret != clientSecret {
		s.t.Logf("Invalid client credentials: %s", clientID)
		http.Error(w, `{"error": "invalid_client"}`, http.StatusUnauthorized)
		return
	}

	authCodeData, ok := s.authCodes[code]
	if !ok || authCodeData.Expiry.Before(time.Now()) || authCodeData.ClientID != clientID {
		s.t.Logf("Invalid or expired authorization code for client %s", clientID)
		http.Error(w, `{"error": "invalid_grant"}`, http.StatusBadRequest)
		return
	}

	// Invalidate the used authorization code (one-time use)
	delete(s.authCodes, code)
	s.t.Logf("Auth code %s consumed.", code)

	// Generate a unique access token
	accessToken := uuid.New().String()
	s.accessTokens[accessToken] = fakeAccessToken{
		ClientID: clientID,
		UserID:   authCodeData.UserID,
		Expiry:   time.Now().Add(accessTokenLifetime),
	}
	s.t.Logf("Generated access token: %s for client %s, user %s", accessToken, clientID, authCodeData.UserID)

	// Respond with the access token
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   int(accessTokenLifetime.Seconds()),
		// A real OAuth server might also return refresh_token, scope, etc.
	})
}

// userinfoHandler simulates a protected resource endpoint.
// Requires an Authorization: Bearer <access_token> header.
func (s *fakeGitHubServer) userinfoHandler(w http.ResponseWriter, r *http.Request) {
	s.t.Logf("Received /userinfo request from %s", r.RemoteAddr)
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, `{"error": "unauthorized", "message": "Missing Authorization header"}`, http.StatusUnauthorized)
		return
	}

	// Extract token
	const bearerPrefix = "Bearer "
	if len(authHeader) < len(bearerPrefix) || authHeader[:len(bearerPrefix)] != bearerPrefix {
		http.Error(w, `{"error": "invalid_token", "message": "Invalid Authorization header format"}`, http.StatusUnauthorized)
		return
	}
	accessToken := authHeader[len(bearerPrefix):]

	// Validate access token
	tokenData, ok := s.accessTokens[accessToken]
	if !ok || tokenData.Expiry.Before(time.Now()) {
		s.t.Logf("Invalid or expired access token: %s", accessToken)
		http.Error(w, `{"error": "invalid_token", "message": "Access token is invalid or expired"}`, http.StatusUnauthorized)
		return
	}

	s.t.Logf("Access token %s is valid for user %s", accessToken, tokenData.UserID)

	// Respond with fake user info
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"sub":      tokenData.UserID, // Subject (user ID)
		"name":     "Fake User",
		"email":    fmt.Sprintf("%s@example.com", tokenData.UserID),
		"client":   tokenData.ClientID,
		"accessed": time.Now().Format(time.RFC3339),
	})
}

// userHandler fakes the GitHub user info API
// Requires an Authorization: token <oauth_token> header.
// This should probably be updated to use the Bearer token convention https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps#3-use-the-access-token-to-access-the-api
// https://docs.github.com/en/enterprise-server@3.13/rest/users/users?apiVersion=2022-11-28#get-the-authenticated-user
func (s *fakeGitHubServer) userHandler(w http.ResponseWriter, r *http.Request) {
	s.t.Logf("Received /api/v3/user request from %s", r.RemoteAddr)
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, `{"error": "unauthorized", "message": "Missing Authorization header"}`, http.StatusUnauthorized)
		return
	}

	const bearerPrefix = "token "
	if len(authHeader) < len(bearerPrefix) || authHeader[:len(bearerPrefix)] != bearerPrefix {
		http.Error(w, `{"error": "invalid_token", "message": "Invalid Authorization header format"}`, http.StatusUnauthorized)
		return
	}
	accessToken := authHeader[len(bearerPrefix):]

	tokenData, ok := s.accessTokens[accessToken]
	if !ok || tokenData.Expiry.Before(time.Now()) {
		s.t.Logf("Invalid or expired access token: %s", accessToken)
		http.Error(w, `{"error": "invalid_token", "message": "Access token is invalid or expired"}`, http.StatusUnauthorized)
		return
	}

	s.t.Logf("Access token %s is valid for user %s", accessToken, tokenData.UserID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"login":                     "octocat",
		"id":                        1,
		"node_id":                   "MDQ6VXNlcjE=",
		"avatar_url":                "https://github.com/images/error/octocat_happy.gif",
		"gravatar_id":               "",
		"url":                       "https://HOSTNAME/users/octocat",
		"html_url":                  "https://github.com/octocat",
		"followers_url":             "https://HOSTNAME/users/octocat/followers",
		"following_url":             "https://HOSTNAME/users/octocat/following{/other_user}",
		"gists_url":                 "https://HOSTNAME/users/octocat/gists{/gist_id}",
		"starred_url":               "https://HOSTNAME/users/octocat/starred{/owner}{/repo}",
		"subscriptions_url":         "https://HOSTNAME/users/octocat/subscriptions",
		"organizations_url":         "https://HOSTNAME/users/octocat/orgs",
		"repos_url":                 "https://HOSTNAME/users/octocat/repos",
		"events_url":                "https://HOSTNAME/users/octocat/events{/privacy}",
		"received_events_url":       "https://HOSTNAME/users/octocat/received_events",
		"type":                      "User",
		"site_admin":                false,
		"name":                      "monalisa octocat",
		"company":                   "GitHub",
		"blog":                      "https://github.com/blog",
		"location":                  "San Francisco",
		"email":                     "octocat@github.com",
		"hireable":                  false,
		"bio":                       "There once was...",
		"public_repos":              2,
		"public_gists":              1,
		"followers":                 20,
		"following":                 0,
		"created_at":                "2008-01-14T04:33:35Z",
		"updated_at":                "2008-01-14T04:33:35Z",
		"private_gists":             81,
		"total_private_repos":       100,
		"owned_private_repos":       100,
		"disk_usage":                10000,
		"collaborators":             8,
		"two_factor_authentication": true,
		"plan": map[string]any{
			"name":          "Medium",
			"space":         400,
			"private_repos": 20,
			"collaborators": 0,
		},
	})
}

// Helper function to check if a redirect URI is valid for a given client.
func (s *fakeGitHubServer) isValidRedirectURI(clientID, redirectURI string) bool {
	client, ok := s.registeredClients[clientID]
	if !ok {
		return false // Client not registered
	}
	for _, uri := range client.RedirectURIs {
		if uri == redirectURI {
			return true
		}
	}
	return false
}
