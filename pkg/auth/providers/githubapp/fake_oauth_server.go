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

type fakeOAuthServer struct {
	*http.ServeMux
	t *testing.T
	// Registered clients: clientID -> clientSecret, redirectURIs
	registeredClients map[string]fakeClientDetails
	// Stored authorization codes: code -> {clientID, redirectURI, userID, expiry}
	authCodes map[string]fakeAuthCode
	// Stored access tokens: token -> {clientID, userID, expiry}
	accessTokens map[string]fakeAccessToken
}

func withTestCode(clientID, code, redirectURI, userID string) func(*fakeOAuthServer) {
	return func(s *fakeOAuthServer) {
		s.authCodes[code] = fakeAuthCode{
			ClientID:    clientID,
			RedirectURI: redirectURI,
			UserID:      userID,
			Expiry:      time.Now().Add(authCodeLifetime),
		}
	}
}

func newFakeOAuthServer(t *testing.T, opts ...func(*fakeOAuthServer)) *fakeOAuthServer {
	mux := http.NewServeMux()

	srv := &fakeOAuthServer{
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
	srv.HandleFunc("/token", srv.tokenHandler)
	srv.HandleFunc("/userinfo", srv.userinfoHandler)

	return srv
}

// authorizeHandler simulates the user consent and redirects back to the client.
// Expected query parameters: response_type, client_id, redirect_uri, scope, state
func (s *fakeOAuthServer) authorizeHandler(w http.ResponseWriter, r *http.Request) {
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
// Expected form parameters: grant_type, client_id, client_secret, code, redirect_uri
func (s *fakeOAuthServer) tokenHandler(w http.ResponseWriter, r *http.Request) {
	s.t.Logf("Received /token request from %s", r.RemoteAddr)
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	grantType := r.Form.Get("grant_type")
	clientID := r.Form.Get("client_id")
	clientSecret := r.Form.Get("client_secret")
	code := r.Form.Get("code")
	redirectURI := r.Form.Get("redirect_uri")

	// Validate grant type
	if grantType != "authorization_code" {
		s.t.Logf("Invalid grant_type: %s", grantType)
		http.Error(w, `{"error": "unsupported_grant_type"}`, http.StatusBadRequest)
		return
	}

	// Validate client ID and secret
	registeredClient, ok := s.registeredClients[clientID]
	if !ok || registeredClient.Secret != clientSecret {
		s.t.Logf("Invalid client credentials: %s", clientID)
		http.Error(w, `{"error": "invalid_client"}`, http.StatusUnauthorized)
		return
	}

	// Retrieve and validate authorization code
	authCodeData, ok := s.authCodes[code]
	if !ok || authCodeData.Expiry.Before(time.Now()) || authCodeData.ClientID != clientID || authCodeData.RedirectURI != redirectURI {
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
func (s *fakeOAuthServer) userinfoHandler(w http.ResponseWriter, r *http.Request) {
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

// Helper function to check if a redirect URI is valid for a given client.
func (s *fakeOAuthServer) isValidRedirectURI(clientID, redirectURI string) bool {
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
