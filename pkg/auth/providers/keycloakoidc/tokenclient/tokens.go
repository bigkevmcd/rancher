package tokenclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"
)

// ErrUnauthorized should be returned from functions called by RetryWithToken
// in the event of an unauthorized response.
var ErrUnauthorized = errors.New("unauthorized")

// New creates and returns a KeycloakTokenClient with the provided details.
func New(endpoint, clientID, clientSecret, realm string, opts ...func(*KeycloakTokenClient)) *KeycloakTokenClient {
	client := &KeycloakTokenClient{
		Endpoint:     endpoint,
		ClientID:     clientID,
		clientSecret: clientSecret,
		Realm:        realm,
		httpClient:   http.DefaultClient,
		clock:        time.Now,
	}

	for _, opt := range opts {
		opt(client)
	}

	return client
}

// NewFromEnvironment creates and returns a new KeycloakTokenClient using the
// following environment variables:
//
// KEYCLOAK_ENDPOINT
// KEYCLOAK_REALM
// KEYCLOAK_CLIENT_ID
// KEYCLOAK_CLIENT_SECRET
func NewFromEnvironment(opts ...func(*KeycloakTokenClient)) (*KeycloakTokenClient, error) {
	endpoint, realm := os.Getenv("KEYCLOAK_ENDPOINT"), os.Getenv("KEYCLOAK_REALM")
	clientID, clientSecret := os.Getenv("KEYCLOAK_CLIENT_ID"), os.Getenv("KEYCLOAK_CLIENT_SECRET")

	// TODO: Return an error if any of these are ""

	return New(endpoint, clientID, clientSecret, realm, opts...), nil
}

type tokenResponse struct {
	AccessToken     string        `json:"access_token"`
	ExpiresIn       time.Duration `json:"expires_in"`
	TokenType       string        `json:"token_type"`
	NotBeforePolicy int           `json:"not-before-policy"`
	Scope           string        `json:"scope"`
}

// Used to maintain a Keycloak authentication token.
type KeycloakTokenClient struct {
	Endpoint     string
	ClientID     string
	clientSecret string
	Realm        string
	httpClient   *http.Client

	lastResponse     *tokenResponse
	lastResponseTime time.Time
	clock            func() time.Time
}

// GetToken returns token that can be used as a Bearer token to access the
// Keycloak API.
func (o *KeycloakTokenClient) GetToken(ctx context.Context) (string, error) {
	if o.hasValidAccessToken() {
		return o.lastResponse.AccessToken, nil
	}

	tokenURL, err := url.JoinPath(o.Endpoint, "realms", o.Realm, "protocol", "openid-connect", "token")
	if err != nil {
		// TODO: Improve error?
		return "", err
	}
	values := url.Values{}
	values.Set("client_id", o.ClientID)
	values.Set("client_secret", o.clientSecret)
	values.Set("grant_type", "client_credentials")

	resp, err := o.httpClient.PostForm(tokenURL, values)
	if err != nil {
		// TODO: Improve error?
		return "", err
	}
	defer func() {
		resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK {
		return "", readKeycloakError(resp)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		// TODO: Improve error
		return "", err
	}
	var token tokenResponse
	if err := json.Unmarshal(body, &token); err != nil {
		// TODO: Improve error
		return "", err
	}

	// TODO: Error if token.AccessToken == ""?

	o.lastResponseTime = o.clock()
	o.lastResponse = &token

	return token.AccessToken, nil
}

// ForceRefresh clears the existing token and the next request should make a
// fresh token request.
func (o *KeycloakTokenClient) ForceRefresh() {
	o.lastResponse = nil
}

// RetryWithToken executes a function and provides a token.
//
// If the function returns an Unauthorized error then the function will be
// called again with a refreshed token.
func (o *KeycloakTokenClient) RetryWithToken(ctx context.Context, f func(ctx context.Context, token string) error) error {
	token, err := o.GetToken(ctx)
	if err != nil {
		// TODO: Improve error
		return err
	}

	executeErr := f(ctx, token)
	if errors.Is(executeErr, ErrUnauthorized) {
		o.ForceRefresh()
		token, err := o.GetToken(ctx)
		if err != nil {
			return errors.Join(executeErr, err)
		}

		return f(ctx, token)
	}

	return executeErr
}

func (o *KeycloakTokenClient) hasValidAccessToken() bool {
	if o.lastResponse == nil {
		return false
	}

	if time.Since(o.lastResponseTime) > o.lastResponse.ExpiresIn*time.Second {
		return false
	}

	return true
}

// KeycloakError parses a Keycloak error response.
type KeycloakError struct {
	Response   map[string]any
	StatusCode int
}

func (e KeycloakError) Error() string {
	if msg, ok := e.Response["error"]; ok {
		return msg.(string)
	}

	if msg, ok := e.Response["errorMessage"]; ok {
		return msg.(string)
	}

	return fmt.Sprintf("unknown error: %v", e.StatusCode)
}

// readKeycloakError parses an HTTP Response and returns an error with the
// message from Keycloak.
func readKeycloakError(resp *http.Response) error {
	defer resp.Body.Close()
	var response map[string]any
	decoder := json.NewDecoder(resp.Body)

	if err := decoder.Decode(&response); err != nil {
		return err
	}

	return KeycloakError{Response: response, StatusCode: resp.StatusCode}
}
