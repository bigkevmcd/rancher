package tokenclient

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestGetToken(t *testing.T) {
	srv := startFakeKeycloakServer(t)
	transport := &testTransportWrapper{rt: http.DefaultTransport.(*http.Transport).Clone()}
	httpClient := srv.Client()
	httpClient.Transport = transport

	client := New(srv.URL, "client-id", "client-secret", "testing", func(cl *KeycloakTokenClient) {
		cl.httpClient = httpClient
	})

	token, err := client.GetToken(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	if token == "" {
		t.Error("did not get a token")
	}
	want := map[string]int{
		"POST /realms/testing/protocol/openid-connect/token": 1,
	}
	assert.Equal(t, want, transport.counts)
}

func TestGetTokenWithExistingToken(t *testing.T) {
	srv := startFakeKeycloakServer(t)
	transport := &testTransportWrapper{rt: http.DefaultTransport.(*http.Transport).Clone()}
	httpClient := srv.Client()
	httpClient.Transport = transport

	client := New(srv.URL, "client-id", "client-secret", "testing", func(cl *KeycloakTokenClient) {
		cl.httpClient = httpClient
	})

	token1, err := client.GetToken(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if token1 == "" {
		t.Fatal("did not get a token")
	}

	// Get the token a second time - should get the existing token
	token2, err := client.GetToken(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if token2 != token1 {
		t.Error("tokens did not match between requests")
	}
	want := map[string]int{
		"POST /realms/testing/protocol/openid-connect/token": 1,
	}
	assert.Equal(t, want, transport.counts)
}

func TestGetTokenWithExpiredToken(t *testing.T) {
	srv := startFakeKeycloakServer(t)
	transport := &testTransportWrapper{rt: http.DefaultTransport.(*http.Transport).Clone()}
	httpClient := srv.Client()
	httpClient.Transport = transport

	// This cheats the expiry time by making the last response recorded an hour
	// ago.
	now := time.Now().Add(time.Second * -3600)
	client := New(srv.URL, "client-id", "client-secret", "testing", func(cl *KeycloakTokenClient) {
		cl.httpClient = httpClient
		cl.clock = func() time.Time {
			return now
		}
	})

	token1, err := client.GetToken(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if token1 == "" {
		t.Fatal("did not get a token")
	}

	// Get the token a second time - should get a new token
	token2, err := client.GetToken(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if token2 == token1 {
		t.Error("tokens matched - response reused")
	}
	want := map[string]int{
		"POST /realms/testing/protocol/openid-connect/token": 2,
	}
	assert.Equal(t, want, transport.counts)
}

func TestForceRefresh(t *testing.T) {
	srv := startFakeKeycloakServer(t)
	transport := &testTransportWrapper{rt: http.DefaultTransport.(*http.Transport).Clone()}
	httpClient := &http.Client{Transport: transport}
	client := New(srv.URL, "client-id", "client-secret", "testing", func(cl *KeycloakTokenClient) {
		cl.httpClient = httpClient
	})

	token1, err := client.GetToken(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if token1 == "" {
		t.Fatal("did not get a token")
	}

	client.ForceRefresh()

	// Get the token a second time - should get a new token
	token2, err := client.GetToken(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if token2 == token1 {
		t.Error("tokens matched - response reused")
	}
	want := map[string]int{
		"POST /realms/testing/protocol/openid-connect/token": 2,
	}
	assert.Equal(t, want, transport.counts)
}

func TestRetryWithToken(t *testing.T) {
	srv := startFakeKeycloakServer(t)
	transport := &testTransportWrapper{rt: http.DefaultTransport.(*http.Transport).Clone()}
	httpClient := &http.Client{Transport: transport}
	client := New(srv.URL, "client-id", "client-secret", "testing", func(cl *KeycloakTokenClient) {
		cl.httpClient = httpClient
	})

	usersURL, err := url.JoinPath(client.Endpoint, "admin/realms/testing/users")
	if err != nil {
		t.Fatal(err)
	}

	var users []map[string]any
	if err := client.RetryWithToken(t.Context(), func(ctx context.Context, clientToken string) error {
		users, err = get[[]map[string]any](ctx, clientToken, usersURL)
		if err != nil {
			if err.(KeycloakError).StatusCode == http.StatusForbidden {
				return ErrUnauthorized
			}
		}

		return err
	}); err != nil {
		t.Fatal(err)
	}

	userNames := func() []string {
		var names []string
		for _, user := range users {
			names = append(names, user["username"].(string))
		}

		return names
	}()

	want := []string{"testuser", "testing"}
	assert.Equal(t, want, userNames)
}

// an http.RoundTripper that counts the number of requests by method/path.
type testTransportWrapper struct {
	rt     http.RoundTripper
	counts map[string]int
}

func (o *testTransportWrapper) RoundTrip(req *http.Request) (*http.Response, error) {
	if o.counts == nil {
		o.counts = map[string]int{}
	}
	o.counts[req.Method+" "+req.URL.Path]++

	return o.rt.RoundTrip(req)
}

func get[T any](ctx context.Context, token, queryURL string) (T, error) {
	var m T

	r, err := http.NewRequestWithContext(ctx, http.MethodGet, queryURL, nil)
	if err != nil {
		return m, err
	}

	r.Header.Add("Accept", "application/json")
	r.Header.Add("Authorization", "Bearer "+token)

	res, err := http.DefaultClient.Do(r)
	if err != nil {
		return m, err
	}

	if res.StatusCode != http.StatusOK {
		return m, readKeycloakError(res)
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return m, err
	}
	if err := res.Body.Close(); err != nil {
		return m, err
	}

	if err := json.Unmarshal(body, &m); err != nil {
		return m, err
	}

	return m, nil
}

// this is a fake Keycloak Server that only serves the token and users endpoints
// in the testing realm.
//
// Bearer token validation is only performed in the users endpoint.
func startFakeKeycloakServer(t *testing.T) *httptest.Server {
	mux := http.NewServeMux()
	mu := sync.Mutex{}
	var accessTokens []string

	mux.HandleFunc("POST /realms/testing/protocol/openid-connect/token", func(w http.ResponseWriter, r *http.Request) {
		token := "test-token-" + uuid.New().String()
		mu.Lock()
		defer mu.Unlock()
		accessTokens = append(accessTokens, token)

		response := tokenResponse{
			AccessToken: token,
			ExpiresIn:   600,
			TokenType:   "Bearer",
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	mux.HandleFunc("GET /admin/realms/testing/users", func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		mu.Lock()
		defer mu.Unlock()

		if !slices.ContainsFunc(accessTokens, func(s string) bool {
			return "Bearer "+s == token
		}) {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "invalid bearer token"})
		}

		response := []map[string]any{
			{
				"username": "testuser",
			},
			{
				"username": "testing",
			},
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(func() {
		srv.Close()
	})

	return srv
}
