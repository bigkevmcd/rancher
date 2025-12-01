package provider

import (
	"testing"

	"net/http"

	"golang.org/x/time/rate"
	"github.com/stretchr/testify/assert"
)

func TestValidateRegistrationRequest(t *testing.T) {
	handler := &registrationHandler{}

	testCases := []struct {
		name        string
		input       ClientRegistrationRequest
		expectError bool
	}{
		{
			name: "valid request",
			input: ClientRegistrationRequest{
				RedirectURIs:            []string{"https://example.com/callback"},
				GrantTypes:              []string{"authorization_code"},
				ResponseTypes:           []string{"code"},
				TokenEndpointAuthMethod: "client_secret_basic",
			},
			expectError: false,
		},
		{
			name: "multiple valid redirect URIs",
			input: ClientRegistrationRequest{
				RedirectURIs: []string{
					"https://example.com/callback",
					"https://example.org/auth",
					"http://localhost:8080/callback",
				},
			},
			expectError: false,
		},
		{
			name: "missing redirect URIs",
			input: ClientRegistrationRequest{
				ClientName: "Test",
			},
			expectError: true,
		},
		{
			name: "empty redirect URI",
			input: ClientRegistrationRequest{
				RedirectURIs: []string{""},
			},
			expectError: true,
		},
		{
			name: "redirect URI without scheme",
			input: ClientRegistrationRequest{
				RedirectURIs: []string{"example.com/callback"},
			},
			expectError: true,
		},
		{
			name: "redirect URI with fragment",
			input: ClientRegistrationRequest{
				RedirectURIs: []string{"https://example.com/callback#fragment"},
			},
			expectError: true,
		},
		{
			name: "unsupported grant type",
			input: ClientRegistrationRequest{
				RedirectURIs: []string{"https://example.com/callback"},
				GrantTypes:   []string{"implicit"},
			},
			expectError: true,
		},
		{
			name: "unsupported response type",
			input: ClientRegistrationRequest{
				RedirectURIs:  []string{"https://example.com/callback"},
				ResponseTypes: []string{"token"},
			},
			expectError: true,
		},
		{
			name: "unsupported token endpoint auth method",
			input: ClientRegistrationRequest{
				RedirectURIs:            []string{"https://example.com/callback"},
				TokenEndpointAuthMethod: "client_secret_jwt",
			},
			expectError: true,
		},
		{
			name: "valid token endpoint auth method - client_secret_post",
			input: ClientRegistrationRequest{
				RedirectURIs:            []string{"https://example.com/callback"},
				TokenEndpointAuthMethod: "client_secret_post",
			},
			expectError: false,
		},
		{
			name: "valid token endpoint auth method - none",
			input: ClientRegistrationRequest{
				RedirectURIs:            []string{"https://example.com/callback"},
				TokenEndpointAuthMethod: "none",
			},
			expectError: false,
		},
		{
			name: "supported grant types - authorization_code and refresh_token",
			input: ClientRegistrationRequest{
				RedirectURIs: []string{"https://example.com/callback"},
				GrantTypes:   []string{"authorization_code", "refresh_token"},
			},
			expectError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := handler.validateRegistrationRequest(&tc.input)
			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestApplyDefaults(t *testing.T) {
	handler := &registrationHandler{}

	testCases := []struct {
		name     string
		input    ClientRegistrationRequest
		expected ClientRegistrationRequest
	}{
		{
			name: "all fields empty",
			input: ClientRegistrationRequest{
				RedirectURIs: []string{"https://example.com/callback"},
			},
			expected: ClientRegistrationRequest{
				RedirectURIs:            []string{"https://example.com/callback"},
				TokenEndpointAuthMethod: "client_secret_basic",
				GrantTypes:              []string{"authorization_code"},
				ResponseTypes:           []string{"code"},
				ClientName:              "Dynamic Client",
			},
		},
		{
			name: "some fields set",
			input: ClientRegistrationRequest{
				RedirectURIs: []string{"https://example.com/callback"},
				ClientName:   "My Client",
				GrantTypes:   []string{"authorization_code", "refresh_token"},
			},
			expected: ClientRegistrationRequest{
				RedirectURIs:            []string{"https://example.com/callback"},
				TokenEndpointAuthMethod: "client_secret_basic",
				GrantTypes:              []string{"authorization_code", "refresh_token"},
				ResponseTypes:           []string{"code"},
				ClientName:              "My Client",
			},
		},
		{
			name: "all fields set",
			input: ClientRegistrationRequest{
				RedirectURIs:            []string{"https://example.com/callback"},
				TokenEndpointAuthMethod: "client_secret_post",
				GrantTypes:              []string{"authorization_code"},
				ResponseTypes:           []string{"code"},
				ClientName:              "Custom Client",
			},
			expected: ClientRegistrationRequest{
				RedirectURIs:            []string{"https://example.com/callback"},
				TokenEndpointAuthMethod: "client_secret_post",
				GrantTypes:              []string{"authorization_code"},
				ResponseTypes:           []string{"code"},
				ClientName:              "Custom Client",
			},
		},
		{
			name: "empty client name gets default",
			input: ClientRegistrationRequest{
				RedirectURIs:            []string{"https://example.com/callback"},
				TokenEndpointAuthMethod: "client_secret_post",
				GrantTypes:              []string{"authorization_code"},
				ResponseTypes:           []string{"code"},
			},
			expected: ClientRegistrationRequest{
				RedirectURIs:            []string{"https://example.com/callback"},
				TokenEndpointAuthMethod: "client_secret_post",
				GrantTypes:              []string{"authorization_code"},
				ResponseTypes:           []string{"code"},
				ClientName:              "Dynamic Client",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := tc.input
			handler.applyDefaults(&req)
			assert.Equal(t, tc.expected, req)
		})
	}
}

func TestRateLimiting(t *testing.T) {
handler := &registrationHandler{
rateLimiters:      make(map[string]*rate.Limiter),
registrationRate:  rate.Limit(1), // 1 request per second for testing
registrationBurst: 2,              // allow burst of 2
}

testCases := []struct {
name          string
ip            string
requestCount  int
expectAllowed int
}{
{
name:          "within burst limit",
ip:            "192.168.1.1",
requestCount:  2,
expectAllowed: 2,
},
{
name:          "exceeds burst limit",
ip:            "192.168.1.2",
requestCount:  5,
expectAllowed: 2,
},
{
name:          "different IPs have separate limits",
ip:            "192.168.1.3",
requestCount:  2,
expectAllowed: 2,
},
}

for _, tc := range testCases {
t.Run(tc.name, func(t *testing.T) {
allowed := 0
for i := 0; i < tc.requestCount; i++ {
limiter := handler.getLimiter(tc.ip)
if limiter.Allow() {
allowed++
}
}
assert.Equal(t, tc.expectAllowed, allowed)
})
}
}

func TestGetClientIP(t *testing.T) {
handler := &registrationHandler{}

testCases := []struct {
name       string
remoteAddr string
headers    map[string]string
expectedIP string
}{
{
name:       "X-Forwarded-For single IP",
remoteAddr: "10.0.0.1:12345",
headers: map[string]string{
"X-Forwarded-For": "203.0.113.1",
},
expectedIP: "203.0.113.1",
},
{
name:       "X-Forwarded-For multiple IPs",
remoteAddr: "10.0.0.1:12345",
headers: map[string]string{
"X-Forwarded-For": "203.0.113.1, 198.51.100.1, 192.0.2.1",
},
expectedIP: "203.0.113.1",
},
{
name:       "X-Real-IP",
remoteAddr: "10.0.0.1:12345",
headers: map[string]string{
"X-Real-IP": "203.0.113.5",
},
expectedIP: "203.0.113.5",
},
{
name:       "X-Forwarded-For takes precedence over X-Real-IP",
remoteAddr: "10.0.0.1:12345",
headers: map[string]string{
"X-Forwarded-For": "203.0.113.1",
"X-Real-IP":       "203.0.113.5",
},
expectedIP: "203.0.113.1",
},
{
name:       "RemoteAddr without port",
remoteAddr: "192.168.1.100",
headers:    map[string]string{},
expectedIP: "192.168.1.100",
},
{
name:       "RemoteAddr with port",
remoteAddr: "192.168.1.100:54321",
headers:    map[string]string{},
expectedIP: "192.168.1.100",
},
{
name:       "IPv6 with port",
remoteAddr: "[::1]:8080",
headers:    map[string]string{},
expectedIP: "[::1]",
},
}

for _, tc := range testCases {
t.Run(tc.name, func(t *testing.T) {
req := &http.Request{
RemoteAddr: tc.remoteAddr,
Header:     http.Header{},
}
for k, v := range tc.headers {
req.Header.Set(k, v)
}

ip := handler.getClientIP(req)
assert.Equal(t, tc.expectedIP, ip)
})
}
}
