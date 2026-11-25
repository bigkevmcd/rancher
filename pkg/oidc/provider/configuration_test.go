package provider

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/rancher/pkg/settings"
	"github.com/rancher/wrangler/v3/pkg/generic/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"k8s.io/apimachinery/pkg/labels"
)

func TestOpenIDConfigurationEndpoint(t *testing.T) {
	const redirectURI = "https://client.example/callback"
	ctrl := gomock.NewController(t)
	oidcClientCache := fake.NewMockNonNamespacedCacheInterface[*v3.OIDCClient](ctrl)
	oidcClientCache.EXPECT().List(labels.Everything()).Return([]*v3.OIDCClient{
		{
			Spec: v3.OIDCClientSpec{
				RedirectURIs: []string{redirectURI},
			},
		},
	}, nil)
	provider := Provider{
		authHandler: &authorizeHandler{
			oidcClientCache: oidcClientCache,
		},
	}
	mux := http.NewServeMux()
	provider.RegisterOIDCProviderHandles(mux)
	rec := httptest.NewRecorder()
	err := settings.ServerURL.Set("https://rancher.com")
	assert.NoError(t, err)

	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://client.example/oidc/.well-known/openid-configuration", nil))

	assertOpenIDConfigurationResponse(t, rec)
	assert.Equal(t, http.Header{
		"Access-Control-Allow-Methods": []string{"GET, POST"},
		"Access-Control-Allow-Origin":  []string{redirectURI},
		"Content-Type":                 []string{"application/json"},
		"Referrer-Policy":              []string{"strict-origin-when-cross-origin"},
		"Strict-Transport-Security":    []string{"max-age=31536000"},
		"X-Content-Type-Options":       []string{"nosniff"},
		"X-Frame-Options":              []string{"SAMEORIGIN"},
	}, rec.Header())
}

func TestOpenIDConfigurationEndpointWithoutOIDCClients(t *testing.T) {
	ctrl := gomock.NewController(t)
	oidcClientCache := fake.NewMockNonNamespacedCacheInterface[*v3.OIDCClient](ctrl)
	oidcClientCache.EXPECT().List(labels.Everything()).Return(nil, nil)
	err := settings.ServerURL.Set("https://rancher.com")
	assert.NoError(t, err)

	provider := Provider{
		authHandler: &authorizeHandler{
			oidcClientCache: oidcClientCache,
		},
	}
	mux := http.NewServeMux()
	provider.RegisterOIDCProviderHandles(mux)
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/oidc/.well-known/openid-configuration", nil))

	assertOpenIDConfigurationResponse(t, rec)
	assert.Equal(t, http.Header{
		// Does not contain Access-Control-Allow-Origin header because there are no OIDC clients configured.
		"Access-Control-Allow-Methods": []string{"GET, POST"},
		"Content-Type":                 []string{"application/json"},
		"Referrer-Policy":              []string{"strict-origin-when-cross-origin"},
		"Strict-Transport-Security":    []string{"max-age=31536000"},
		"X-Content-Type-Options":       []string{"nosniff"},
		"X-Frame-Options":              []string{"SAMEORIGIN"},
	}, rec.Header())
}

func TestOpenIDConfigurationBackchannelMetadata(t *testing.T) {
	require.NoError(t, settings.ServerURL.Set("https://rancher.com"))
	rec := httptest.NewRecorder()
	openIDConfigurationEndpoint(rec, httptest.NewRequest(http.MethodGet, "/oidc/.well-known/openid-configuration", nil))

	// The raw JSON, so that fields which must be present (and those which must not) are checked as sent.
	var raw map[string]any
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&raw))

	// CIBA Core section 4: both of these are REQUIRED.
	assert.Equal(t, "https://rancher.com/oidc/bc-authorize", raw["backchannel_authentication_endpoint"])
	assert.Equal(t, []any{"poll"}, raw["backchannel_token_delivery_modes_supported"])
	// Sent as false and not left out, which would mean the same.
	assert.Equal(t, false, raw["backchannel_user_code_parameter_supported"])
	// No signed authentication requests, which is what the omission says.
	assert.NotContains(t, raw, "backchannel_authentication_request_signing_alg_values_supported")
	assert.Contains(t, raw["grant_types_supported"], "urn:openid:params:grant-type:ciba")
	assert.Equal(t, []any{"RS256"}, raw["id_token_signing_alg_values_supported"])
	assert.Equal(t, []any{"client_secret_basic", "client_secret_post"}, raw["token_endpoint_auth_methods_supported"])
}

func assertOpenIDConfigurationResponse(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))

	var response OpenIDConfiguration
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&response))
	assert.Equal(t, "https://rancher.com/oidc", response.Issuer)
	assert.Equal(t, "https://rancher.com/oidc/authorize", response.AuthorizationEndpoint)
	assert.Equal(t, "https://rancher.com/oidc/token", response.TokenEndpoint)
	assert.Equal(t, "https://rancher.com/oidc/userinfo", response.UserInfoEndpoint)
	assert.Equal(t, "https://rancher.com/oidc/.well-known/jwks.json", response.JWKSURI)
	assert.Equal(t, []string{"code"}, response.ResponseTypesSupported)
	assert.Equal(t, []string{"public"}, response.SubjectTypesSupported)
	assert.Equal(t, []string{"RS256"}, response.IDTokenSigningAlgsValuesSupported)
	assert.Equal(t, []string{"S256"}, response.CodeChallengeMethodsSupported)
	assert.Equal(t, []string{"openid", "profile", "offline_access"}, response.ScopesSupported)
	assert.Equal(t, []string{"authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:token-exchange"}, response.GrantTypesSupported)
	assert.Empty(t, response.BackchannelAuthenticationEndpoint)
	assert.Empty(t, response.BackchannelTokenDeliveryModesSupported)
	assert.Nil(t, response.BackchannelAuthenticationRequestSigningAlgValuesSupported)
	assert.Nil(t, response.BackchannelUserCodeParameterSupported)
}

func TestOpenIDConfigurationEndpointWithCIBA(t *testing.T) {
	require.NoError(t, settings.ServerURL.Set("https://rancher.com"))
	setCIBAFeatures(t, true, true)
	rec := httptest.NewRecorder()

	openIDConfigurationEndpoint(rec, httptest.NewRequest(http.MethodGet, "/oidc/.well-known/openid-configuration", nil))

	body := rec.Body.String()
	var response OpenIDConfiguration
	require.NoError(t, json.Unmarshal([]byte(body), &response))
	assert.Equal(t, []string{"authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:token-exchange", "urn:openid:params:grant-type:ciba"}, response.GrantTypesSupported)
	assert.Equal(t, "https://rancher.com/oidc/bc-authorize", response.BackchannelAuthenticationEndpoint)
	assert.Equal(t, []string{"poll"}, response.BackchannelTokenDeliveryModesSupported)
	// Signed requests aren't supported: the key is there, with no algorithm.
	require.NotNil(t, response.BackchannelAuthenticationRequestSigningAlgValuesSupported)
	assert.Empty(t, *response.BackchannelAuthenticationRequestSigningAlgValuesSupported)
	assert.Contains(t, body, `"backchannel_authentication_request_signing_alg_values_supported":[]`)
	// User codes aren't supported, and the document says so rather than leaving it out.
	require.NotNil(t, response.BackchannelUserCodeParameterSupported)
	assert.False(t, *response.BackchannelUserCodeParameterSupported)
	assert.Contains(t, body, `"backchannel_user_code_parameter_supported":false`)
}

// Without CIBA the document has none of the backchannel keys, whatever their value would be.
func TestOpenIDConfigurationHasNoBackchannelKeysWithoutCIBA(t *testing.T) {
	require.NoError(t, settings.ServerURL.Set("https://rancher.com"))
	setCIBAFeatures(t, true, false)
	rec := httptest.NewRecorder()

	openIDConfigurationEndpoint(rec, httptest.NewRequest(http.MethodGet, "/oidc/.well-known/openid-configuration", nil))

	assert.NotContains(t, rec.Body.String(), "backchannel")
}
