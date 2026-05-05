package azure

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rancher/norman/api/writer"
	"github.com/rancher/norman/types"
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/rancher/pkg/auth/accessor"
	managementschema "github.com/rancher/rancher/pkg/schemas/management.cattle.io/v3"
	"github.com/rancher/rancher/pkg/user"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apitypes "k8s.io/apimachinery/pkg/types"
)

// TestConfigureTest inspects the Redirect URL during Azure AD setup.
func TestConfigureTest(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name                string
		authConfig          map[string]any
		expectedRedirectURL string
	}{
		{
			name: "initial setup of Azure AD with Microsoft Graph",
			authConfig: map[string]any{
				"accessMode": "unrestricted",
				"annotations": map[string]any{
					"auth.cattle.io/azuread-endpoint-migrated": "true",
				},
				"enabled":           false,
				"endpoint":          "https://login.microsoftonline.com/",
				"graphEndpoint":     "https://graph.microsoft.com",
				"tokenEndpoint":     "https://login.microsoftonline.com/tenant123/oauth2/v2.0/token",
				"authEndpoint":      "https://login.microsoftonline.com/tenant123/oauth2/v2.0/authorize",
				"tenantId":          "tenant123",
				"applicationId":     "app123",
				"applicationSecret": "secret123",
				"rancherUrl":        "https://myrancher.com",
			},
			expectedRedirectURL: "https://login.microsoftonline.com/tenant123/oauth2/v2.0/authorize?client_id=app123&redirect_uri=https://myrancher.com&response_type=code&scope=openid",
		},
		{
			name: "attempt to initially setup Azure AD with deprecated Azure AD Graph",
			authConfig: map[string]any{
				"accessMode":        "unrestricted",
				"annotations":       map[string]any{},
				"enabled":           false,
				"endpoint":          "https://login.microsoftonline.com/",
				"graphEndpoint":     "https://graph.windows.net/",
				"tokenEndpoint":     "https://login.microsoftonline.com/tenant123/oauth2/token",
				"authEndpoint":      "https://login.microsoftonline.com/tenant123/oauth2/authorize",
				"tenantId":          "tenant123",
				"applicationId":     "app123",
				"applicationSecret": "secret123",
				"rancherUrl":        "https://myrancher.com",
			},
			expectedRedirectURL: "https://login.microsoftonline.com/tenant123/oauth2/authorize?client_id=app123&redirect_uri=https://myrancher.com&response_type=code&scope=openid",
		},
		{
			name: "editing an existing setup of Azure AD",
			authConfig: map[string]any{
				"enabled":    true,
				"accessMode": "unrestricted",
				"annotations": map[string]any{
					"auth.cattle.io/azuread-endpoint-migrated": "true",
				},
				"endpoint":          "https://login.microsoftonline.com/",
				"graphEndpoint":     "https://graph.microsoft.com",
				"tokenEndpoint":     "https://login.microsoftonline.com/tenant123/oauth2/v2.0/token",
				"authEndpoint":      "https://login.microsoftonline.com/tenant123/oauth2/v2.0/authorize",
				"tenantId":          "tenant123",
				"applicationId":     "app123",
				"applicationSecret": "secret123",
				"rancherUrl":        "https://myrancher.com",
			},
			expectedRedirectURL: "https://login.microsoftonline.com/tenant123/oauth2/v2.0/authorize?client_id=app123&redirect_uri=https://myrancher.com&response_type=code&scope=openid",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			b, err := json.Marshal(test.authConfig)
			assert.NoError(t, err)

			req := httptest.NewRequest(http.MethodPost, "/v3/azureADConfigs/azuread?action=configureTest", bytes.NewReader(b))

			schemas := types.NewSchemas()
			schemas.AddSchemas(managementschema.AuthSchemas)

			rw := &writer.EncodingResponseWriter{
				ContentType: "application/json",
				Encoder:     types.JSONEncoder,
			}
			rr := httptest.NewRecorder()
			r := &types.APIContext{
				Schemas:        schemas,
				Request:        req,
				Response:       rr,
				ResponseWriter: rw,
				Version:        &managementschema.Version,
			}

			provider := Provider{}
			err = provider.ConfigureTest(r)
			assert.NoError(t, err)

			res := rr.Result()
			defer res.Body.Close()

			var output v3.AzureADConfigTestOutput
			err = json.NewDecoder(res.Body).Decode(&output)
			assert.NoError(t, err)
			assert.Equal(t, test.expectedRedirectURL, output.RedirectURL)
		})
	}

}

func TestTransformToAuthProvider(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name                 string
		authConfig           map[string]any
		expectedAuthProvider map[string]any
	}{
		{
			name: "redirect URL for Microsoft Graph",
			authConfig: map[string]any{
				"enabled":    true,
				"accessMode": "unrestricted",
				"metadata": map[string]any{
					"name": "providerName",
					"annotations": map[string]any{
						"auth.cattle.io/azuread-endpoint-migrated": "true",
					},
				},
				"endpoint":          "https://login.microsoftonline.com/",
				"graphEndpoint":     "https://graph.microsoft.com",
				"tokenEndpoint":     "https://login.microsoftonline.com/tenant123/oauth2/v2.0/token",
				"authEndpoint":      "https://login.microsoftonline.com/tenant123/oauth2/v2.0/authorize",
				"tenantId":          "tenant123",
				"applicationId":     "app123",
				"applicationSecret": "secret123",
				"rancherUrl":        "https://myrancher.com",
			},
			expectedAuthProvider: map[string]any{
				"id":                 "providerName",
				"clientId":           "app123",
				"tenantId":           "tenant123",
				"scopes":             []string{"openid", "profile", "email"},
				"authUrl":            "https://login.microsoftonline.com/tenant123/oauth2/v2.0/authorize",
				"tokenUrl":           "https://login.microsoftonline.com/tenant123/oauth2/v2.0/token",
				"deviceAuthUrl":      "https://login.microsoftonline.com/tenant123/oauth2/v2.0/devicecode",
				"redirectUrl":        "https://login.microsoftonline.com/tenant123/oauth2/v2.0/authorize?client_id=app123&redirect_uri=https://myrancher.com&response_type=code&scope=openid",
				"logoutAllSupported": false,
				"logoutAllEnabled":   false,
				"logoutAllForced":    false,
			},
		},
		{
			name: "redirect URL for disabled auth provider with annotation",
			authConfig: map[string]any{
				"accessMode": "unrestricted",
				"metadata": map[string]any{
					"name": "providerName",
					"annotations": map[string]any{
						"auth.cattle.io/azuread-endpoint-migrated": "true",
					},
				},
				"endpoint":          "https://login.microsoftonline.com/",
				"graphEndpoint":     "https://graph.microsoft.com",
				"tokenEndpoint":     "https://login.microsoftonline.com/tenant123/oauth2/token",
				"authEndpoint":      "https://login.microsoftonline.com/tenant123/oauth2/v2.0/authorize",
				"tenantId":          "tenant123",
				"applicationId":     "app123",
				"applicationSecret": "secret123",
				"rancherUrl":        "https://myrancher.com",
			},
			expectedAuthProvider: map[string]any{
				"id":                 "providerName",
				"clientId":           "app123",
				"tenantId":           "tenant123",
				"scopes":             []string{"openid", "profile", "email"},
				"authUrl":            "https://login.microsoftonline.com/tenant123/oauth2/v2.0/authorize",
				"tokenUrl":           "https://login.microsoftonline.com/tenant123/oauth2/token",
				"deviceAuthUrl":      "https://login.microsoftonline.com/tenant123/oauth2/v2.0/devicecode",
				"redirectUrl":        "https://login.microsoftonline.com/tenant123/oauth2/v2.0/authorize?client_id=app123&redirect_uri=https://myrancher.com&response_type=code&scope=openid",
				"logoutAllSupported": false,
				"logoutAllEnabled":   false,
				"logoutAllForced":    false,
			},
		},
		{
			name: "redirect URL for disabled auth provider without annotation",
			authConfig: map[string]any{
				"enabled":    false, // Here, enabled is set to false explicitly.
				"accessMode": "unrestricted",
				"metadata": map[string]any{
					"name":        "providerName",
					"annotations": map[string]any{},
				},
				"endpoint":          "https://login.microsoftonline.com/",
				"graphEndpoint":     "https://graph.windows.net/",
				"tokenEndpoint":     "https://login.microsoftonline.com/tenant123/oauth2/token",
				"authEndpoint":      "https://login.microsoftonline.com/tenant123/oauth2/authorize",
				"tenantId":          "tenant123",
				"applicationId":     "app123",
				"applicationSecret": "secret123",
				"rancherUrl":        "https://myrancher.com",
			},
			expectedAuthProvider: map[string]any{
				"id":                 "providerName",
				"clientId":           "app123",
				"tenantId":           "tenant123",
				"scopes":             []string{"openid", "profile", "email"},
				"authUrl":            "https://login.microsoftonline.com/tenant123/oauth2/authorize",
				"tokenUrl":           "https://login.microsoftonline.com/tenant123/oauth2/token",
				"deviceAuthUrl":      "https://login.microsoftonline.com/tenant123/oauth2/v2.0/devicecode",
				"redirectUrl":        "https://login.microsoftonline.com/tenant123/oauth2/authorize?client_id=app123&redirect_uri=https://myrancher.com&response_type=code&scope=openid",
				"logoutAllSupported": false,
				"logoutAllEnabled":   false,
				"logoutAllForced":    false,
			},
		},
		{
			name: "oauth URLs from default endpoint",
			authConfig: map[string]any{
				"enabled":    false, // Here, enabled is set to false explicitly.
				"accessMode": "unrestricted",
				"metadata": map[string]any{
					"name":        "providerName",
					"annotations": map[string]any{},
				},
				"endpoint":          "https://login.microsoftonline.com/",
				"graphEndpoint":     "https://graph.windows.net/",
				"authEndpoint":      "https://login.microsoftonline.com/tenant123/oauth2/authorize",
				"tenantId":          "tenant123",
				"applicationId":     "app123",
				"applicationSecret": "secret123",
				"rancherUrl":        "https://myrancher.com",
			},
			expectedAuthProvider: map[string]any{
				"id":                 "providerName",
				"clientId":           "app123",
				"tenantId":           "tenant123",
				"scopes":             []string{"openid", "profile", "email"},
				"authUrl":            "https://login.microsoftonline.com/tenant123/oauth2/authorize",
				"tokenUrl":           "https://login.microsoftonline.com/tenant123/oauth2/v2.0/token",
				"deviceAuthUrl":      "https://login.microsoftonline.com/tenant123/oauth2/v2.0/devicecode",
				"redirectUrl":        "https://login.microsoftonline.com/tenant123/oauth2/authorize?client_id=app123&redirect_uri=https://myrancher.com&response_type=code&scope=openid",
				"logoutAllSupported": false,
				"logoutAllEnabled":   false,
				"logoutAllForced":    false,
			},
		},
		{
			name: "oauth URLs from custom endpoint and no oauth URLs",
			authConfig: map[string]any{
				"enabled":    false, // Here, enabled is set to false explicitly.
				"accessMode": "unrestricted",
				"metadata": map[string]any{
					"name":        "providerName",
					"annotations": map[string]any{},
				},
				"endpoint":          "https://myendpoint.com/",
				"graphEndpoint":     "https://graph.windows.net/",
				"authEndpoint":      "https://myendpoint.com/tenant123/oauth2/authorize",
				"tenantId":          "tenant123",
				"applicationId":     "app123",
				"applicationSecret": "secret123",
				"rancherUrl":        "https://myrancher.com",
			},
			expectedAuthProvider: map[string]any{
				"id":                 "providerName",
				"clientId":           "app123",
				"tenantId":           "tenant123",
				"scopes":             []string{"openid", "profile", "email"},
				"authUrl":            "https://myendpoint.com/tenant123/oauth2/authorize",
				"tokenUrl":           "https://myendpoint.com/tenant123/oauth2/v2.0/token",
				"deviceAuthUrl":      "https://myendpoint.com/tenant123/oauth2/v2.0/devicecode",
				"redirectUrl":        "https://myendpoint.com/tenant123/oauth2/authorize?client_id=app123&redirect_uri=https://myrancher.com&response_type=code&scope=openid",
				"logoutAllSupported": false,
				"logoutAllEnabled":   false,
				"logoutAllForced":    false,
			},
		},
		{
			name: "oauth URLs from custom URLs",
			authConfig: map[string]any{
				"enabled":    false, // Here, enabled is set to false explicitly.
				"accessMode": "unrestricted",
				"metadata": map[string]any{
					"name":        "providerName",
					"annotations": map[string]any{},
				},
				"endpoint":           "https://login.microsoftonline.com/",
				"graphEndpoint":      "https://graph.windows.net/",
				"tokenEndpoint":      "https://custom.com/oauth2/token",
				"authEndpoint":       "https://custom.com/oauth2/authorize",
				"deviceAuthEndpoint": "https://custom.com/oauth2/device",
				"tenantId":           "tenant123",
				"applicationId":      "app123",
				"applicationSecret":  "secret123",
				"rancherUrl":         "https://myrancher.com",
			},
			expectedAuthProvider: map[string]any{
				"id":                 "providerName",
				"clientId":           "app123",
				"tenantId":           "tenant123",
				"scopes":             []string{"openid", "profile", "email"},
				"authUrl":            "https://custom.com/oauth2/authorize",
				"tokenUrl":           "https://custom.com/oauth2/token",
				"deviceAuthUrl":      "https://custom.com/oauth2/device",
				"redirectUrl":        "https://custom.com/oauth2/authorize?client_id=app123&redirect_uri=https://myrancher.com&response_type=code&scope=openid",
				"logoutAllSupported": false,
				"logoutAllEnabled":   false,
				"logoutAllForced":    false,
			},
		},
	}

	var provider Provider
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			authProvider, err := provider.TransformToAuthProvider(test.authConfig)
			assert.NoError(t, err)
			assert.Equal(t, test.expectedAuthProvider, authProvider)
		})
	}
}

func TestMigrateNewFlowAnnotation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name               string
		proposed           *v3.AzureADConfig
		annotationExpected bool
	}{
		{
			name:               "nil annotations gets annotation set",
			proposed:           &v3.AzureADConfig{},
			annotationExpected: true,
		},
		{
			name: "existing annotations preserved and annotation set",
			proposed: &v3.AzureADConfig{
				AuthConfig: v3.AuthConfig{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							"other": "value",
						},
					},
				},
			},
			annotationExpected: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			migrateNewFlowAnnotation(test.proposed)
			_, hasAnnotation := test.proposed.Annotations[GraphEndpointMigratedAnnotation]
			assert.Equal(t, test.annotationExpected, hasAnnotation)
		})
	}
}

func TestPreserveStoredFields(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		stored   v3.AzureADConfig
		incoming v3.AzureADConfig
		want     v3.AzureADConfig
	}{
		{
			name: "stored Enabled true survives incoming false",
			stored: v3.AzureADConfig{
				AuthConfig: v3.AuthConfig{Enabled: true},
			},
			incoming: v3.AzureADConfig{},
			want: v3.AzureADConfig{
				AuthConfig: v3.AuthConfig{Enabled: true},
			},
		},
		{
			name:   "stored Enabled false allows incoming true",
			stored: v3.AzureADConfig{},
			incoming: v3.AzureADConfig{
				AuthConfig: v3.AuthConfig{Enabled: true},
			},
			want: v3.AzureADConfig{
				AuthConfig: v3.AuthConfig{Enabled: true},
			},
		},
		{
			name:     "both Enabled false stays false",
			stored:   v3.AzureADConfig{},
			incoming: v3.AzureADConfig{},
			want:     v3.AzureADConfig{},
		},
		{
			name: "SLO fields always preserved from stored",
			stored: v3.AzureADConfig{
				AuthConfig: v3.AuthConfig{
					LogoutAllSupported: true,
				},
				EndSessionEndpoint: "https://custom.gov/logout",
				LogoutAllEnabled:   true,
				LogoutAllForced:    true,
			},
			incoming: v3.AzureADConfig{},
			want: v3.AzureADConfig{
				AuthConfig: v3.AuthConfig{
					LogoutAllSupported: true,
				},
				EndSessionEndpoint: "https://custom.gov/logout",
				LogoutAllEnabled:   true,
				LogoutAllForced:    true,
			},
		},
		{
			name: "AccessMode preserved when incoming is empty",
			stored: v3.AzureADConfig{
				AuthConfig: v3.AuthConfig{AccessMode: "restricted"},
			},
			incoming: v3.AzureADConfig{},
			want: v3.AzureADConfig{
				AuthConfig: v3.AuthConfig{AccessMode: "restricted"},
			},
		},
		{
			name: "AccessMode from incoming used when non-empty",
			stored: v3.AzureADConfig{
				AuthConfig: v3.AuthConfig{AccessMode: "restricted"},
			},
			incoming: v3.AzureADConfig{
				AuthConfig: v3.AuthConfig{AccessMode: "unrestricted"},
			},
			want: v3.AzureADConfig{
				AuthConfig: v3.AuthConfig{AccessMode: "unrestricted"},
			},
		},
		{
			name: "AllowedPrincipalIDs preserved when incoming is nil",
			stored: v3.AzureADConfig{
				AuthConfig: v3.AuthConfig{
					AllowedPrincipalIDs: []string{"azuread_user://123"},
				},
			},
			incoming: v3.AzureADConfig{},
			want: v3.AzureADConfig{
				AuthConfig: v3.AuthConfig{
					AllowedPrincipalIDs: []string{"azuread_user://123"},
				},
			},
		},
		{
			name: "AllowedPrincipalIDs from incoming used when non-nil",
			stored: v3.AzureADConfig{
				AuthConfig: v3.AuthConfig{
					AllowedPrincipalIDs: []string{"azuread_user://123"},
				},
			},
			incoming: v3.AzureADConfig{
				AuthConfig: v3.AuthConfig{
					AllowedPrincipalIDs: []string{"azuread_user://456"},
				},
			},
			want: v3.AzureADConfig{
				AuthConfig: v3.AuthConfig{
					AllowedPrincipalIDs: []string{"azuread_user://456"},
				},
			},
		},
		{
			name:   "zero-value stored does not corrupt incoming",
			stored: v3.AzureADConfig{},
			incoming: v3.AzureADConfig{
				AuthConfig: v3.AuthConfig{
					Enabled:    true,
					AccessMode: "unrestricted",
				},
			},
			want: v3.AzureADConfig{
				AuthConfig: v3.AuthConfig{
					Enabled:    true,
					AccessMode: "unrestricted",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			preserveStoredFields(&tt.stored, &tt.incoming)
			assert.Equal(t, tt.want, tt.incoming)
		})
	}
}

func newAzureConfig(endpoint, tenantID, appID string, mods ...func(*v3.AzureADConfig)) *v3.AzureADConfig {
	cfg := &v3.AzureADConfig{
		Endpoint:         endpoint,
		TenantID:         tenantID,
		ApplicationID:    appID,
		LogoutAllEnabled: true,
	}
	for _, mod := range mods {
		mod(cfg)
	}
	return cfg
}

func TestLogout(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		config  *v3.AzureADConfig
		wantErr bool
	}{
		"regular logout allowed when LogoutAllForced is false": {
			config:  newAzureConfig("https://login.microsoftonline.com/", "tenant1", "app1"),
			wantErr: false,
		},
		"regular logout rejected when LogoutAllForced is true": {
			config: newAzureConfig("https://login.microsoftonline.com/", "tenant1", "app1", func(c *v3.AzureADConfig) {
				c.LogoutAllForced = true
			}),
			wantErr: true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			p := &Provider{getConfig: func() (*v3.AzureADConfig, error) { return tt.config, nil }}
			r := httptest.NewRequest(http.MethodPost, "/v3/tokens?action=logout", nil)
			w := httptest.NewRecorder()

			err := p.Logout(w, r, &v3.Token{})
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestLogoutAllDisabled(t *testing.T) {
	t.Parallel()

	cfg := newAzureConfig("https://login.microsoftonline.com/", "tenant1", "app1", func(c *v3.AzureADConfig) {
		c.LogoutAllEnabled = false
	})
	p := &Provider{getConfig: func() (*v3.AzureADConfig, error) { return cfg, nil }}

	b, err := json.Marshal(&v3.AuthConfigLogoutInput{FinalRedirectURL: "https://example.com/logged-out"})
	require.NoError(t, err)

	r := httptest.NewRequest(http.MethodPost, "/v3/tokens?action=logoutAll", bytes.NewReader(b))
	w := httptest.NewRecorder()

	assert.ErrorContains(t, p.LogoutAll(w, r, &v3.Token{}), "not configured for SSO logout")
}

func TestLogoutAll(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		config          *v3.AzureADConfig
		idTokenCookie   string
		finalRedirect   string
		wantURLContains []string
		wantURLAbsent   []string
	}{
		"default endpoint, with id_token_hint and post_logout_redirect_uri": {
			config:        newAzureConfig("https://login.microsoftonline.com/", "tenant1", "app1"),
			idTokenCookie: "my.jwt.token",
			finalRedirect: "https://example.com/logged-out",
			wantURLContains: []string{
				"https://login.microsoftonline.com/tenant1/oauth2/v2.0/logout",
				"client_id=app1",
				"id_token_hint=my.jwt.token",
				"post_logout_redirect_uri=https%3A%2F%2Fexample.com%2Flogged-out",
			},
		},
		"default endpoint, without id_token_hint": {
			config:        newAzureConfig("https://login.microsoftonline.com/", "tenant1", "app1"),
			finalRedirect: "https://example.com/logged-out",
			wantURLContains: []string{
				"https://login.microsoftonline.com/tenant1/oauth2/v2.0/logout",
				"client_id=app1",
				"post_logout_redirect_uri=https%3A%2F%2Fexample.com%2Flogged-out",
			},
			wantURLAbsent: []string{"id_token_hint"},
		},
		"default endpoint, without post_logout_redirect_uri": {
			config:        newAzureConfig("https://login.microsoftonline.com/", "tenant1", "app1"),
			idTokenCookie: "my.jwt.token",
			wantURLContains: []string{
				"https://login.microsoftonline.com/tenant1/oauth2/v2.0/logout",
				"client_id=app1",
				"id_token_hint=my.jwt.token",
			},
			wantURLAbsent: []string{"post_logout_redirect_uri"},
		},
		"custom EndSessionEndpoint overrides default": {
			config: newAzureConfig("https://login.microsoftonline.com/", "tenant1", "app1", func(c *v3.AzureADConfig) {
				c.EndSessionEndpoint = "https://custom.gov/logout"
			}),
			finalRedirect: "https://example.com/logged-out",
			wantURLContains: []string{
				"https://custom.gov/logout",
				"client_id=app1",
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			p := &Provider{getConfig: func() (*v3.AzureADConfig, error) { return tt.config, nil }}

			b, err := json.Marshal(&v3.AuthConfigLogoutInput{FinalRedirectURL: tt.finalRedirect})
			require.NoError(t, err)

			r := httptest.NewRequest(http.MethodPost, "/v3/tokens?action=logoutAll", bytes.NewReader(b))
			if tt.idTokenCookie != "" {
				r.AddCookie(&http.Cookie{Name: IDTokenCookie, Value: tt.idTokenCookie})
			}
			w := httptest.NewRecorder()

			require.NoError(t, p.LogoutAll(w, r, &v3.Token{}))
			require.Equal(t, http.StatusOK, w.Code)

			var resp map[string]any
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
			assert.Equal(t, "authConfigLogoutOutput", resp["type"])
			assert.Equal(t, "authConfigLogoutOutput", resp["baseType"])

			idpURL, _ := resp["idpRedirectUrl"].(string)
			for _, want := range tt.wantURLContains {
				assert.Contains(t, idpURL, want)
			}
			for _, absent := range tt.wantURLAbsent {
				assert.NotContains(t, idpURL, absent)
			}
		})
	}
}

func TestSetIDTokenCookie(t *testing.T) {
	t.Parallel()

	r := httptest.NewRequest(http.MethodGet, "https://rancher.example.com/", nil)
	w := httptest.NewRecorder()
	setIDTokenCookie(r, w, "my.id.token")

	resp := w.Result()
	cookies := resp.Cookies()
	var found *http.Cookie
	for _, c := range cookies {
		if c.Name == IDTokenCookie {
			found = c
			break
		}
	}
	require.NotNil(t, found, "expected %s cookie to be set", IDTokenCookie)
	assert.Equal(t, "my.id.token", found.Value)
	assert.True(t, found.HttpOnly)
}

func TestSearchUserPrincipalsByNameODataInjection(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name           string
		searchName     string
		expectedFilter string
	}{
		{
			name:           "benign name passes through unchanged",
			searchName:     "john",
			expectedFilter: "startswith(userPrincipalName,'john') or startswith(displayName,'john') or startswith(givenName,'john') or startswith(surname,'john')",
		},
		{
			name:           "single quote in name is escaped to prevent OData injection",
			searchName:     "o'malley",
			expectedFilter: "startswith(userPrincipalName,'o''malley') or startswith(displayName,'o''malley') or startswith(givenName,'o''malley') or startswith(surname,'o''malley')",
		},
		{
			name:           "multiple single quotes are all escaped",
			searchName:     "it's O'Malley's",
			expectedFilter: "startswith(userPrincipalName,'it''s O''Malley''s') or startswith(displayName,'it''s O''Malley''s') or startswith(givenName,'it''s O''Malley''s') or startswith(surname,'it''s O''Malley''s')",
		},
		{
			name:           "injection attempt breaking out of startswith clause is neutralised",
			searchName:     "') or 1 eq 1 or startswith(x,'",
			expectedFilter: "startswith(userPrincipalName,''') or 1 eq 1 or startswith(x,''') or startswith(displayName,''') or 1 eq 1 or startswith(x,''') or startswith(givenName,''') or 1 eq 1 or startswith(x,''') or startswith(surname,''') or 1 eq 1 or startswith(x,''')",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fc := &fakeAzureClient{}
			p := &Provider{}
			_, err := p.searchUserPrincipalsByName(fc, tt.searchName, &v3.Token{})
			require.NoError(t, err)
			assert.Equal(t, tt.expectedFilter, fc.capturedUserFilter)
		})
	}
}

func TestSearchGroupPrincipalsByNameODataInjection(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name           string
		searchName     string
		expectedFilter string
	}{
		{
			name:           "benign name passes through unchanged",
			searchName:     "engineering",
			expectedFilter: "startswith(displayName,'engineering') or startswith(mail,'engineering') or startswith(mailNickname,'engineering')",
		},
		{
			name:           "single quote in name is escaped to prevent OData injection",
			searchName:     "dev's team",
			expectedFilter: "startswith(displayName,'dev''s team') or startswith(mail,'dev''s team') or startswith(mailNickname,'dev''s team')",
		},
		{
			name:           "injection attempt breaking out of startswith clause is neutralised",
			searchName:     "') or 1 eq 1 or startswith(x,'",
			expectedFilter: "startswith(displayName,''') or 1 eq 1 or startswith(x,''') or startswith(mail,''') or 1 eq 1 or startswith(x,''') or startswith(mailNickname,''') or 1 eq 1 or startswith(x,''')",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fc := &fakeAzureClient{}
			p := &Provider{}
			_, err := p.searchGroupPrincipalsByName(fc, tt.searchName, &v3.Token{})
			require.NoError(t, err)
			assert.Equal(t, tt.expectedFilter, fc.capturedGroupFilter)
		})
	}
}

func TestSearchUserPrincipalsByNameMeFlag(t *testing.T) {
	t.Parallel()

	myPrincipal := v3.Principal{
		ObjectMeta:    metav1.ObjectMeta{Name: "azuread_user://abc123"},
		LoginName:     "me@example.com",
		PrincipalType: "user",
	}
	otherPrincipal := v3.Principal{
		ObjectMeta:    metav1.ObjectMeta{Name: "azuread_user://xyz789"},
		LoginName:     "other@example.com",
		PrincipalType: "user",
	}

	token := &v3.Token{}
	token.UserPrincipal = myPrincipal

	fc := &fakeAzureClient{usersToReturn: []v3.Principal{myPrincipal, otherPrincipal}}
	p := &Provider{}

	results, err := p.searchUserPrincipalsByName(fc, "me", token)
	require.NoError(t, err)
	require.Len(t, results, 2)

	assert.True(t, results[0].Me, "first result should have Me=true because it matches the token's user principal")
	assert.False(t, results[1].Me, "second result should have Me=false because it does not match the token's user principal")
}

func TestSearchGroupPrincipalsByNameMemberOfFlag(t *testing.T) {
	t.Parallel()

	memberGroup := v3.Principal{
		ObjectMeta:    metav1.ObjectMeta{Name: "azuread_group://group-a"},
		PrincipalType: "group",
	}
	nonMemberGroup := v3.Principal{
		ObjectMeta:    metav1.ObjectMeta{Name: "azuread_group://group-b"},
		PrincipalType: "group",
	}

	fc := &fakeAzureClient{groupsToReturn: []v3.Principal{memberGroup, nonMemberGroup}}
	p := &Provider{
		userMGR: &fakeUserManager{
			isMemberOfFn: func(_ accessor.TokenAccessor, group v3.Principal) bool {
				return group.Name == memberGroup.Name
			},
		},
	}

	token := &v3.Token{}
	results, err := p.searchGroupPrincipalsByName(fc, "group", token)
	require.NoError(t, err)
	require.Len(t, results, 2)

	assert.True(t, results[0].MemberOf, "first result should have MemberOf=true because the user is a member")
	assert.False(t, results[1].MemberOf, "second result should have MemberOf=false because the user is not a member")
}

// fakeAzureClient implements clients.AzureClient. It records the OData filter
// strings passed to ListUsers and ListGroups and can be pre-loaded with
// principals to return from those calls.
type fakeAzureClient struct {
	capturedUserFilter  string
	capturedGroupFilter string
	usersToReturn       []v3.Principal
	groupsToReturn      []v3.Principal
}

func (f *fakeAzureClient) LoginUser(*v3.AzureADConfig, *v3.AzureADLogin) (v3.Principal, []v3.Principal, string, string, error) {
	return v3.Principal{}, nil, "", "", nil
}

func (f *fakeAzureClient) AccessToken() string { return "" }

func (f *fakeAzureClient) MarshalTokenJSON() (string, error) { return "", nil }

func (f *fakeAzureClient) GetUser(string) (v3.Principal, error) { return v3.Principal{}, nil }

func (f *fakeAzureClient) ListUsers(filter string) ([]v3.Principal, error) {
	f.capturedUserFilter = filter
	return f.usersToReturn, nil
}

func (f *fakeAzureClient) GetGroup(string) (v3.Principal, error) { return v3.Principal{}, nil }

func (f *fakeAzureClient) ListGroups(filter string) ([]v3.Principal, error) {
	f.capturedGroupFilter = filter
	return f.groupsToReturn, nil
}

func (f *fakeAzureClient) ListGroupMemberships(string, string) ([]string, error) { return nil, nil }

// fakeUserManager is a stub implementation of user.Manager.
// Only IsMemberOf has meaningful behaviour; all other methods panic.
type fakeUserManager struct {
	isMemberOfFn func(token accessor.TokenAccessor, group v3.Principal) bool
}

func (f *fakeUserManager) IsMemberOf(token accessor.TokenAccessor, group v3.Principal) bool {
	return f.isMemberOfFn(token, group)
}

func (f *fakeUserManager) GetUser(*http.Request) string                { panic("not implemented") }
func (f *fakeUserManager) EnsureUser(string, string) (*v3.User, error) { panic("not implemented") }
func (f *fakeUserManager) CheckAccess(string, []string, string, []v3.Principal) (bool, error) {
	panic("not implemented")
}
func (f *fakeUserManager) SetPrincipalOnCurrentUserByUserID(string, v3.Principal) (*v3.User, error) {
	panic("not implemented")
}
func (f *fakeUserManager) SetPrincipalOnCurrentUser(*http.Request, v3.Principal) (*v3.User, error) {
	panic("not implemented")
}
func (f *fakeUserManager) CreateNewUserClusterRoleBinding(string, apitypes.UID) error {
	panic("not implemented")
}
func (f *fakeUserManager) GetUserByPrincipalID(string) (*v3.User, error) { panic("not implemented") }
func (f *fakeUserManager) GetGroupsForTokenAuthProvider(accessor.TokenAccessor) []v3.Principal {
	panic("not implemented")
}
func (f *fakeUserManager) EnsureAndGetUserAttribute(string) (*v3.UserAttribute, bool, error) {
	panic("not implemented")
}
func (f *fakeUserManager) UserAttributeCreateOrUpdate(string, string, []v3.Principal, map[string][]string, ...time.Time) error {
	panic("not implemented")
}

// Compile-time assertion that fakeUserManager satisfies user.Manager.
var _ user.Manager = (*fakeUserManager)(nil)
