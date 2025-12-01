package provider

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	wrangmgmtv3 "github.com/rancher/rancher/pkg/generated/controllers/management.cattle.io/v3"
	oidcerror "github.com/rancher/rancher/pkg/oidc/provider/error"
	"github.com/rancher/rancher/pkg/oidc/randomstring"
	corev1 "github.com/rancher/wrangler/v3/pkg/generated/controllers/core/v1"
	"golang.org/x/time/rate"
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ClientRegistrationRequest represents a client registration request as defined in RFC 7591
type ClientRegistrationRequest struct {
	// RedirectURIs is an array of redirection URIs for use in redirect-based flows
	RedirectURIs []string `json:"redirect_uris,omitempty"`
	// TokenEndpointAuthMethod is the requested authentication method for the token endpoint
	TokenEndpointAuthMethod string `json:"token_endpoint_auth_method,omitempty"`
	// GrantTypes is an array of OAuth 2.0 grant type strings
	GrantTypes []string `json:"grant_types,omitempty"`
	// ResponseTypes is an array of OAuth 2.0 response type strings
	ResponseTypes []string `json:"response_types,omitempty"`
	// ClientName is a human-readable string name of the client
	ClientName string `json:"client_name,omitempty"`
	// ClientURI is the URL of the home page of the client
	ClientURI string `json:"client_uri,omitempty"`
	// LogoURI is the URL that references a logo for the client
	LogoURI string `json:"logo_uri,omitempty"`
	// Scope is a space-separated list of scope values
	Scope string `json:"scope,omitempty"`
	// Contacts is an array of strings representing ways to contact people responsible for this client
	Contacts []string `json:"contacts,omitempty"`
	// TOSUri is the URL that points to a human-readable terms of service document
	TOSUri string `json:"tos_uri,omitempty"`
	// PolicyURI is the URL that points to a human-readable privacy policy document
	PolicyURI string `json:"policy_uri,omitempty"`
	// JWKSUri is the URL for the client's JSON Web Key Set
	JWKSUri string `json:"jwks_uri,omitempty"`
	// SoftwareID is a unique identifier string assigned by the client developer
	SoftwareID string `json:"software_id,omitempty"`
	// SoftwareVersion is a version identifier string for the client software
	SoftwareVersion string `json:"software_version,omitempty"`
}

// ClientRegistrationResponse represents a successful client registration response as defined in RFC 7591
type ClientRegistrationResponse struct {
	// ClientID is the unique client identifier
	ClientID string `json:"client_id"`
	// ClientSecret is the client secret (for confidential clients)
	ClientSecret string `json:"client_secret,omitempty"`
	// ClientIDIssuedAt is the time at which the client identifier was issued
	ClientIDIssuedAt int64 `json:"client_id_issued_at"`
	// ClientSecretExpiresAt is the time at which the client secret will expire or 0 if it will not expire
	ClientSecretExpiresAt int64 `json:"client_secret_expires_at,omitempty"`
	// RedirectURIs is an array of registered redirection URIs
	RedirectURIs []string `json:"redirect_uris,omitempty"`
	// TokenEndpointAuthMethod is the authentication method for the token endpoint
	TokenEndpointAuthMethod string `json:"token_endpoint_auth_method,omitempty"`
	// GrantTypes is an array of OAuth 2.0 grant type strings
	GrantTypes []string `json:"grant_types,omitempty"`
	// ResponseTypes is an array of OAuth 2.0 response type strings
	ResponseTypes []string `json:"response_types,omitempty"`
	// ClientName is the human-readable name of the client
	ClientName string `json:"client_name,omitempty"`
	// ClientURI is the URL of the home page of the client
	ClientURI string `json:"client_uri,omitempty"`
	// LogoURI is the URL that references a logo for the client
	LogoURI string `json:"logo_uri,omitempty"`
	// Scope is a space-separated list of scope values
	Scope string `json:"scope,omitempty"`
	// Contacts is an array of strings representing ways to contact people responsible for this client
	Contacts []string `json:"contacts,omitempty"`
	// TOSUri is the URL that points to a human-readable terms of service document
	TOSUri string `json:"tos_uri,omitempty"`
	// PolicyURI is the URL that points to a human-readable privacy policy document
	PolicyURI string `json:"policy_uri,omitempty"`
	// JWKSUri is the URL for the client's JSON Web Key Set
	JWKSUri string `json:"jwks_uri,omitempty"`
	// SoftwareID is a unique identifier string assigned by the client developer
	SoftwareID string `json:"software_id,omitempty"`
	// SoftwareVersion is a version identifier string for the client software
	SoftwareVersion string `json:"software_version,omitempty"`
}

type registrationHandler struct {
	oidcClientClient wrangmgmtv3.OIDCClientClient
	oidcClientCache  wrangmgmtv3.OIDCClientCache
	secretClient     corev1.SecretClient
	secretCache      corev1.SecretCache
	randomGenerator  *randomstring.Generator
	now              func() time.Time
	// Rate limiting per IP address
	rateLimiters      map[string]*rate.Limiter
	rateLimitersMu    sync.RWMutex
	registrationRate  rate.Limit // requests per second
	registrationBurst int        // burst size
}

// No interface needed - using concrete type *randomstring.Generator directly

func newRegistrationHandler(
	oidcClientClient wrangmgmtv3.OIDCClientClient,
	oidcClientCache wrangmgmtv3.OIDCClientCache,
	secretClient corev1.SecretClient,
	secretCache corev1.SecretCache,
	randomGenerator *randomstring.Generator,
) *registrationHandler {
	return &registrationHandler{
		oidcClientClient: oidcClientClient,
		oidcClientCache:  oidcClientCache,
		secretClient:     secretClient,
		secretCache:      secretCache,
		randomGenerator:  randomGenerator,
		rateLimiters:     make(map[string]*rate.Limiter),
		registrationRate: rate.Limit(0.1), // 1 request per 10 seconds per IP
		registrationBurst: 3,               // allow burst of 3 requests
		now:              time.Now,
	}
}

// registerEndpoint implements the dynamic client registration endpoint as defined in RFC 7591
func (h *registrationHandler) registerEndpoint(w http.ResponseWriter, r *http.Request) {
	// Check rate limit
	clientIP := h.getClientIP(r)
	limiter := h.getLimiter(clientIP)
	if !limiter.Allow() {
		oidcerror.WriteError(oidcerror.InvalidRequest, "rate limit exceeded", http.StatusTooManyRequests, w)
		return
	}

	var req ClientRegistrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		oidcerror.WriteError(oidcerror.InvalidRequest, "invalid request body", http.StatusBadRequest, w)
		return
	}

	// Validate the registration request
	if err := h.validateRegistrationRequest(&req); err != nil {
		oidcerror.WriteError(oidcerror.InvalidClientMetadata, err.Error(), http.StatusBadRequest, w)
		return
	}

	// Apply defaults for optional fields
	h.applyDefaults(&req)

	// Generate client ID
	clientID, err := h.randomGenerator.GenerateClientID()
	if err != nil {
		oidcerror.WriteError(oidcerror.ServerError, "failed to generate client ID", http.StatusInternalServerError, w)
		return
	}

	// Generate client secret
	clientSecret, err := h.randomGenerator.GenerateClientSecret()
	if err != nil {
		oidcerror.WriteError(oidcerror.ServerError, "failed to generate client secret", http.StatusInternalServerError, w)
		return
	}

	// Create OIDCClient resource
	oidcClient := &v3.OIDCClient{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "dynamic-client-",
			Annotations: map[string]string{
				"oidc.management.cattle.io/dynamic": "true",
			},
		},
		Spec: v3.OIDCClientSpec{
			Description:                   req.ClientName,
			RedirectURIs:                  req.RedirectURIs,
			TokenExpirationSeconds:        3600,    // 1 hour default
			RefreshTokenExpirationSeconds: 2592000, // 30 days default
		},
	}

	// Create the OIDCClient
	createdClient, err := h.oidcClientClient.Create(oidcClient)
	if err != nil {
		oidcerror.WriteError(oidcerror.ServerError, "failed to create client", http.StatusInternalServerError, w)
		return
	}

	// Update status with client ID
	createdClient.Status.ClientID = clientID
	if createdClient.Status.ClientSecrets == nil {
		createdClient.Status.ClientSecrets = make(map[string]v3.OIDCClientSecretStatus)
	}

	// Store client secret in Kubernetes secret
	secretHash := sha256.Sum256([]byte(clientSecret))
	secretHashStr := hex.EncodeToString(secretHash[:])

	secretName := fmt.Sprintf("oidc-client-%s", createdClient.Name)
	secret := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: secretsNamespace,
			Labels: map[string]string{
				"oidc.management.cattle.io/client": createdClient.Name,
			},
		},
		Type: v1.SecretTypeOpaque,
		Data: map[string][]byte{
			secretHashStr: []byte(clientSecret),
		},
	}

	_, err = h.secretClient.Create(secret)
	if err != nil && !apierrors.IsAlreadyExists(err) {
		// Clean up the OIDCClient if secret creation fails
		_ = h.oidcClientClient.Delete(createdClient.Name, &metav1.DeleteOptions{})
		oidcerror.WriteError(oidcerror.ServerError, "failed to store client secret", http.StatusInternalServerError, w)
		return
	}

	// Update client secret status
	now := h.now()
	createdClient.Status.ClientSecrets[secretHashStr] = v3.OIDCClientSecretStatus{
		CreatedAt:          now.Format(time.RFC3339),
		LastFiveCharacters: clientSecret[len(clientSecret)-5:],
	}

	_, err = h.oidcClientClient.UpdateStatus(createdClient)
	if err != nil {
		// Clean up on failure
		_ = h.secretClient.Delete(secretsNamespace, secretName, &metav1.DeleteOptions{})
		_ = h.oidcClientClient.Delete(createdClient.Name, &metav1.DeleteOptions{})
		oidcerror.WriteError(oidcerror.ServerError, "failed to update client status", http.StatusInternalServerError, w)
		return
	}

	// Build response
	response := ClientRegistrationResponse{
		ClientID:                clientID,
		ClientSecret:            clientSecret,
		ClientIDIssuedAt:        now.Unix(),
		ClientSecretExpiresAt:   0, // Never expires
		RedirectURIs:            req.RedirectURIs,
		TokenEndpointAuthMethod: req.TokenEndpointAuthMethod,
		GrantTypes:              req.GrantTypes,
		ResponseTypes:           req.ResponseTypes,
		ClientName:              req.ClientName,
		ClientURI:               req.ClientURI,
		LogoURI:                 req.LogoURI,
		Scope:                   req.Scope,
		Contacts:                req.Contacts,
		TOSUri:                  req.TOSUri,
		PolicyURI:               req.PolicyURI,
		JWKSUri:                 req.JWKSUri,
		SoftwareID:              req.SoftwareID,
		SoftwareVersion:         req.SoftwareVersion,
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusCreated)

	if err := json.NewEncoder(w).Encode(response); err != nil {
		// Response already sent, just log the error
		fmt.Printf("failed to encode registration response: %v\n", err)
	}
}

// validateRegistrationRequest validates the client registration request according to RFC 7591
func (h *registrationHandler) validateRegistrationRequest(req *ClientRegistrationRequest) error {
	// Validate redirect URIs
	if len(req.RedirectURIs) == 0 {
		return fmt.Errorf("at least one redirect_uri is required")
	}

	for _, redirectURI := range req.RedirectURIs {
		if redirectURI == "" {
			return fmt.Errorf("redirect_uri cannot be empty")
		}

		parsedURL, err := url.Parse(redirectURI)
		if err != nil {
			return fmt.Errorf("invalid redirect_uri: %s", redirectURI)
		}

		if parsedURL.Scheme == "" {
			return fmt.Errorf("redirect_uri must have a scheme: %s", redirectURI)
		}

		// Fragment identifiers are not allowed in redirect URIs
		if parsedURL.Fragment != "" {
			return fmt.Errorf("redirect_uri must not contain fragment: %s", redirectURI)
		}
	}

	// Validate grant types if provided
	if len(req.GrantTypes) > 0 {
		validGrantTypes := map[string]bool{
			"authorization_code": true,
			"refresh_token":      true,
		}
		for _, grantType := range req.GrantTypes {
			if !validGrantTypes[grantType] {
				return fmt.Errorf("unsupported grant_type: %s", grantType)
			}
		}
	}

	// Validate response types if provided
	if len(req.ResponseTypes) > 0 {
		validResponseTypes := map[string]bool{
			"code": true,
		}
		for _, responseType := range req.ResponseTypes {
			if !validResponseTypes[responseType] {
				return fmt.Errorf("unsupported response_type: %s", responseType)
			}
		}
	}

	// Validate token endpoint auth method if provided
	if req.TokenEndpointAuthMethod != "" {
		validAuthMethods := map[string]bool{
			"client_secret_basic": true,
			"client_secret_post":  true,
			"none":                true,
		}
		if !validAuthMethods[req.TokenEndpointAuthMethod] {
			return fmt.Errorf("unsupported token_endpoint_auth_method: %s", req.TokenEndpointAuthMethod)
		}
	}

	return nil
}

// applyDefaults applies default values to optional fields in the registration request
func (h *registrationHandler) applyDefaults(req *ClientRegistrationRequest) {
	if req.TokenEndpointAuthMethod == "" {
		req.TokenEndpointAuthMethod = "client_secret_basic"
	}

	if len(req.GrantTypes) == 0 {
		req.GrantTypes = []string{"authorization_code"}
	}

	if len(req.ResponseTypes) == 0 {
		req.ResponseTypes = []string{"code"}
	}

	if req.ClientName == "" {
		req.ClientName = "Dynamic Client"
	}
}

// getLimiter returns the rate limiter for the given IP address
func (h *registrationHandler) getLimiter(ip string) *rate.Limiter {
h.rateLimitersMu.Lock()
defer h.rateLimitersMu.Unlock()

limiter, exists := h.rateLimiters[ip]
if !exists {
limiter = rate.NewLimiter(h.registrationRate, h.registrationBurst)
h.rateLimiters[ip] = limiter
}

return limiter
}

// getClientIP extracts the client IP from the request
func (h *registrationHandler) getClientIP(r *http.Request) string {
// Check X-Forwarded-For header first (for proxied requests)
if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
// X-Forwarded-For can contain multiple IPs, use the first one
if idx := len(xff); idx > 0 {
for i := 0; i < idx; i++ {
if xff[i] == ',' {
return xff[:i]
}
}
return xff
}
}

// Check X-Real-IP header
if xri := r.Header.Get("X-Real-IP"); xri != "" {
return xri
}

// Fall back to RemoteAddr
ip := r.RemoteAddr
// Remove port if present
if idx := len(ip); idx > 0 {
for i := idx - 1; i >= 0; i-- {
if ip[i] == ':' {
return ip[:i]
}
}
}
return ip
}
