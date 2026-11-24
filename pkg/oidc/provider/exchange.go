package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/rancher/rancher/pkg/auth/audit"
	"io"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"sync"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
	ext "github.com/rancher/rancher/pkg/apis/ext.cattle.io/v1"
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	exttokenstore "github.com/rancher/rancher/pkg/ext/stores/tokens"
	wrangmgmtv3 "github.com/rancher/rancher/pkg/generated/controllers/management.cattle.io/v3"
	oidcerror "github.com/rancher/rancher/pkg/oidc/provider/error"
	"github.com/sirupsen/logrus"
	"golang.org/x/time/rate"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
)

// RFC 8693 identifiers.
const (
	grantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
	tokenTypeJWT           = "urn:ietf:params:oauth:token-type:jwt"
	tokenTypeIDToken       = "urn:ietf:params:oauth:token-type:id_token"
	tokenTypeAccessToken   = "urn:ietf:params:oauth:token-type:access_token"

	// AgentTrustLabel is set on the agent tokens issued for an AgentTrust, with the trust's name.
	AgentTrustLabel = "cattle.io/agent-trust"

	defaultAgentTrustTTLSeconds = 3600
	maxSubjectTokenBytes        = 16 * 1024
	// maxIssuerResponseBytes caps the discovery and key documents read from an issuer.
	maxIssuerResponseBytes = 1 << 20
	issuerRequestTimeout   = 10 * time.Second
	maxIssuerRedirects     = 3
)

// agentTokenCreator mints agent tokens, see [exttokenstore.SystemStore.CreateAgentToken].
type agentTokenCreator interface {
	CreateAgentToken(req exttokenstore.AgentTokenRequest) (*ext.Token, error)
}

// exchangeHandler implements the OAuth 2.0 token exchange grant (RFC 8693) for workload identity
// federation: a workload presents an identity token from an issuer an AgentTrust names, and receives
// a short-lived agent token in return, so that agents hold no long-lived Rancher credentials.
//
// The subject token authenticates the caller, so the grant needs no client credentials.
type exchangeHandler struct {
	trusts    wrangmgmtv3.AgentTrustCache
	tokens    agentTokenCreator
	verifiers *verifierCache
	limiter   *rate.Limiter
	now       func() time.Time
}

func newExchangeHandler(ctx context.Context, trusts wrangmgmtv3.AgentTrustCache, tokens agentTokenCreator) *exchangeHandler {
	return &exchangeHandler{
		trusts:    trusts,
		tokens:    tokens,
		verifiers: newVerifierCache(ctx, newIssuerHTTPClient()),
		// The endpoint is unauthenticated and may fetch from issuers, so it is limited as a whole.
		limiter: rate.NewLimiter(rate.Limit(20), 40),
		now:     time.Now,
	}
}

type exchangeResponse struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int64  `json:"expires_in"`
}

// handle serves a token exchange request on the token endpoint, whose form is already parsed.
func (h *exchangeHandler) handle(w http.ResponseWriter, r *http.Request) {
	if !h.limiter.Allow() {
		oidcerror.WriteError(oidcerror.SlowDown, "too many requests", http.StatusTooManyRequests, w)
		return
	}

	resp, oidcErr := h.exchange(r)
	if oidcErr != nil {
		logrus.Debugf("[OIDC provider] token exchange failed: %s", oidcErr.ToString())
		status := http.StatusBadRequest
		if oidcErr.Error == oidcerror.ServerError {
			status = http.StatusInternalServerError
		}
		oidcErr.Write(status, w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		logrus.Errorf("[OIDC provider] failed to encode token exchange response: %v", err)
	}
}

func (h *exchangeHandler) exchange(r *http.Request) (*exchangeResponse, *oidcerror.Error) {
	subjectToken := r.Form.Get("subject_token")
	if subjectToken == "" {
		return nil, oidcerror.New(oidcerror.InvalidRequest, "missing subject_token")
	}
	if len(subjectToken) > maxSubjectTokenBytes {
		return nil, oidcerror.New(oidcerror.InvalidRequest, "subject_token is too large")
	}
	if tokenType := r.Form.Get("subject_token_type"); tokenType != tokenTypeJWT && tokenType != tokenTypeIDToken {
		return nil, oidcerror.Newf(oidcerror.InvalidRequest, "subject_token_type must be %s or %s", tokenTypeJWT, tokenTypeIDToken)
	}
	if requested := r.Form.Get("requested_token_type"); requested != "" && requested != tokenTypeAccessToken {
		return nil, oidcerror.Newf(oidcerror.InvalidRequest, "requested_token_type must be %s", tokenTypeAccessToken)
	}
	// The authority of the token comes from the trust, and can't be asked for or narrowed here yet.
	if r.Form.Get("scope") != "" {
		return nil, oidcerror.New(oidcerror.InvalidScope, "scope is not supported, the AgentTrust defines the token's rules")
	}
	if r.Form.Get("actor_token") != "" {
		return nil, oidcerror.New(oidcerror.InvalidRequest, "actor_token is not supported")
	}

	// Only the issuer is read before the signature is verified, to find the trusts to verify it for.
	// Nothing is fetched for an issuer no trust names.
	var unverified jwt.RegisteredClaims
	if _, _, err := jwt.NewParser().ParseUnverified(subjectToken, &unverified); err != nil || unverified.Issuer == "" {
		return nil, oidcerror.New(oidcerror.InvalidGrant, "subject_token is not valid")
	}

	trusts, err := h.trustsForIssuer(unverified.Issuer)
	if err != nil {
		logrus.Errorf("[OIDC provider] failed to list agent trusts: %v", err)
		return nil, oidcerror.New(oidcerror.ServerError, "failed to look up trusts")
	}
	if len(trusts) == 0 {
		return nil, oidcerror.New(oidcerror.InvalidGrant, "subject_token is not valid")
	}

	for _, trust := range trusts {
		verifier, err := h.verifiers.verifier(trust.Spec.Issuer, trust.Spec.Audience, h.now)
		if err != nil {
			// The issuer can't be reached or is misconfigured. Another trust may use another issuer
			// URL spelling, so go on.
			logrus.Warnf("[OIDC provider] agent trust %s: cannot use issuer %s: %v", trust.Name, trust.Spec.Issuer, err)
			continue
		}
		idToken, err := verifier.Verify(r.Context(), subjectToken)
		if err != nil {
			logrus.Debugf("[OIDC provider] agent trust %s: subject_token not verified: %v", trust.Name, err)
			continue
		}
		if !slices.Contains(trust.Spec.Subjects, idToken.Subject) {
			logrus.Debugf("[OIDC provider] agent trust %s: subject %q is not trusted", trust.Name, idToken.Subject)
			continue
		}

		resp, oidcErr := h.issue(trust, idToken.Subject)
		if oidcErr == nil {
			audit.SetUserID(r.Context(), trust.Spec.UserID)
		}
		return resp, oidcErr
	}

	// The reason is deliberately not revealed: which issuers, audiences and subjects are trusted is
	// not for an unauthenticated caller to find out.
	return nil, oidcerror.New(oidcerror.InvalidGrant, "subject_token is not valid")
}

// trustsForIssuer returns the usable trusts for the issuer in name order, so which one applies if
// several do is predictable.
func (h *exchangeHandler) trustsForIssuer(issuer string) ([]*v3.AgentTrust, error) {
	all, err := h.trusts.List(labels.Everything())
	if err != nil {
		return nil, err
	}
	var trusts []*v3.AgentTrust
	for _, trust := range all {
		if trust.Spec.Issuer != issuer {
			continue
		}
		if err := validateTrust(trust); err != nil {
			logrus.Warnf("[OIDC provider] ignoring agent trust %s: %v", trust.Name, err)
			continue
		}
		trusts = append(trusts, trust)
	}
	sort.Slice(trusts, func(i, j int) bool { return trusts[i].Name < trusts[j].Name })
	return trusts, nil
}

// validateTrust rejects trusts which must not be used, as the CRD validation can't be relied on
// alone, e.g. for trusts created before it was tightened.
func validateTrust(trust *v3.AgentTrust) error {
	spec := trust.Spec
	if u, err := url.Parse(spec.Issuer); err != nil || u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("issuer must be an https URL")
	}
	if spec.Audience == "" {
		return fmt.Errorf("audience is required")
	}
	if len(spec.Subjects) == 0 || slices.Contains(spec.Subjects, "") {
		return fmt.Errorf("subjects must name at least one subject, and no empty ones")
	}
	if spec.UserID == "" {
		return fmt.Errorf("userID is required")
	}
	return exttokenstore.ValidateAgent(exttokenstore.KindAgent, agentFromTrust(trust))
}

func agentFromTrust(trust *v3.AgentTrust) *ext.TokenAgent {
	name := trust.Spec.AgentName
	if name == "" {
		name = trust.Name
	}
	agent := &ext.TokenAgent{Name: name}
	for _, r := range trust.Spec.Rules {
		agent.Rules = append(agent.Rules, ext.TokenAgentRule{Verbs: r.Verbs, APIGroups: r.APIGroups, Resources: r.Resources})
	}
	return agent
}

func (h *exchangeHandler) issue(trust *v3.AgentTrust, subject string) (*exchangeResponse, *oidcerror.Error) {
	ttlSeconds := trust.Spec.MaxTTLSeconds
	if ttlSeconds <= 0 {
		ttlSeconds = defaultAgentTrustTTLSeconds
	}

	token, err := h.tokens.CreateAgentToken(exttokenstore.AgentTokenRequest{
		UserID:      trust.Spec.UserID,
		Agent:       *agentFromTrust(trust),
		TTL:         ttlSeconds * 1000,
		Description: fmt.Sprintf("Issued for agent trust %s", trust.Name),
		Labels:      map[string]string{AgentTrustLabel: trust.Name},
	})
	if err != nil {
		if apierrors.IsBadRequest(err) {
			// The user is gone or disabled, or the trust is not usable: the trust's problem, not the caller's.
			logrus.Warnf("[OIDC provider] agent trust %s can't issue a token: %v", trust.Name, err)
			return nil, oidcerror.New(oidcerror.InvalidGrant, "subject_token is not valid")
		}
		logrus.Errorf("[OIDC provider] agent trust %s: failed to create agent token: %v", trust.Name, err)
		return nil, oidcerror.New(oidcerror.ServerError, "failed to create token")
	}

	// The token value is never logged.
	logrus.Infof("[OIDC provider] agent trust %s issued agent token %s to subject %q for user %s",
		trust.Name, token.Name, subject, trust.Spec.UserID)

	return &exchangeResponse{
		AccessToken:     token.Status.BearerToken,
		IssuedTokenType: tokenTypeAccessToken,
		TokenType:       bearerTokenType,
		ExpiresIn:       token.Spec.TTL / 1000,
	}, nil
}

// verifierCache holds a verifier for each issuer and audience, and the OIDC provider (discovery
// and key set, which refreshes itself) for each issuer. Issuers come from AgentTrusts only.
type verifierCache struct {
	// ctx outlives requests: the key sets of providers keep using it to refresh their keys.
	ctx    context.Context
	client *http.Client

	mu        sync.Mutex
	providers map[string]*gooidc.Provider
}

func newVerifierCache(ctx context.Context, client *http.Client) *verifierCache {
	return &verifierCache{
		ctx:       gooidc.ClientContext(ctx, client),
		client:    client,
		providers: map[string]*gooidc.Provider{},
	}
}

func (c *verifierCache) verifier(issuer, audience string, now func() time.Time) (*gooidc.IDTokenVerifier, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	provider, ok := c.providers[issuer]
	if !ok {
		var err error
		provider, err = gooidc.NewProvider(c.ctx, issuer)
		if err != nil {
			return nil, err
		}
		c.providers[issuer] = provider
	}

	return provider.Verifier(&gooidc.Config{
		ClientID:             audience,
		SupportedSigningAlgs: []string{"RS256", "RS384", "RS512", "ES256", "ES384", "PS256", "PS384", "PS512"},
		Now:                  now,
	}), nil
}

// newIssuerHTTPClient returns the client used to reach issuers. Responses are size limited, requests
// time out, redirects are limited and never leave https.
func newIssuerHTTPClient() *http.Client {
	return &http.Client{
		Timeout:   issuerRequestTimeout,
		Transport: &limitedTransport{next: http.DefaultTransport},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxIssuerRedirects {
				return fmt.Errorf("stopped after %d redirects", maxIssuerRedirects)
			}
			if req.URL.Scheme != "https" {
				return fmt.Errorf("redirect to a non-https URL")
			}
			return nil
		},
	}
}

// limitedTransport refuses non-https requests and caps the size of response bodies.
type limitedTransport struct {
	next http.RoundTripper
}

func (t *limitedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme != "https" {
		return nil, fmt.Errorf("issuer requests must use https, not %q", req.URL.Scheme)
	}
	resp, err := t.next.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	resp.Body = &limitedBody{ReadCloser: resp.Body, remaining: maxIssuerResponseBytes}
	return resp, nil
}

// limitedBody fails, rather than truncates, reads past the limit.
type limitedBody struct {
	io.ReadCloser
	remaining int64
}

func (b *limitedBody) Read(p []byte) (int, error) {
	if b.remaining <= 0 {
		return 0, fmt.Errorf("response from issuer is larger than %d bytes", maxIssuerResponseBytes)
	}
	if int64(len(p)) > b.remaining {
		p = p[:b.remaining]
	}
	n, err := b.ReadCloser.Read(p)
	b.remaining -= int64(n)
	return n, err
}
