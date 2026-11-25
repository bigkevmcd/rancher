package provider

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/rancher/rancher/pkg/auth/audit"
	"maps"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	ext "github.com/rancher/rancher/pkg/apis/ext.cattle.io/v1"
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/rancher/pkg/auth/accessor"
	exttokenstore "github.com/rancher/rancher/pkg/ext/stores/tokens"
	wrangmgmtv3 "github.com/rancher/rancher/pkg/generated/controllers/management.cattle.io/v3"
	"github.com/rancher/rancher/pkg/oidc/provider/ciba"
	oidcerror "github.com/rancher/rancher/pkg/oidc/provider/error"
	"github.com/sirupsen/logrus"
	"golang.org/x/time/rate"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
)

// Client-Initiated Backchannel Authentication (CIBA), in poll mode: an agent asks for a user's approval
// without a browser, the user approves in Rancher, and the agent collects an agent token.
const (
	grantTypeCIBA = "urn:openid:params:grant-type:ciba"

	cibaDefaultInterval     = 5
	cibaMaxInterval         = 60
	cibaSlowDownStep        = 5
	cibaMaxExpiry           = 600
	cibaDefaultExpiry       = 120
	cibaDefaultTokenTTL     = 3600
	cibaMaxBindingMessage   = 100
	cibaMaxLoginHint        = 256
	cibaMaxDecisionBody     = 1024
	cibaCleanupInterval     = 5 * time.Minute
	cibaMaxPendingPerUser   = 10
	cibaMaxPendingPerPair   = 3
	cibaMaxPendingPerClient = 200
)

// errNotApprovable is the reason an approval is refused, e.g. for another user's request.
var errNotApprovable = errors.New("request can't be approved")

// clientAuthenticator authenticates the client of a request.
type clientAuthenticator interface {
	authenticateClient(r *http.Request, recordUse bool) (*v3.OIDCClient, *oidcerror.Error)
}

// userTokenVerifier returns the login token of the user making a request.
type userTokenVerifier func(r *http.Request) (accessor.TokenAccessor, error)

type cibaHandler struct {
	store   *ciba.Store
	clients clientAuthenticator
	users   wrangmgmtv3.UserCache
	oidc    wrangmgmtv3.OIDCClientCache
	tokens  agentTokenCreator
	// verifyUser authenticates the user who approves. It only accepts login tokens.
	verifyUser userTokenVerifier
	// limiter limits the requests which cause writes or work, as a whole.
	limiter *rate.Limiter
	now     func() time.Time
}

func newCIBAHandler(store *ciba.Store, clients clientAuthenticator, users wrangmgmtv3.UserCache,
	oidc wrangmgmtv3.OIDCClientCache, tokens agentTokenCreator, verifyUser userTokenVerifier) *cibaHandler {
	return &cibaHandler{
		store:      store,
		clients:    clients,
		users:      users,
		oidc:       oidc,
		tokens:     tokens,
		verifyUser: verifyUser,
		limiter:    rate.NewLimiter(rate.Limit(20), 40),
		now:        time.Now,
	}
}

// authorizeResponse is the response to a successful backchannel authentication request.
type authorizeResponse struct {
	AuthReqID string `json:"auth_req_id"`
	ExpiresIn int64  `json:"expires_in"`
	Interval  int    `json:"interval"`
}

// authorizeEndpoint is the backchannel authentication endpoint. It starts a request for the user to
// approve. Whether the user exists is not told: a request for an unknown user looks like any other, and
// is never approved.
func (h *cibaHandler) authorizeEndpoint(w http.ResponseWriter, r *http.Request) {
	if !h.limiter.Allow() {
		oidcerror.WriteError(oidcerror.InvalidRequest, "too many requests", http.StatusTooManyRequests, w)
		return
	}
	// CIBA Core section 7.1: the parameters are form-urlencoded in the body of a POST.
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/x-www-form-urlencoded" {
		oidcerror.WriteError(oidcerror.InvalidRequest, "content type must be application/x-www-form-urlencoded", http.StatusBadRequest, w)
		return
	}
	if err := r.ParseForm(); err != nil {
		oidcerror.WriteError(oidcerror.InvalidRequest, "error parsing parameters from request", http.StatusBadRequest, w)
		return
	}
	if name := repeatedParameter(r.Form); name != "" {
		oidcerror.WriteError(oidcerror.InvalidRequest, fmt.Sprintf("%s is included more than once", name), http.StatusBadRequest, w)
		return
	}

	client, oidcErr := h.clients.authenticateClient(r, true)
	if oidcErr != nil {
		h.writeError(w, oidcErr, clientAuthStatus(oidcErr))
		return
	}

	resp, oidcErr := h.createRequest(r, client)
	if oidcErr != nil {
		// CIBA Core section 13: every error of the authentication request is 400, but invalid_client
		// (401, only when client authentication failed) and access_denied (403, which is not returned here).
		status := http.StatusBadRequest
		if oidcErr.Error == oidcerror.ServerError {
			status = http.StatusInternalServerError
		}
		h.writeError(w, oidcErr, status)
		return
	}

	writeJSON(w, resp)
}

func (h *cibaHandler) createRequest(r *http.Request, client *v3.OIDCClient) (*authorizeResponse, *oidcerror.Error) {
	config := client.Spec.Backchannel
	if config == nil || len(config.Scopes) == 0 {
		return nil, oidcerror.New(oidcerror.UnauthorizedClient, "client is not allowed to make backchannel authentication requests")
	}

	// Only login_hint is supported to name the user, and no user code, nor a signed request object, whose
	// parameters would otherwise be ignored in favour of the unsigned ones (section 7.1.1).
	for _, param := range []string{"id_token_hint", "login_hint_token", "user_code", "request"} {
		if r.PostForm.Get(param) != "" {
			return nil, oidcerror.Newf(oidcerror.InvalidRequest, "%s is not supported", param)
		}
	}
	hint := r.PostForm.Get("login_hint")
	if hint == "" || len(hint) > cibaMaxLoginHint {
		return nil, oidcerror.New(oidcerror.InvalidRequest, "missing or invalid login_hint")
	}
	if r.PostForm.Get("client_notification_token") != "" {
		return nil, oidcerror.New(oidcerror.InvalidRequest, "client_notification_token is not supported, only poll mode is")
	}

	scopes, rules, oidcErr := resolveScopes(config, r.PostForm.Get("scope"))
	if oidcErr != nil {
		return nil, oidcErr
	}

	message := r.PostForm.Get("binding_message")
	if !validBindingMessage(message) {
		return nil, oidcerror.New(oidcerror.InvalidBindingMessage, "binding_message is too long or has characters which can't be shown")
	}

	expiry := config.RequestExpirationSeconds
	if expiry <= 0 || expiry > cibaMaxExpiry {
		expiry = cibaDefaultExpiry
	}
	if requested := r.PostForm.Get("requested_expiry"); requested != "" {
		// A positive integer: no sign, no fraction.
		seconds, err := strconv.ParseUint(requested, 10, 63)
		if err != nil || seconds < 1 {
			return nil, oidcerror.New(oidcerror.InvalidRequest, "invalid requested_expiry")
		}
		// The client can ask for less time than the configured one, not more.
		expiry = min(expiry, int64(seconds))
	}

	ttl := config.TokenExpirationSeconds
	if ttl <= 0 {
		ttl = cibaDefaultTokenTTL
	}

	agent := ext.TokenAgent{Name: agentName(client), Rules: rules}
	if err := exttokenstore.ValidateAgent(exttokenstore.KindAgent, &agent); err != nil {
		logrus.Errorf("[OIDC provider] OIDC client %s has an unusable backchannel configuration: %v", client.Name, err)
		return nil, oidcerror.New(oidcerror.ServerError, "the client is not configured correctly")
	}

	userID, err := h.resolveUser(hint)
	if err != nil {
		logrus.Errorf("[OIDC provider] failed to look up user for backchannel request: %v", err)
		return nil, oidcerror.New(oidcerror.ServerError, "failed to look up the user")
	}

	audit.SetUserID(r.Context(), userID)
	if oidcErr := h.checkCaps(client.Status.ClientID, userID); oidcErr != nil {
		return nil, oidcErr
	}

	id, secret, err := ciba.NewIDs()
	if err != nil {
		return nil, oidcerror.New(oidcerror.ServerError, "failed to create request")
	}
	now := h.now()
	req := &ciba.Request{
		ID:              id,
		ClientID:        client.Status.ClientID,
		UserID:          userID,
		Scopes:          scopes,
		AgentName:       agent.Name,
		Rules:           agent.Rules,
		TokenTTLSeconds: ttl,
		BindingMessage:  message,
		Status:          ciba.Pending,
		CreatedAt:       now,
		ExpiresAt:       now.Add(time.Duration(expiry) * time.Second),
		IntervalSeconds: cibaDefaultInterval,
		SecretHash:      ciba.HashSecret(secret),
	}
	if err := h.store.Create(req); err != nil {
		logrus.Errorf("[OIDC provider] failed to store backchannel request: %v", err)
		return nil, oidcerror.New(oidcerror.ServerError, "failed to create request")
	}

	// Which user, if any, is not logged: that is for the user's own request list.
	logrus.Infof("[OIDC provider] backchannel request %s from client %s for scopes %v", id, client.Name, scopes)

	return &authorizeResponse{
		AuthReqID: ciba.AuthReqID(id, secret),
		ExpiresIn: expiry,
		Interval:  cibaDefaultInterval,
	}, nil
}

// repeatedParameter returns the name of a parameter included more than once, which RFC 6749 and CIBA
// Core section 13 make an invalid request, or the empty string if there is none.
func repeatedParameter(form url.Values) string {
	for _, name := range slices.Sorted(maps.Keys(form)) {
		if len(form[name]) > 1 {
			return name
		}
	}
	return ""
}

// agentName is the name of the agent of the client in audit records.
func agentName(client *v3.OIDCClient) string {
	if client.Spec.Backchannel != nil && client.Spec.Backchannel.AgentName != "" {
		return client.Spec.Backchannel.AgentName
	}
	return client.Name
}

// resolveScopes checks the requested scopes against the client's and returns them with the rules
// they add up to.
func resolveScopes(config *v3.OIDCClientBackchannel, requested string) ([]string, []ext.TokenAgentRule, *oidcerror.Error) {
	names := strings.Fields(requested)
	if len(names) == 0 {
		return nil, nil, oidcerror.New(oidcerror.InvalidScope, "scope is required")
	}

	var scopes []string
	var rules []ext.TokenAgentRule
	for _, name := range names {
		if slices.Contains(scopes, name) {
			continue
		}
		i := slices.IndexFunc(config.Scopes, func(s v3.OIDCClientBackchannelScope) bool { return s.Name == name })
		if i < 0 {
			return nil, nil, oidcerror.Newf(oidcerror.InvalidScope, "invalid scope: %s", name)
		}
		scopes = append(scopes, name)
		for _, rule := range config.Scopes[i].Rules {
			rules = append(rules, ext.TokenAgentRule{Verbs: rule.Verbs, APIGroups: rule.APIGroups, Resources: rule.Resources})
		}
	}
	return scopes, rules, nil
}

// validBindingMessage allows short, plain text. It is shown to the user as a reason to approve, so
// what could make it look like something else, such as control characters, is refused.
func validBindingMessage(message string) bool {
	if utf8.RuneCountInString(message) > cibaMaxBindingMessage || !utf8.ValidString(message) {
		return false
	}
	for _, r := range message {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

// resolveUser returns the ID of the user a login_hint names, which is the user's ID or username, or
// the empty string if there is no such user, or it isn't one who may approve. A username two users
// have names no one.
func (h *cibaHandler) resolveUser(hint string) (string, error) {
	users, err := h.users.List(labels.Everything())
	if err != nil {
		return "", err
	}
	var found []*v3.User
	for _, u := range users {
		if u.Name == hint || u.Username == hint {
			found = append(found, u)
		}
	}
	if len(found) != 1 {
		return "", nil
	}
	user := found[0]
	if (user.Enabled != nil && !*user.Enabled) || user.IsSystem() {
		return "", nil
	}
	return user.Name, nil
}

// checkCaps limits the requests waiting for approval, so that a client can't flood a user with
// requests, nor the store with them. The counts come from a cache, so they can be a little behind.
// A request for an unknown user, which has no userID, only counts against the client.
func (h *cibaHandler) checkCaps(clientID, userID string) *oidcerror.Error {
	type limit struct {
		client, user string
		max          int
	}
	limits := []limit{{client: clientID, max: cibaMaxPendingPerClient}}
	if userID != "" {
		limits = append(limits,
			limit{client: clientID, user: userID, max: cibaMaxPendingPerPair},
			limit{user: userID, max: cibaMaxPendingPerUser})
	}

	for _, l := range limits {
		n, err := h.store.CountPending(l.client, l.user)
		if err != nil {
			logrus.Errorf("[OIDC provider] failed to count backchannel requests: %v", err)
			return oidcerror.New(oidcerror.ServerError, "failed to create request")
		}
		if n >= l.max {
			return oidcerror.New(oidcerror.InvalidRequest, "too many pending requests")
		}
	}
	return nil
}

// cibaTokenResponse is the response to a poll for an approved request.
type cibaTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
	Scope       string `json:"scope"`
}

// handleToken serves the CIBA grant on the token endpoint, whose form is already parsed. The client
// polls it until the user has decided.
func (h *cibaHandler) handleToken(w http.ResponseWriter, r *http.Request) {
	client, oidcErr := h.clients.authenticateClient(r, false)
	if oidcErr != nil {
		h.writeError(w, oidcErr, clientAuthStatus(oidcErr))
		return
	}

	resp, oidcErr := h.poll(r, client)
	if oidcErr != nil {
		status := http.StatusBadRequest
		if oidcErr.Error == oidcerror.ServerError {
			status = http.StatusInternalServerError
		}
		h.writeError(w, oidcErr, status)
		return
	}
	writeJSON(w, resp)
}

func (h *cibaHandler) poll(r *http.Request, client *v3.OIDCClient) (*cibaTokenResponse, *oidcerror.Error) {
	invalid := oidcerror.New(oidcerror.InvalidGrant, "auth_req_id is not valid")

	if name := repeatedParameter(r.Form); name != "" {
		return nil, oidcerror.Newf(oidcerror.InvalidRequest, "%s is included more than once", name)
	}

	id, secret, ok := ciba.ParseAuthReqID(r.Form.Get("auth_req_id"))
	if !ok {
		return nil, invalid
	}

	for range 3 {
		req, err := h.store.Get(id)
		if err != nil {
			if apierrors.IsNotFound(err) {
				return nil, invalid
			}
			logrus.Errorf("[OIDC provider] failed to get backchannel request: %v", err)
			return nil, oidcerror.New(oidcerror.ServerError, "failed to look up request")
		}
		// A request is only the client's own, and only with the secret which was given with it.
		if req.ClientID != client.Status.ClientID || !req.SecretMatches(secret) {
			return nil, invalid
		}

		now := h.now()
		// An expired request is kept, and not deleted here, so that a client which polls again learns it
		// expired and not that the request is unknown. The store removes it after a grace period. The
		// client and secret were checked above, so this tells nothing to others.
		if req.Expired(now) {
			return nil, oidcerror.New(oidcerror.ExpiredToken, "the request has expired")
		}

		switch req.Status {
		case ciba.Denied:
			if err := h.store.Consume(req); err != nil && !apierrors.IsNotFound(err) && !apierrors.IsConflict(err) {
				logrus.Errorf("[OIDC provider] failed to delete denied backchannel request: %v", err)
			}
			return nil, oidcerror.New(oidcerror.AccessDenied, "the user denied the request")

		case ciba.Approved:
			resp, oidcErr, retry := h.issue(req)
			if retry {
				continue
			}
			if resp != nil {
				audit.SetUserID(r.Context(), req.UserID)
			}
			return resp, oidcErr

		default:
			return nil, h.pending(req, now)
		}
	}

	return nil, oidcerror.New(oidcerror.ServerError, "the request is busy, try again")
}

// pending answers a poll of a request which waits for the user. A client polling faster than the
// interval is told to slow down, and the interval grows, up to a limit. Only that growth is written, so
// a client which hammers the endpoint costs reads only.
func (h *cibaHandler) pending(req *ciba.Request, now time.Time) *oidcerror.Error {
	interval := time.Duration(req.IntervalSeconds) * time.Second
	if !req.LastPollAt.IsZero() && now.Sub(req.LastPollAt) < interval {
		if req.IntervalSeconds < cibaMaxInterval {
			_, err := h.store.Update(req.ID, func(r *ciba.Request) error {
				r.IntervalSeconds = min(r.IntervalSeconds+cibaSlowDownStep, cibaMaxInterval)
				return nil
			})
			if err != nil && !apierrors.IsNotFound(err) {
				logrus.Errorf("[OIDC provider] failed to update backchannel request: %v", err)
			}
		}
		return oidcerror.Newf(oidcerror.SlowDown, "poll at most every %d seconds", min(req.IntervalSeconds+cibaSlowDownStep, cibaMaxInterval))
	}

	if _, err := h.store.Update(req.ID, func(r *ciba.Request) error {
		r.LastPollAt = now
		return nil
	}); err != nil && !apierrors.IsNotFound(err) {
		logrus.Errorf("[OIDC provider] failed to update backchannel request: %v", err)
	}
	return oidcerror.New(oidcerror.AuthorizationPending, "the user has not decided yet")
}

// issue hands the token of an approved request to the client. The request is consumed first, so that
// of several polls at the same time only one gets a token; if the request changed since it was read,
// the caller reads it again.
func (h *cibaHandler) issue(req *ciba.Request) (resp *cibaTokenResponse, oidcErr *oidcerror.Error, retry bool) {
	if err := h.store.Consume(req); err != nil {
		if apierrors.IsConflict(err) {
			return nil, nil, true
		}
		if apierrors.IsNotFound(err) {
			return nil, oidcerror.New(oidcerror.InvalidGrant, "auth_req_id is not valid"), false
		}
		logrus.Errorf("[OIDC provider] failed to consume backchannel request: %v", err)
		return nil, oidcerror.New(oidcerror.ServerError, "failed to create token"), false
	}

	token, err := h.tokens.CreateAgentToken(exttokenstore.AgentTokenRequest{
		UserID:      req.UserID,
		Agent:       ext.TokenAgent{Name: req.AgentName, Rules: req.Rules},
		TTL:         req.TokenTTLSeconds * 1000,
		Description: fmt.Sprintf("Approved backchannel request %s", req.ID),
		Labels:      map[string]string{"cattle.io/backchannel-request": req.ID},
		Principal:   req.ApproverPrincipal,
	})
	if err != nil {
		if apierrors.IsBadRequest(err) {
			// The user was disabled or removed since approving.
			logrus.Warnf("[OIDC provider] backchannel request %s can't issue a token: %v", req.ID, err)
			return nil, oidcerror.New(oidcerror.AccessDenied, "the request can't be granted"), false
		}
		logrus.Errorf("[OIDC provider] backchannel request %s: failed to create agent token: %v", req.ID, err)
		return nil, oidcerror.New(oidcerror.ServerError, "failed to create token"), false
	}

	// The token value is never logged.
	logrus.Infof("[OIDC provider] backchannel request %s issued agent token %s for user %s", req.ID, token.Name, req.UserID)

	return &cibaTokenResponse{
		AccessToken: token.Status.BearerToken,
		TokenType:   bearerTokenType,
		ExpiresIn:   token.Spec.TTL / 1000,
		Scope:       strings.Join(req.Scopes, " "),
	}, nil, false
}

// requestView is what a user is shown of a request to approve.
type requestView struct {
	ID             string               `json:"id"`
	Client         string               `json:"client"`
	Description    string               `json:"description,omitempty"`
	Agent          string               `json:"agent"`
	Scopes         []string             `json:"scopes"`
	Rules          []ext.TokenAgentRule `json:"rules"`
	BindingMessage string               `json:"bindingMessage,omitempty"`
	CreatedAt      time.Time            `json:"createdAt"`
	ExpiresAt      time.Time            `json:"expiresAt"`
	TokenTTL       int64                `json:"tokenTTLSeconds"`
}

// listEndpoint lists the requests waiting for the user who asks.
func (h *cibaHandler) listEndpoint(w http.ResponseWriter, r *http.Request) {
	userID, _, ok := h.authenticateUser(w, r)
	if !ok {
		return
	}
	pending, err := h.store.PendingForUser(userID)
	if err != nil {
		logrus.Errorf("[OIDC provider] failed to list backchannel requests: %v", err)
		oidcerror.WriteError(oidcerror.ServerError, "failed to list requests", http.StatusInternalServerError, w)
		return
	}

	views := make([]requestView, 0, len(pending))
	for _, req := range pending {
		views = append(views, h.view(req))
	}
	writeJSON(w, views)
}

func (h *cibaHandler) view(req *ciba.Request) requestView {
	v := requestView{
		ID:             req.ID,
		Client:         req.ClientID,
		Agent:          req.AgentName,
		Scopes:         req.Scopes,
		Rules:          req.Rules,
		BindingMessage: req.BindingMessage,
		CreatedAt:      req.CreatedAt,
		ExpiresAt:      req.ExpiresAt,
		TokenTTL:       req.TokenTTLSeconds,
	}
	// Show the name the administrator gave the client, if it still exists.
	if clients, err := h.oidc.List(labels.Everything()); err == nil {
		for _, c := range clients {
			if c.Status.ClientID == req.ClientID {
				v.Client = c.Name
				v.Description = c.Spec.Description
				break
			}
		}
	}
	return v
}

type decision struct {
	Decision string `json:"decision"`
}

// decideEndpoint approves or denies a request. Only the user the request asks can decide, and only
// while it waits. Anything else is "not found", so requests of other users aren't revealed.
func (h *cibaHandler) decideEndpoint(w http.ResponseWriter, r *http.Request) {
	userID, principal, ok := h.authenticateUser(w, r)
	if !ok {
		return
	}

	// A JSON body can't be sent by a form of another site, which keeps this from being forged.
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		oidcerror.WriteError(oidcerror.InvalidRequest, "content type must be application/json", http.StatusUnsupportedMediaType, w)
		return
	}
	var d decision
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, cibaMaxDecisionBody)).Decode(&d); err != nil {
		oidcerror.WriteError(oidcerror.InvalidRequest, "invalid body", http.StatusBadRequest, w)
		return
	}
	var status ciba.Status
	switch d.Decision {
	case "approve":
		status = ciba.Approved
	case "deny":
		status = ciba.Denied
	default:
		oidcerror.WriteError(oidcerror.InvalidRequest, `decision must be "approve" or "deny"`, http.StatusBadRequest, w)
		return
	}

	id := r.PathValue("id")
	now := h.now()
	_, err := h.store.Update(id, func(req *ciba.Request) error {
		if req.UserID == "" || req.UserID != userID || req.Status != ciba.Pending || req.Expired(now) {
			return errNotApprovable
		}
		req.Status = status
		if status == ciba.Approved {
			req.ApproverPrincipal = &principal
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, errNotApprovable) || apierrors.IsNotFound(err) {
			oidcerror.WriteError(oidcerror.InvalidRequest, "request not found", http.StatusNotFound, w)
			return
		}
		logrus.Errorf("[OIDC provider] failed to record decision on backchannel request: %v", err)
		oidcerror.WriteError(oidcerror.ServerError, "failed to record the decision", http.StatusInternalServerError, w)
		return
	}

	logrus.Infof("[OIDC provider] user %s decided %q on backchannel request %s", userID, d.Decision, id)
	w.WriteHeader(http.StatusNoContent)
}

// authenticateUser returns the user making the request, who must present a login token in the
// Authorization header. Cookies are not accepted, which would let another site act for the user, and
// neither are API keys or agent tokens: an agent can't approve its own requests.
func (h *cibaHandler) authenticateUser(w http.ResponseWriter, r *http.Request) (string, ext.TokenPrincipal, bool) {
	auth := r.Header.Get("Authorization")
	if len(auth) < 7 || !strings.EqualFold(auth[:7], "bearer ") {
		oidcerror.WriteError(oidcerror.InvalidRequest, "must authenticate", http.StatusUnauthorized, w)
		return "", ext.TokenPrincipal{}, false
	}
	token, err := h.verifyUser(r)
	if err != nil {
		logrus.Debugf("[OIDC provider] backchannel approval authentication failed: %v", err)
		oidcerror.WriteError(oidcerror.InvalidRequest, "must authenticate", http.StatusUnauthorized, w)
		return "", ext.TokenPrincipal{}, false
	}
	audit.SetUserID(r.Context(), token.GetUserID())
	p := token.GetUserPrincipal()
	return token.GetUserID(), ext.TokenPrincipal{
		Name:          p.Name,
		DisplayName:   p.DisplayName,
		LoginName:     p.LoginName,
		PrincipalType: p.PrincipalType,
		Provider:      p.Provider,
	}, true
}

// clientAuthStatus is the HTTP status of a failure to authenticate the client: 401 for failed
// authentication (invalid_client), and not for anything else, such as a failure of the server.
func clientAuthStatus(oidcErr *oidcerror.Error) int {
	switch oidcErr.Error {
	case oidcerror.InvalidClient:
		return http.StatusUnauthorized
	case oidcerror.ServerError:
		return http.StatusInternalServerError
	}
	return http.StatusBadRequest
}

func (h *cibaHandler) writeError(w http.ResponseWriter, oidcErr *oidcerror.Error, status int) {
	logrus.Debugf("[OIDC provider] backchannel request failed: %s", oidcErr.ToString())
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Basic realm="rancher"`)
	}
	oidcErr.Write(status, w)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		logrus.Errorf("[OIDC provider] failed to encode response: %v", err)
	}
}
