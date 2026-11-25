// Package ciba stores the pending requests of Client-Initiated Backchannel Authentication.
package ciba

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	ext "github.com/rancher/rancher/pkg/apis/ext.cattle.io/v1"
	"github.com/rancher/wrangler/v3/pkg/randomtoken"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/util/retry"
)

const (
	// Namespace holds the requests, one Secret each.
	Namespace = "cattle-oidc-ciba"

	// Label marks the Secrets of requests.
	Label = "cattle.io/oidc-ciba"
	// UserLabel holds the ID of the user the request asks, if there is one.
	UserLabel = "cattle.io/oidc-ciba-user"
	// ClientLabel holds the client ID of the request.
	ClientLabel = "cattle.io/oidc-ciba-client"

	dataKey = "request"

	// retention is how long an expired request is kept, so that its client learns it expired.
	retention = time.Minute
)

// Status is the state of a request.
type Status string

const (
	// Pending requests wait for the user.
	Pending Status = "pending"
	// Approved requests are waiting for the client to collect the token.
	Approved Status = "approved"
	// Denied requests were refused by the user.
	Denied Status = "denied"
)

// Request is a backchannel authentication request.
type Request struct {
	// ID identifies the request, and is not secret. It is the name of the Secret. The user
	// approving the request uses it.
	ID string `json:"-"`
	// ResourceVersion is the version the request was read at.
	ResourceVersion string `json:"-"`

	// ClientID is the client which made the request.
	ClientID string `json:"clientID"`
	// UserID is the user asked to approve. It is empty when the user the client named isn't known,
	// so that a client can't tell known from unknown users. Such requests are never approved.
	UserID string `json:"userID,omitempty"`
	// Scopes are the scopes requested.
	Scopes []string `json:"scopes"`
	// AgentName and Rules are what the token will be, if approved. They are copied from the client
	// when the request is made, so the user approves what they were shown.
	AgentName string               `json:"agentName"`
	Rules     []ext.TokenAgentRule `json:"rules"`
	// TokenTTLSeconds is the lifetime of the token.
	TokenTTLSeconds int64 `json:"tokenTTLSeconds"`
	// ApproverPrincipal is the principal of the user's login token when they approved. The token
	// is issued with it, so that it has the permissions the user has through their auth provider,
	// such as those of their groups. It is empty until the request is approved.
	ApproverPrincipal *ext.TokenPrincipal `json:"approverPrincipal,omitempty"`
	// BindingMessage is shown to the user to tie the approval to what the agent is doing.
	BindingMessage string `json:"bindingMessage,omitempty"`

	Status    Status    `json:"status"`
	CreatedAt time.Time `json:"createdAt"`
	ExpiresAt time.Time `json:"expiresAt"`
	// IntervalSeconds is the least time between polls of the client.
	IntervalSeconds int `json:"intervalSeconds"`
	// LastPollAt is when the client polled last.
	LastPollAt time.Time `json:"lastPollAt"`
	// SecretHash is the hash of the secret part of the auth_req_id, which is not stored.
	SecretHash string `json:"secretHash"`
}

// Expired reports whether the request can't be approved or collected anymore.
func (r *Request) Expired(now time.Time) bool {
	return !now.Before(r.ExpiresAt)
}

// NewIDs generates the ID of a request and the secret which, with the ID, makes up its auth_req_id.
func NewIDs() (id, secret string, err error) {
	a, err := randomtoken.Generate()
	if err != nil {
		return "", "", err
	}
	b, err := randomtoken.Generate()
	if err != nil {
		return "", "", err
	}
	return "ciba-" + a[:16], b[:40], nil
}

// AuthReqID is the identifier given to the client, which it polls with.
func AuthReqID(id, secret string) string {
	return id + "." + secret
}

// ParseAuthReqID splits an auth_req_id into the request ID and the secret.
func ParseAuthReqID(authReqID string) (id, secret string, ok bool) {
	id, secret, ok = strings.Cut(authReqID, ".")
	if !ok || !strings.HasPrefix(id, "ciba-") || secret == "" || len(authReqID) > 128 {
		return "", "", false
	}
	return id, secret, true
}

// HashSecret returns what is stored of the secret.
func HashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// SecretMatches reports whether the secret is that of the request, in constant time.
func (r *Request) SecretMatches(secret string) bool {
	return subtle.ConstantTimeCompare([]byte(HashSecret(secret)), []byte(r.SecretHash)) == 1
}

// secretAPI is what the store uses of the Secret client.
type secretAPI interface {
	Get(namespace, name string, options metav1.GetOptions) (*corev1.Secret, error)
	Create(*corev1.Secret) (*corev1.Secret, error)
	Update(*corev1.Secret) (*corev1.Secret, error)
	Delete(namespace, name string, options *metav1.DeleteOptions) error
}

// secretLister is what the store uses of the Secret cache.
type secretLister interface {
	List(namespace string, selector labels.Selector) ([]*corev1.Secret, error)
}

// Store keeps requests in Secrets, so that all replicas see them and they survive restarts.
type Store struct {
	client secretAPI
	cache  secretLister
	now    func() time.Time

	mu sync.Mutex
}

// NewStore returns a store. The namespace is expected to exist.
func NewStore(client secretAPI, cache secretLister) *Store {
	return NewStoreWithClock(client, cache, time.Now)
}

// NewStoreWithClock returns a store which tells the time by the clock, for tests.
func NewStoreWithClock(client secretAPI, cache secretLister, now func() time.Time) *Store {
	return &Store{client: client, cache: cache, now: now}
}

// Create stores a new request, which must have its ID and secret hash set.
func (s *Store) Create(r *Request) error {
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	secret := &corev1.Secret{
		Name:      r.ID,
		Namespace: Namespace,
		Labels:    map[string]string{Label: "true"},
		Data:      map[string][]byte{dataKey: data},
	}
	// Labels let requests be counted and listed. A value which isn't valid as a label is skipped, it
	// then isn't counted.
	for key, value := range map[string]string{UserLabel: r.UserID, ClientLabel: r.ClientID} {
		if value != "" && len(validation.IsValidLabelValue(value)) == 0 {
			secret.Labels[key] = value
		}
	}
	created, err := s.client.Create(secret)
	if err != nil {
		return err
	}
	r.ResourceVersion = created.ResourceVersion
	return nil
}

// Get returns the request read from the API server, not the cache, so a poll sees the user's decision
// at once. It returns a NotFound error for an unknown request.
func (s *Store) Get(id string) (*Request, error) {
	secret, err := s.client.Get(Namespace, id, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return fromSecret(secret)
}

func fromSecret(secret *corev1.Secret) (*Request, error) {
	var r Request
	if err := json.Unmarshal(secret.Data[dataKey], &r); err != nil {
		return nil, fmt.Errorf("invalid request %s: %w", secret.Name, err)
	}
	r.ID = secret.Name
	r.ResourceVersion = secret.ResourceVersion
	return &r, nil
}

// Update changes the request, reading it again and retrying if it was changed in between. The
// mutation sees the current state, and may return an error to stop.
func (s *Store) Update(id string, mutate func(*Request) error) (*Request, error) {
	var result *Request
	err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		secret, err := s.client.Get(Namespace, id, metav1.GetOptions{})
		if err != nil {
			return err
		}
		r, err := fromSecret(secret)
		if err != nil {
			return err
		}
		if err := mutate(r); err != nil {
			return &mutationError{err}
		}
		data, err := json.Marshal(r)
		if err != nil {
			return err
		}
		secret = secret.DeepCopy()
		secret.Data[dataKey] = data
		updated, err := s.client.Update(secret)
		if err != nil {
			return err
		}
		r.ResourceVersion = updated.ResourceVersion
		result = r
		return nil
	})
	if me, ok := err.(*mutationError); ok {
		return nil, me.err
	}
	return result, err
}

// mutationError carries the error of a mutation past the retry.
type mutationError struct{ err error }

func (e *mutationError) Error() string { return e.err.Error() }

// Consume deletes the request, if it is still as read. Of several callers consuming the same
// request exactly one succeeds, and the others get a Conflict or NotFound error.
func (s *Store) Consume(r *Request) error {
	rv := r.ResourceVersion
	return s.client.Delete(Namespace, r.ID, &metav1.DeleteOptions{
		Preconditions: &metav1.Preconditions{ResourceVersion: &rv},
	})
}

// Delete removes the request, if it exists.
func (s *Store) Delete(id string) error {
	err := s.client.Delete(Namespace, id, &metav1.DeleteOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	return err
}

// list returns the requests with the labels, from the cache.
func (s *Store) list(set labels.Set) ([]*Request, error) {
	secrets, err := s.cache.List(Namespace, labels.SelectorFromSet(set))
	if err != nil {
		return nil, err
	}
	requests := make([]*Request, 0, len(secrets))
	for _, secret := range secrets {
		r, err := fromSecret(secret)
		if err != nil {
			logrus.Warnf("[OIDC provider] ignoring %v", err)
			continue
		}
		requests = append(requests, r)
	}
	return requests, nil
}

// PendingForUser returns the requests the user can still approve.
func (s *Store) PendingForUser(userID string) ([]*Request, error) {
	requests, err := s.list(labels.Set{Label: "true", UserLabel: userID})
	if err != nil {
		return nil, err
	}
	now := s.now()
	pending := requests[:0]
	for _, r := range requests {
		if r.Status == Pending && !r.Expired(now) {
			pending = append(pending, r)
		}
	}
	return pending, nil
}

// CountPending returns how many requests wait for approval, of the client and, if given, of the user.
// It is read from the cache, so recent requests may be missing.
func (s *Store) CountPending(clientID, userID string) (int, error) {
	set := labels.Set{Label: "true"}
	if clientID != "" {
		set[ClientLabel] = clientID
	}
	if userID != "" {
		set[UserLabel] = userID
	}
	requests, err := s.list(set)
	if err != nil {
		return 0, err
	}
	now := s.now()
	count := 0
	for _, r := range requests {
		if r.Status == Pending && !r.Expired(now) {
			count++
		}
	}
	return count, nil
}

// Cleanup removes expired requests until the context is done. A tick is skipped while enabled returns false.
func (s *Store) Cleanup(ctx context.Context, every time.Duration, enabled func() bool) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if enabled() {
				s.removeExpired()
			}
		}
	}
}

func (s *Store) removeExpired() {
	s.mu.Lock()
	defer s.mu.Unlock()

	requests, err := s.list(labels.Set{Label: "true"})
	if err != nil {
		logrus.Errorf("[OIDC provider] failed to list backchannel requests: %v", err)
		return
	}
	cutoff := s.now().Add(-retention)
	for _, r := range requests {
		if r.ExpiresAt.Before(cutoff) {
			if err := s.Delete(r.ID); err != nil {
				logrus.Errorf("[OIDC provider] failed to delete expired backchannel request: %v", err)
			}
		}
	}
}
