package ciba

import (
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	ext "github.com/rancher/rancher/pkg/apis/ext.cattle.io/v1"
	"github.com/rancher/rancher/pkg/oidc/provider/ciba/cibatest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

var now = time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)

func newStore() (*Store, *cibatest.Secrets) {
	f := cibatest.NewSecrets()
	s := NewStore(f, f)
	s.now = func() time.Time { return now }
	return s, f
}

func newRequest(t *testing.T, mutate func(r *Request)) (*Request, string) {
	t.Helper()
	id, secret, err := NewIDs()
	require.NoError(t, err)
	r := &Request{
		ID:              id,
		ClientID:        "client-1",
		UserID:          "u-1",
		Scopes:          []string{"read"},
		AgentName:       "agent",
		Rules:           []ext.TokenAgentRule{{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"pods"}}},
		TokenTTLSeconds: 3600,
		Status:          Pending,
		CreatedAt:       now,
		ExpiresAt:       now.Add(2 * time.Minute),
		IntervalSeconds: 5,
		SecretHash:      HashSecret(secret),
	}
	if mutate != nil {
		mutate(r)
	}
	return r, AuthReqID(id, secret)
}

func TestAuthReqID(t *testing.T) {
	id, secret, err := NewIDs()
	require.NoError(t, err)
	assert.Regexp(t, `^ciba-[a-z0-9]{16}$`, id)
	assert.Len(t, secret, 40)

	gotID, gotSecret, ok := ParseAuthReqID(AuthReqID(id, secret))
	require.True(t, ok)
	assert.Equal(t, id, gotID)
	assert.Equal(t, secret, gotSecret)

	id2, secret2, err := NewIDs()
	require.NoError(t, err)
	assert.NotEqual(t, id, id2)
	assert.NotEqual(t, secret, secret2)

	for name, bad := range map[string]string{
		"empty":         "",
		"no separator":  "ciba-abc",
		"no secret":     "ciba-abc.",
		"wrong prefix":  "token-abc.def",
		"too long":      "ciba-" + string(make([]byte, 200)) + ".x",
		"just a secret": ".secret",
	} {
		t.Run("rejects "+name, func(t *testing.T) {
			_, _, ok := ParseAuthReqID(bad)
			assert.False(t, ok)
		})
	}
}

func TestStoreCreateGet(t *testing.T) {
	store, fake := newStore()
	r, authReqID := newRequest(t, nil)
	require.NoError(t, store.Create(r))
	assert.NotEmpty(t, r.ResourceVersion)

	got, err := store.Get(r.ID)
	require.NoError(t, err)
	assert.Equal(t, r.ClientID, got.ClientID)
	assert.Equal(t, r.Rules, got.Rules)
	assert.Equal(t, Pending, got.Status)
	assert.Equal(t, now.Add(2*time.Minute), got.ExpiresAt)

	// The secret part of the auth_req_id is not stored, only its hash.
	_, secret, _ := ParseAuthReqID(authReqID)
	for _, s := range fake.Items {
		for _, v := range s.Data {
			assert.NotContains(t, string(v), secret)
		}
	}
	assert.True(t, got.SecretMatches(secret))
	assert.False(t, got.SecretMatches(secret+"x"))
	assert.False(t, got.SecretMatches(""))

	s := fake.Items[Namespace+"/"+r.ID]
	assert.Equal(t, "true", s.Labels[Label])
	assert.Equal(t, "u-1", s.Labels[UserLabel])
	assert.Equal(t, "client-1", s.Labels[ClientLabel])

	_, err = store.Get("ciba-unknown")
	assert.True(t, apierrors.IsNotFound(err))

	assert.True(t, apierrors.IsAlreadyExists(store.Create(r)))
}

func TestStoreLabelsSkipInvalidValues(t *testing.T) {
	store, fake := newStore()
	r, _ := newRequest(t, func(r *Request) { r.ClientID = "not a valid label value!"; r.UserID = "" })
	require.NoError(t, store.Create(r))
	s := fake.Items[Namespace+"/"+r.ID]
	assert.NotContains(t, s.Labels, ClientLabel)
	assert.NotContains(t, s.Labels, UserLabel)
}

func TestStoreUpdate(t *testing.T) {
	t.Run("applies the mutation", func(t *testing.T) {
		store, _ := newStore()
		r, _ := newRequest(t, nil)
		require.NoError(t, store.Create(r))

		updated, err := store.Update(r.ID, func(r *Request) error {
			r.Status = Approved
			return nil
		})
		require.NoError(t, err)
		assert.Equal(t, Approved, updated.Status)
		assert.NotEqual(t, r.ResourceVersion, updated.ResourceVersion)

		got, err := store.Get(r.ID)
		require.NoError(t, err)
		assert.Equal(t, Approved, got.Status)
	})

	t.Run("retries on a conflict and the mutation sees the latest state", func(t *testing.T) {
		store, fake := newStore()
		r, _ := newRequest(t, nil)
		require.NoError(t, store.Create(r))

		// A concurrent writer changes the request between the read and the write, once.
		fake.BeforeUpdate = func(items map[string]*corev1.Secret) {
			other, err := fromSecret(items[Namespace+"/"+r.ID])
			require.NoError(t, err)
			other.LastPollAt = now
			other.IntervalSeconds = 10
			data, _ := json.Marshal(other)
			items[Namespace+"/"+r.ID].Data[dataKey] = data
			fake.Bump(items[Namespace+"/"+r.ID])
		}

		calls := 0
		updated, err := store.Update(r.ID, func(r *Request) error {
			calls++
			r.Status = Denied
			return nil
		})
		require.NoError(t, err)
		assert.Equal(t, 2, calls)
		assert.Equal(t, Denied, updated.Status)
		assert.Equal(t, 10, updated.IntervalSeconds, "the concurrent change is kept")
	})

	t.Run("a failing mutation writes nothing and is not retried", func(t *testing.T) {
		store, _ := newStore()
		r, _ := newRequest(t, nil)
		require.NoError(t, store.Create(r))

		calls := 0
		sentinel := fmt.Errorf("no")
		_, err := store.Update(r.ID, func(r *Request) error {
			calls++
			r.Status = Approved
			return sentinel
		})
		assert.ErrorIs(t, err, sentinel)
		assert.Equal(t, 1, calls)
		got, err := store.Get(r.ID)
		require.NoError(t, err)
		assert.Equal(t, Pending, got.Status)
	})

	t.Run("an unknown request", func(t *testing.T) {
		store, _ := newStore()
		_, err := store.Update("ciba-unknown", func(*Request) error { return nil })
		assert.True(t, apierrors.IsNotFound(err))
	})
}

func TestStoreConsumeIsSingleUse(t *testing.T) {
	store, _ := newStore()
	r, _ := newRequest(t, nil)
	require.NoError(t, store.Create(r))
	read, err := store.Get(r.ID)
	require.NoError(t, err)

	const callers = 20
	var wg sync.WaitGroup
	results := make(chan error, callers)
	for range callers {
		wg.Go(func() {
			results <- store.Consume(read)
		})
	}
	wg.Wait()
	close(results)

	succeeded := 0
	for err := range results {
		if err == nil {
			succeeded++
		} else {
			assert.True(t, apierrors.IsNotFound(err) || apierrors.IsConflict(err), "unexpected %v", err)
		}
	}
	assert.Equal(t, 1, succeeded, "exactly one caller may consume a request")
	_, err = store.Get(r.ID)
	assert.True(t, apierrors.IsNotFound(err))
}

func TestStoreConsumeRefusesAChangedRequest(t *testing.T) {
	store, _ := newStore()
	r, _ := newRequest(t, nil)
	require.NoError(t, store.Create(r))
	stale, err := store.Get(r.ID)
	require.NoError(t, err)

	_, err = store.Update(r.ID, func(r *Request) error { r.Status = Approved; return nil })
	require.NoError(t, err)

	err = store.Consume(stale)
	assert.True(t, apierrors.IsConflict(err), "got %v", err)
	_, err = store.Get(r.ID)
	assert.NoError(t, err, "the request must still be there")
}

func TestStorePending(t *testing.T) {
	store, _ := newStore()
	add := func(mutate func(r *Request)) *Request {
		r, _ := newRequest(t, mutate)
		require.NoError(t, store.Create(r))
		return r
	}
	mine := add(nil)
	add(func(r *Request) { r.Status = Approved })
	add(func(r *Request) { r.Status = Denied })
	add(func(r *Request) { r.ExpiresAt = now.Add(-time.Second) })
	add(func(r *Request) { r.UserID = "u-2" })
	add(func(r *Request) { r.UserID = ""; r.ClientID = "client-2" })
	add(func(r *Request) { r.ClientID = "client-2" })

	pending, err := store.PendingForUser("u-1")
	require.NoError(t, err)
	require.Len(t, pending, 2)
	ids := []string{pending[0].ID, pending[1].ID}
	assert.Contains(t, ids, mine.ID)

	for _, test := range []struct {
		client, user string
		want         int
	}{
		{"client-1", "u-1", 1},
		{"client-1", "", 2},
		{"client-2", "", 2}, // the unknown-user request and the one for u-1
		{"", "u-1", 2},
		{"", "", 4},
		{"client-9", "", 0},
	} {
		got, err := store.CountPending(test.client, test.user)
		require.NoError(t, err)
		assert.Equal(t, test.want, got, "client %q user %q", test.client, test.user)
	}
}

func TestStoreRemoveExpired(t *testing.T) {
	store, _ := newStore()
	add := func(expires time.Time) *Request {
		r, _ := newRequest(t, func(r *Request) { r.ExpiresAt = expires })
		require.NoError(t, store.Create(r))
		return r
	}
	live := add(now.Add(time.Minute))
	justExpired := add(now.Add(-retention / 2)) // kept a while, so its client learns it expired
	old := add(now.Add(-2 * retention))

	store.removeExpired()

	_, err := store.Get(live.ID)
	assert.NoError(t, err)
	_, err = store.Get(justExpired.ID)
	assert.NoError(t, err)
	_, err = store.Get(old.ID)
	assert.True(t, apierrors.IsNotFound(err))
}

func TestRequestExpired(t *testing.T) {
	r := &Request{ExpiresAt: now}
	assert.False(t, r.Expired(now.Add(-time.Nanosecond)))
	assert.True(t, r.Expired(now))
	assert.True(t, r.Expired(now.Add(time.Second)))
}
