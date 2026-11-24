// Package cibatest has fakes for testing code which uses the backchannel request store.
package cibatest

import (
	"fmt"
	"strconv"
	"sync"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var secretsResource = schema.GroupResource{Resource: "secrets"}

// Secrets is an in-memory secret API with resource versions, as the API server has them.
type Secrets struct {
	mu    sync.Mutex
	Items map[string]*corev1.Secret
	rv    int
	// BeforeUpdate runs, once, before the next update is applied.
	BeforeUpdate func(items map[string]*corev1.Secret)
}

// NewSecrets returns an empty secret API.
func NewSecrets() *Secrets { return &Secrets{Items: map[string]*corev1.Secret{}} }

// Bump gives the secret a new resource version, as a write does.
func (f *Secrets) Bump(s *corev1.Secret) {
	f.rv++
	s.ResourceVersion = strconv.Itoa(f.rv)
}

func (f *Secrets) Get(ns, name string, _ metav1.GetOptions) (*corev1.Secret, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.Items[ns+"/"+name]
	if !ok {
		return nil, apierrors.NewNotFound(secretsResource, name)
	}
	return s.DeepCopy(), nil
}

func (f *Secrets) Create(s *corev1.Secret) (*corev1.Secret, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := s.Namespace + "/" + s.Name
	if _, ok := f.Items[key]; ok {
		return nil, apierrors.NewAlreadyExists(secretsResource, s.Name)
	}
	s = s.DeepCopy()
	f.Bump(s)
	f.Items[key] = s
	return s.DeepCopy(), nil
}

func (f *Secrets) Update(s *corev1.Secret) (*corev1.Secret, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.BeforeUpdate != nil {
		hook := f.BeforeUpdate
		f.BeforeUpdate = nil
		hook(f.Items)
	}
	key := s.Namespace + "/" + s.Name
	stored, ok := f.Items[key]
	if !ok {
		return nil, apierrors.NewNotFound(secretsResource, s.Name)
	}
	if s.ResourceVersion != stored.ResourceVersion {
		return nil, apierrors.NewConflict(secretsResource, s.Name, fmt.Errorf("stale"))
	}
	s = s.DeepCopy()
	f.Bump(s)
	f.Items[key] = s
	return s.DeepCopy(), nil
}

func (f *Secrets) Delete(ns, name string, opts *metav1.DeleteOptions) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := ns + "/" + name
	stored, ok := f.Items[key]
	if !ok {
		return apierrors.NewNotFound(secretsResource, name)
	}
	if opts != nil && opts.Preconditions != nil && opts.Preconditions.ResourceVersion != nil &&
		*opts.Preconditions.ResourceVersion != stored.ResourceVersion {
		return apierrors.NewConflict(secretsResource, name, fmt.Errorf("precondition failed"))
	}
	delete(f.Items, key)
	return nil
}

func (f *Secrets) List(ns string, selector labels.Selector) ([]*corev1.Secret, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*corev1.Secret
	for _, s := range f.Items {
		if s.Namespace == ns && selector.Matches(labels.Set(s.Labels)) {
			out = append(out, s.DeepCopy())
		}
	}
	return out, nil
}
