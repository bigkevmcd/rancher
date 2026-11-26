package provider

import (
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	wrangmgmtv3 "github.com/rancher/rancher/pkg/generated/controllers/management.cattle.io/v3"
	"k8s.io/apimachinery/pkg/labels"
)

// userResolver turns the login_hint of a backchannel request into the user asked to approve it. CIBA
// leaves the meaning of the hint to the server, so this is where a different one, such as an email address
// or a structured hint, would go.
type userResolver interface {
	// ResolveUser returns the ID of the user the hint names. It returns the empty string, and no error,
	// when the hint names no user who may approve: the caller must not tell the client, so that it can't find
	// out which users exist. An error means the lookup itself failed.
	ResolveUser(hint string) (string, error)
}

// userIDOrNameResolver is the default userResolver. The hint is a user's ID or username, matched exactly.
type userIDOrNameResolver struct {
	users wrangmgmtv3.UserCache
}

// newUserResolver returns the default resolver, which reads users from the cache.
func newUserResolver(users wrangmgmtv3.UserCache) userResolver {
	return &userIDOrNameResolver{users: users}
}

// ResolveUser returns the ID of the user a login_hint names, which is the user's ID or username, or
// the empty string if there is no such user, or it isn't one who may approve. A username two users
// have names no one.
func (r *userIDOrNameResolver) ResolveUser(hint string) (string, error) {
	users, err := r.users.List(labels.Everything())
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
