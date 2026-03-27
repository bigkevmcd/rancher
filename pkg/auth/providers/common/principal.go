package common

import (
	"fmt"
	"strings"
)

// SplitPrincipalID parses a principal ID to get the provider, external id and
// type.
//
// PrincipalID should look like looks like github_[user|org|team]://12345
//
// returns provider, principalType, externalID, error
func SplitPrincipalID(principalID string) (string, string, string, error) {
	parts := strings.SplitN(principalID, ":", 2)
	if len(parts) != 2 {
		return "", "", "", fmt.Errorf("invalid principal id %v", principalID)
	}
	externalID := strings.TrimPrefix(parts[1], "//")
	parts = strings.SplitN(parts[0], "_", 2)
	if len(parts) != 2 {
		return "", "", "", fmt.Errorf("invalid principal id %v", principalID)
	}

	principalType := parts[1]
	return parts[0], principalType, externalID, nil
}
