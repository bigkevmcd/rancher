package common

import (
	"strings"
	"testing"
)

func TestSplitPrincipalID(t *testing.T) {
	tests := []struct {
		name              string
		principalID       string
		wantProviderType  string
		wantExternalID    string
		wantPrincipalType string
		wantErr           bool
	}{
		{
			name:              "valid user principal id",
			principalID:       "github_user://9253000",
			wantProviderType:  "github",
			wantExternalID:    "9253000",
			wantPrincipalType: "user",
		},
		{
			name:              "valid team principal id",
			principalID:       "github_team://9933605",
			wantProviderType:  "github",
			wantExternalID:    "9933605",
			wantPrincipalType: "team",
		},
		{
			name:              "valid principal id without double slash",
			principalID:       "github_org:9343010",
			wantProviderType:  "github",
			wantExternalID:    "9343010",
			wantPrincipalType: "org",
		},
		{
			name:        "invalid principal id missing colon",
			principalID: "github_user//9253000",
			wantErr:     true,
		},
		{
			name:        "invalid principal id missing underscore",
			principalID: "github://9253000",
			wantErr:     true,
		},
		{
			name:              "empty external id is accepted",
			principalID:       "github_user:",
			wantProviderType:  "github",
			wantExternalID:    "",
			wantPrincipalType: "user",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotProviderType, gotPrincipalType, gotExternalID, err := SplitPrincipalID(tt.principalID)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for principalID %q, got nil", tt.principalID)
				}
				if !strings.Contains(err.Error(), "invalid principal id") {
					t.Fatalf("expected invalid principal id error, got %v", err)
				}
				return
			}

			if err != nil {
				t.Fatalf("expected no error for principalID %q, got %v", tt.principalID, err)
			}

			if gotProviderType != tt.wantProviderType {
				t.Fatalf("expected providerType %q, got %q", tt.wantProviderType, gotProviderType)
			}

			if gotExternalID != tt.wantExternalID {
				t.Fatalf("expected externalID %q, got %q", tt.wantExternalID, gotExternalID)
			}

			if gotPrincipalType != tt.wantPrincipalType {
				t.Fatalf("expected principalType %q, got %q", tt.wantPrincipalType, gotPrincipalType)
			}
		})
	}
}
