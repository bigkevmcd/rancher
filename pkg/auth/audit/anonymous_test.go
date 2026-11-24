package audit

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	auditlogv1 "github.com/rancher/rancher/pkg/apis/auditlog.cattle.io/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Handlers outside Steve's authentication are audited too: without a user on the request, the entry
// is anonymous until the handler names the user it authenticated.
func TestAnonymousAuditedHandlers(t *testing.T) {
	run := func(t *testing.T, handler http.HandlerFunc, level auditlogv1.Level) string {
		writer, out := newTestAuditWriter(level)
		h := Anonymous(NewAuditLogMiddleware(writer)(handler))
		req := httptest.NewRequest(http.MethodPost, "/oidc/ciba/requests/abc", nil)
		h.ServeHTTP(httptest.NewRecorder(), req)
		return out.String()
	}

	t.Run("unauthenticated request is logged as anonymous", func(t *testing.T) {
		log := run(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusUnauthorized) }, auditlogv1.LevelNull)
		require.NotEmpty(t, log)
		assert.Contains(t, log, "/oidc/ciba/requests/abc")
		assert.Contains(t, log, "system:anonymous")
		assert.Contains(t, log, "401")
	})

	t.Run("handler names the user", func(t *testing.T) {
		log := run(t, func(w http.ResponseWriter, r *http.Request) {
			SetUserID(r.Context(), "u-approver")
			w.WriteHeader(http.StatusNoContent)
		}, auditlogv1.LevelNull)
		assert.Contains(t, log, "u-approver")
		assert.False(t, strings.Contains(log, "system:anonymous"))
	})

	t.Run("an authenticated user is kept", func(t *testing.T) {
		writer, out := newTestAuditWriter(auditlogv1.LevelNull)
		h := Anonymous(NewAuditLogMiddleware(writer)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})))
		h.ServeHTTP(httptest.NewRecorder(), newTestRequest(http.MethodGet, "/x", nil))
		assert.Contains(t, out.String(), "test-user")
	})

	t.Run("no audit logging does nothing", func(t *testing.T) {
		assert.NotPanics(t, func() { SetUserID(httptest.NewRequest("GET", "/", nil).Context(), "u") })
	})

	t.Run("auth_req_id in a response is redacted", func(t *testing.T) {
		log := run(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"auth_req_id":"abc.secret","access_token":"t","expires_in":5}`))
		}, auditlogv1.LevelRequestResponse)
		assert.NotContains(t, log, "abc.secret")
		assert.NotContains(t, log, `"t"`)
	})
}
