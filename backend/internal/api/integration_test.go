package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/ruslanrwx/secrets/backend/internal/api"
	"github.com/ruslanrwx/secrets/backend/internal/auth"
	"github.com/ruslanrwx/secrets/backend/internal/config"
	"github.com/ruslanrwx/secrets/backend/internal/cryptoutil"
	"github.com/ruslanrwx/secrets/backend/internal/store"
)

const (
	testMasterKey = "integration-test-master-key"
	testJWTSecret = "integration-test-jwt-secret"
	adminPassword = "admin-password-1234"
)

// harness wraps a live server backed by a real PostgreSQL database.
type harness struct {
	t      *testing.T
	server *httptest.Server
	store  *store.Store
}

// newHarness truncates the database and starts a fresh server against it.
// It skips the whole test when TEST_DATABASE_URL is not configured.
func newHarness(t *testing.T) *harness {
	t.Helper()

	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL is not set; skipping integration tests")
	}

	t.Setenv("DATABASE_URL", dsn)
	t.Setenv("MASTER_KEY", testMasterKey)
	t.Setenv("JWT_SECRET", testJWTSecret)

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx := context.Background()

	st, err := store.Open(ctx, cfg.DatabaseURL, log)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := st.Reset(ctx); err != nil {
		t.Fatalf("reset: %v", err)
	}

	keys, err := cryptoutil.NewKeyring(cfg.MasterKey)
	if err != nil {
		t.Fatalf("keyring: %v", err)
	}

	srv := httptest.NewServer(api.New(cfg, st, keys, log, "test").Routes(nil))

	t.Cleanup(func() {
		srv.Close()
		st.Close()
	})

	return &harness{t: t, server: srv, store: st}
}

// do issues a request and decodes the JSON body into out (which may be nil).
func (h *harness) do(method, path, token string, body, out any) int {
	h.t.Helper()

	var payload io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			h.t.Fatalf("encode body: %v", err)
		}
		payload = bytes.NewReader(encoded)
	}

	req, err := http.NewRequest(method, h.server.URL+path, payload)
	if err != nil {
		h.t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := h.server.Client().Do(req)
	if err != nil {
		h.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			h.t.Fatalf("%s %s: decode %q: %v", method, path, raw, err)
		}
	}

	return resp.StatusCode
}

// mustDo fails the test unless the response carries the expected status.
func (h *harness) mustDo(method, path, token string, body, out any, want int) {
	h.t.Helper()

	var raw json.RawMessage
	if out == nil {
		out = &raw
	}

	if got := h.do(method, path, token, body, out); got != want {
		h.t.Fatalf("%s %s: got status %d want %d (body: %s)", method, path, got, want, mustJSON(out))
	}
}

func mustJSON(v any) string {
	encoded, _ := json.Marshal(v)

	return string(encoded)
}

// setupAdmin runs the install wizard and returns the admin's session token.
func (h *harness) setupAdmin() string {
	h.t.Helper()

	var out struct {
		Token string `json:"token"`
	}
	h.mustDo(http.MethodPost, "/api/v1/setup", "", map[string]any{
		"instanceName": "test",
		"username":     "admin",
		"password":     adminPassword,
	}, &out, http.StatusCreated)

	if out.Token == "" {
		h.t.Fatal("setup returned no session token")
	}

	return out.Token
}

// createUser adds a user and returns their id.
func (h *harness) createUser(adminToken, username, password string, perms []string) string {
	h.t.Helper()

	var out struct {
		ID string `json:"id"`
	}
	h.mustDo(http.MethodPost, "/api/v1/users", adminToken, map[string]any{
		"username":    username,
		"password":    password,
		"permissions": perms,
	}, &out, http.StatusCreated)

	return out.ID
}

// login signs in and returns the session token plus the forced-change flag.
func (h *harness) login(username, password string) (string, bool) {
	h.t.Helper()

	var out struct {
		Token              string `json:"token"`
		MustChangePassword bool   `json:"mustChangePassword"`
	}
	h.mustDo(http.MethodPost, "/api/v1/auth/login", "", map[string]any{
		"username": username, "password": password,
	}, &out, http.StatusOK)

	return out.Token, out.MustChangePassword
}

// onboard creates a user, signs them in and completes the forced password change.
func (h *harness) onboard(adminToken, username string, perms []string) (id, token string) {
	h.t.Helper()

	initial := username + "-initial-pw-1"
	final := username + "-final-pw-1"

	id = h.createUser(adminToken, username, initial, perms)

	token, mustChange := h.login(username, initial)
	if !mustChange {
		h.t.Fatalf("%s was not asked to change their password", username)
	}

	h.mustDo(http.MethodPost, "/api/v1/auth/change-password", token, map[string]any{
		"currentPassword": initial, "newPassword": final,
	}, nil, http.StatusOK)

	token, mustChange = h.login(username, final)
	if mustChange {
		h.t.Fatalf("%s is still being asked to change their password", username)
	}

	return id, token
}

func TestSetupWizardRunsExactlyOnce(t *testing.T) {
	h := newHarness(t)

	var status struct {
		Initialized bool `json:"initialized"`
	}
	h.mustDo(http.MethodGet, "/api/v1/setup/status", "", nil, &status, http.StatusOK)
	if status.Initialized {
		t.Fatal("a fresh database reports itself as already initialized")
	}

	h.setupAdmin()

	h.mustDo(http.MethodGet, "/api/v1/setup/status", "", nil, &status, http.StatusOK)
	if !status.Initialized {
		t.Fatal("setup did not mark the installation as initialized")
	}

	// A second attempt must not be able to mint another administrator.
	h.mustDo(http.MethodPost, "/api/v1/setup", "", map[string]any{
		"username": "intruder", "password": "intruder-password-1234",
	}, nil, http.StatusConflict)
}

func TestSetupRejectsWeakPassword(t *testing.T) {
	h := newHarness(t)

	h.mustDo(http.MethodPost, "/api/v1/setup", "", map[string]any{
		"username": "admin", "password": "short",
	}, nil, http.StatusBadRequest)
}

func TestNewUserMustChangePasswordBeforeUsingTheApp(t *testing.T) {
	h := newHarness(t)
	adminToken := h.setupAdmin()

	h.createUser(adminToken, "bob", "bob-initial-pw-1", []string{auth.PermSecretsRead})

	token, mustChange := h.login("bob", "bob-initial-pw-1")
	if !mustChange {
		t.Fatal("a new user was not flagged for a password change")
	}

	// Everything except /auth/me and /auth/change-password is closed until then.
	h.mustDo(http.MethodGet, "/api/v1/secrets", token, nil, nil, http.StatusForbidden)
	h.mustDo(http.MethodGet, "/api/v1/auth/me", token, nil, nil, http.StatusOK)

	h.mustDo(http.MethodPost, "/api/v1/auth/change-password", token, map[string]any{
		"currentPassword": "bob-initial-pw-1", "newPassword": "bob-final-pw-1",
	}, nil, http.StatusOK)

	token, _ = h.login("bob", "bob-final-pw-1")
	h.mustDo(http.MethodGet, "/api/v1/secrets", token, nil, nil, http.StatusOK)
}

func TestLoginRejectsBadCredentials(t *testing.T) {
	h := newHarness(t)
	h.setupAdmin()

	h.mustDo(http.MethodPost, "/api/v1/auth/login", "", map[string]any{
		"username": "admin", "password": "not-the-password",
	}, nil, http.StatusUnauthorized)

	h.mustDo(http.MethodPost, "/api/v1/auth/login", "", map[string]any{
		"username": "ghost", "password": "not-the-password",
	}, nil, http.StatusUnauthorized)
}

func TestSecretRoundTripAndStorageIsEncrypted(t *testing.T) {
	h := newHarness(t)
	adminToken := h.setupAdmin()

	const value = "s3cret-database-password"

	var created struct {
		ID string `json:"id"`
	}
	h.mustDo(http.MethodPost, "/api/v1/secrets", adminToken, map[string]any{
		"name": "prod db", "kind": "password", "value": value,
	}, &created, http.StatusCreated)

	var revealed struct {
		Value string `json:"value"`
	}
	h.mustDo(http.MethodGet, "/api/v1/secrets/"+created.ID+"/reveal", adminToken, nil, &revealed, http.StatusOK)
	if revealed.Value != value {
		t.Fatalf("revealed %q want %q", revealed.Value, value)
	}

	// The plaintext must not be recoverable by reading the table directly.
	stored, err := h.store.RawCiphertext(context.Background(), created.ID)
	if err != nil {
		t.Fatalf("read raw ciphertext: %v", err)
	}
	if bytes.Contains(stored, []byte(value)) {
		t.Fatal("the plaintext value is present in the stored ciphertext")
	}

	// Listing never exposes values.
	var list struct {
		Secrets []map[string]any `json:"secrets"`
	}
	h.mustDo(http.MethodGet, "/api/v1/secrets", adminToken, nil, &list, http.StatusOK)
	if len(list.Secrets) != 1 {
		t.Fatalf("expected 1 secret, got %d", len(list.Secrets))
	}
	if _, present := list.Secrets[0]["value"]; present {
		t.Fatal("the list endpoint returned a secret value")
	}
}

func TestSecretsArePrivateUntilShared(t *testing.T) {
	h := newHarness(t)
	adminToken := h.setupAdmin()

	fullAccess := []string{
		auth.PermSecretsRead, auth.PermSecretsCreate, auth.PermSecretsUpdate,
		auth.PermSecretsShare, auth.PermGroupsCreate,
	}
	aliceID, aliceToken := h.onboard(adminToken, "alice", fullAccess)
	bobID, bobToken := h.onboard(adminToken, "bob", fullAccess)

	var secret struct {
		ID string `json:"id"`
	}
	h.mustDo(http.MethodPost, "/api/v1/secrets", aliceToken, map[string]any{
		"name": "alice wifi", "value": "alice-wifi-password",
	}, &secret, http.StatusCreated)

	// Bob cannot see or read a secret that is not his and not shared.
	h.mustDo(http.MethodGet, "/api/v1/secrets/"+secret.ID, bobToken, nil, nil, http.StatusNotFound)
	h.mustDo(http.MethodGet, "/api/v1/secrets/"+secret.ID+"/reveal", bobToken, nil, nil, http.StatusNotFound)

	var group struct {
		ID string `json:"id"`
	}
	h.mustDo(http.MethodPost, "/api/v1/groups", aliceToken, map[string]any{
		"name": "ops", "description": "operations",
	}, &group, http.StatusCreated)

	h.mustDo(http.MethodPost, "/api/v1/groups/"+group.ID+"/members", aliceToken, map[string]any{
		"userId": bobID, "role": "member",
	}, nil, http.StatusOK)

	// Membership alone is not enough; the secret has to be shared with the group.
	h.mustDo(http.MethodGet, "/api/v1/secrets/"+secret.ID, bobToken, nil, nil, http.StatusNotFound)

	h.mustDo(http.MethodPost, "/api/v1/secrets/"+secret.ID+"/shares", aliceToken, map[string]any{
		"groupId": group.ID, "canWrite": false,
	}, nil, http.StatusOK)

	var revealed struct {
		Value string `json:"value"`
	}
	h.mustDo(http.MethodGet, "/api/v1/secrets/"+secret.ID+"/reveal", bobToken, nil, &revealed, http.StatusOK)
	if revealed.Value != "alice-wifi-password" {
		t.Fatalf("bob revealed %q", revealed.Value)
	}

	// Read-only sharing must not let Bob change the value.
	h.mustDo(http.MethodPatch, "/api/v1/secrets/"+secret.ID, bobToken, map[string]any{
		"value": "bob-overwrote-this",
	}, nil, http.StatusNotFound)

	// Granting write access lets him through.
	h.mustDo(http.MethodPost, "/api/v1/secrets/"+secret.ID+"/shares", aliceToken, map[string]any{
		"groupId": group.ID, "canWrite": true,
	}, nil, http.StatusOK)

	h.mustDo(http.MethodPatch, "/api/v1/secrets/"+secret.ID, bobToken, map[string]any{
		"value": "bob-rotated-this",
	}, nil, http.StatusOK)

	h.mustDo(http.MethodGet, "/api/v1/secrets/"+secret.ID+"/reveal", aliceToken, nil, &revealed, http.StatusOK)
	if revealed.Value != "bob-rotated-this" {
		t.Fatalf("after rotation the value is %q", revealed.Value)
	}

	// Revoking the share closes access again.
	h.mustDo(http.MethodDelete, "/api/v1/secrets/"+secret.ID+"/shares/"+group.ID, aliceToken, nil, nil, http.StatusNoContent)
	h.mustDo(http.MethodGet, "/api/v1/secrets/"+secret.ID, bobToken, nil, nil, http.StatusNotFound)

	_ = aliceID
}

func TestPermissionsGateEndpoints(t *testing.T) {
	h := newHarness(t)
	adminToken := h.setupAdmin()

	// A read-only user can list but not create, share, or manage anything.
	_, viewerToken := h.onboard(adminToken, "viewer", []string{auth.PermSecretsRead})

	h.mustDo(http.MethodGet, "/api/v1/secrets", viewerToken, nil, nil, http.StatusOK)
	h.mustDo(http.MethodPost, "/api/v1/secrets", viewerToken, map[string]any{
		"name": "nope", "value": "should-not-be-created",
	}, nil, http.StatusForbidden)
	h.mustDo(http.MethodPost, "/api/v1/groups", viewerToken, map[string]any{"name": "nope"}, nil, http.StatusForbidden)
	h.mustDo(http.MethodPost, "/api/v1/users", viewerToken, map[string]any{
		"username": "nope", "password": "nope-password-1234",
	}, nil, http.StatusForbidden)
	h.mustDo(http.MethodGet, "/api/v1/audit", viewerToken, nil, nil, http.StatusForbidden)
	h.mustDo(http.MethodPost, "/api/v1/tokens", viewerToken, map[string]any{
		"name": "nope", "scopes": []string{auth.PermSecretsRead},
	}, nil, http.StatusForbidden)
}

func TestNonAdminCannotSeeOtherUsersPermissions(t *testing.T) {
	h := newHarness(t)
	adminToken := h.setupAdmin()

	_, viewerToken := h.onboard(adminToken, "viewer", []string{auth.PermSecretsRead})

	var list struct {
		Users []map[string]any `json:"users"`
	}
	h.mustDo(http.MethodGet, "/api/v1/users", viewerToken, nil, &list, http.StatusOK)

	for _, u := range list.Users {
		if _, present := u["permissions"]; present {
			t.Fatal("the directory view leaked permissions to a non-admin")
		}
		if _, present := u["isAdmin"]; present {
			t.Fatal("the directory view leaked the admin flag to a non-admin")
		}
	}
}

func TestUserTokenActsWithinItsScopes(t *testing.T) {
	h := newHarness(t)
	adminToken := h.setupAdmin()

	_, aliceToken := h.onboard(adminToken, "alice", []string{
		auth.PermSecretsRead, auth.PermSecretsCreate, auth.PermTokensCreate,
	})

	var secret struct {
		ID string `json:"id"`
	}
	h.mustDo(http.MethodPost, "/api/v1/secrets", aliceToken, map[string]any{
		"name": "api target", "value": "api-target-value",
	}, &secret, http.StatusCreated)

	// A token may not exceed the permissions of the user who mints it.
	h.mustDo(http.MethodPost, "/api/v1/tokens", aliceToken, map[string]any{
		"name": "too broad", "scopes": []string{auth.PermUsersManage},
	}, nil, http.StatusForbidden)

	var minted struct {
		Plaintext string `json:"plaintext"`
	}
	h.mustDo(http.MethodPost, "/api/v1/tokens", aliceToken, map[string]any{
		"name": "ci reader", "scopes": []string{auth.PermSecretsRead},
	}, &minted, http.StatusCreated)

	if minted.Plaintext == "" {
		t.Fatal("token creation did not return the plaintext")
	}

	var revealed struct {
		Value string `json:"value"`
	}
	h.mustDo(http.MethodGet, "/api/v1/secrets/"+secret.ID+"/reveal", minted.Plaintext, nil, &revealed, http.StatusOK)
	if revealed.Value != "api-target-value" {
		t.Fatalf("token revealed %q", revealed.Value)
	}

	// The token holds secrets:read only, even though Alice can also create.
	h.mustDo(http.MethodPost, "/api/v1/secrets", minted.Plaintext, map[string]any{
		"name": "from token", "value": "should-be-refused",
	}, nil, http.StatusForbidden)
}

func TestRevokedTokenStopsWorking(t *testing.T) {
	h := newHarness(t)
	adminToken := h.setupAdmin()

	var minted struct {
		Plaintext string `json:"plaintext"`
		Token     struct {
			ID string `json:"id"`
		} `json:"token"`
	}
	h.mustDo(http.MethodPost, "/api/v1/tokens", adminToken, map[string]any{
		"name": "temporary", "scopes": []string{auth.PermSecretsRead},
	}, &minted, http.StatusCreated)

	h.mustDo(http.MethodGet, "/api/v1/secrets", minted.Plaintext, nil, nil, http.StatusOK)
	h.mustDo(http.MethodDelete, "/api/v1/tokens/"+minted.Token.ID, adminToken, nil, nil, http.StatusNoContent)
	h.mustDo(http.MethodGet, "/api/v1/secrets", minted.Plaintext, nil, nil, http.StatusUnauthorized)
}

func TestTokenNarrowsWhenOwnerLosesPermission(t *testing.T) {
	h := newHarness(t)
	adminToken := h.setupAdmin()

	aliceID, aliceToken := h.onboard(adminToken, "alice", []string{
		auth.PermSecretsRead, auth.PermSecretsCreate, auth.PermTokensCreate,
	})

	var minted struct {
		Plaintext string `json:"plaintext"`
	}
	h.mustDo(http.MethodPost, "/api/v1/tokens", aliceToken, map[string]any{
		"name": "writer", "scopes": []string{auth.PermSecretsRead, auth.PermSecretsCreate},
	}, &minted, http.StatusCreated)

	h.mustDo(http.MethodPost, "/api/v1/secrets", minted.Plaintext, map[string]any{
		"name": "made by token", "value": "made-by-token-value",
	}, nil, http.StatusCreated)

	// Taking the permission away from Alice must immediately narrow her token.
	h.mustDo(http.MethodPatch, "/api/v1/users/"+aliceID, adminToken, map[string]any{
		"permissions": []string{auth.PermSecretsRead},
	}, nil, http.StatusOK)

	h.mustDo(http.MethodPost, "/api/v1/secrets", minted.Plaintext, map[string]any{
		"name": "second attempt", "value": "should-be-refused",
	}, nil, http.StatusForbidden)
	h.mustDo(http.MethodGet, "/api/v1/secrets", minted.Plaintext, nil, nil, http.StatusOK)
}

func TestGroupTokenReadsOnlySharedSecrets(t *testing.T) {
	h := newHarness(t)
	adminToken := h.setupAdmin()

	var group struct {
		ID string `json:"id"`
	}
	h.mustDo(http.MethodPost, "/api/v1/groups", adminToken, map[string]any{"name": "ci"}, &group, http.StatusCreated)

	var shared, private struct {
		ID string `json:"id"`
	}
	h.mustDo(http.MethodPost, "/api/v1/secrets", adminToken, map[string]any{
		"name": "ci deploy key", "value": "ci-deploy-key-value",
		"shareWith": []map[string]any{{"groupId": group.ID, "canWrite": false}},
	}, &shared, http.StatusCreated)
	h.mustDo(http.MethodPost, "/api/v1/secrets", adminToken, map[string]any{
		"name": "admin only", "value": "admin-only-value",
	}, &private, http.StatusCreated)

	var minted struct {
		Plaintext string `json:"plaintext"`
	}
	h.mustDo(http.MethodPost, "/api/v1/tokens", adminToken, map[string]any{
		"name": "ci runner", "groupId": group.ID, "scopes": []string{auth.PermSecretsRead},
	}, &minted, http.StatusCreated)

	var list struct {
		Secrets []struct {
			ID string `json:"id"`
		} `json:"secrets"`
	}
	h.mustDo(http.MethodGet, "/api/v1/secrets", minted.Plaintext, nil, &list, http.StatusOK)
	if len(list.Secrets) != 1 || list.Secrets[0].ID != shared.ID {
		t.Fatalf("the group token sees %s, expected only the shared secret", mustJSON(list.Secrets))
	}

	h.mustDo(http.MethodGet, "/api/v1/secrets/"+shared.ID+"/reveal", minted.Plaintext, nil, nil, http.StatusOK)
	h.mustDo(http.MethodGet, "/api/v1/secrets/"+private.ID+"/reveal", minted.Plaintext, nil, nil, http.StatusNotFound)

	// A group token is a machine credential; it cannot create anything.
	h.mustDo(http.MethodPost, "/api/v1/secrets", minted.Plaintext, map[string]any{
		"name": "nope", "value": "should-be-refused",
	}, nil, http.StatusForbidden)
}

func TestSecretVersionsAreRecordedOnRotation(t *testing.T) {
	h := newHarness(t)
	adminToken := h.setupAdmin()

	var secret struct {
		ID string `json:"id"`
	}
	h.mustDo(http.MethodPost, "/api/v1/secrets", adminToken, map[string]any{
		"name": "rotating", "value": "version-one-value",
	}, &secret, http.StatusCreated)

	h.mustDo(http.MethodPatch, "/api/v1/secrets/"+secret.ID, adminToken, map[string]any{
		"value": "version-two-value",
	}, nil, http.StatusOK)

	var versions struct {
		Versions []struct {
			Version int `json:"version"`
		} `json:"versions"`
	}
	h.mustDo(http.MethodGet, "/api/v1/secrets/"+secret.ID+"/versions", adminToken, nil, &versions, http.StatusOK)

	if len(versions.Versions) != 2 {
		t.Fatalf("expected 2 versions, got %d", len(versions.Versions))
	}
	if versions.Versions[0].Version != 2 {
		t.Fatalf("newest version is %d, expected 2", versions.Versions[0].Version)
	}
}

func TestLastAdminCannotBeRemovedOrDemoted(t *testing.T) {
	h := newHarness(t)
	adminToken := h.setupAdmin()

	var me struct {
		User struct {
			ID string `json:"id"`
		} `json:"user"`
	}
	h.mustDo(http.MethodGet, "/api/v1/auth/me", adminToken, nil, &me, http.StatusOK)

	h.mustDo(http.MethodPatch, "/api/v1/users/"+me.User.ID, adminToken, map[string]any{
		"isAdmin": false,
	}, nil, http.StatusConflict)
	h.mustDo(http.MethodDelete, "/api/v1/users/"+me.User.ID, adminToken, nil, nil, http.StatusConflict)
}

func TestDisabledUserCannotUseExistingSession(t *testing.T) {
	h := newHarness(t)
	adminToken := h.setupAdmin()

	bobID, bobToken := h.onboard(adminToken, "bob", []string{auth.PermSecretsRead})

	h.mustDo(http.MethodGet, "/api/v1/secrets", bobToken, nil, nil, http.StatusOK)

	h.mustDo(http.MethodPatch, "/api/v1/users/"+bobID, adminToken, map[string]any{
		"isActive": false,
	}, nil, http.StatusOK)

	h.mustDo(http.MethodGet, "/api/v1/secrets", bobToken, nil, nil, http.StatusUnauthorized)
	h.mustDo(http.MethodPost, "/api/v1/auth/login", "", map[string]any{
		"username": "bob", "password": "bob-final-pw-1",
	}, nil, http.StatusForbidden)
}

func TestUnauthenticatedRequestsAreRejected(t *testing.T) {
	h := newHarness(t)
	h.setupAdmin()

	for _, path := range []string{"/api/v1/secrets", "/api/v1/users", "/api/v1/groups", "/api/v1/tokens"} {
		h.mustDo(http.MethodGet, path, "", nil, nil, http.StatusUnauthorized)
	}

	h.mustDo(http.MethodGet, "/api/v1/secrets", "sks_deadbeef_notarealtoken", nil, nil, http.StatusUnauthorized)
	h.mustDo(http.MethodGet, "/api/v1/secrets", "not-even-a-token", nil, nil, http.StatusUnauthorized)
}

func TestAuditLogRecordsReveals(t *testing.T) {
	h := newHarness(t)
	adminToken := h.setupAdmin()

	var secret struct {
		ID string `json:"id"`
	}
	h.mustDo(http.MethodPost, "/api/v1/secrets", adminToken, map[string]any{
		"name": "watched", "value": "watched-secret-value",
	}, &secret, http.StatusCreated)

	h.mustDo(http.MethodGet, "/api/v1/secrets/"+secret.ID+"/reveal", adminToken, nil, nil, http.StatusOK)

	var log struct {
		Entries []struct {
			Action   string `json:"action"`
			TargetID string `json:"targetId"`
		} `json:"entries"`
	}
	h.mustDo(http.MethodGet, "/api/v1/audit", adminToken, nil, &log, http.StatusOK)

	var found bool
	for _, e := range log.Entries {
		if e.Action == "secret.revealed" && e.TargetID == secret.ID {
			found = true
		}
	}
	if !found {
		t.Fatalf("no reveal entry in the audit log: %s", mustJSON(log.Entries))
	}
}

func TestExpiredTokenIsRejected(t *testing.T) {
	h := newHarness(t)
	adminToken := h.setupAdmin()

	var minted struct {
		Plaintext string `json:"plaintext"`
		Token     struct {
			ID string `json:"id"`
		} `json:"token"`
	}
	h.mustDo(http.MethodPost, "/api/v1/tokens", adminToken, map[string]any{
		"name": "short lived", "scopes": []string{auth.PermSecretsRead}, "expiresInDays": 1,
	}, &minted, http.StatusCreated)

	h.mustDo(http.MethodGet, "/api/v1/secrets", minted.Plaintext, nil, nil, http.StatusOK)

	if err := h.store.ForceExpireToken(context.Background(), minted.Token.ID, time.Now().Add(-time.Hour)); err != nil {
		t.Fatalf("expire token: %v", err)
	}

	h.mustDo(http.MethodGet, "/api/v1/secrets", minted.Plaintext, nil, nil, http.StatusUnauthorized)
}

func TestHealthEndpoints(t *testing.T) {
	h := newHarness(t)

	h.mustDo(http.MethodGet, "/healthz", "", nil, nil, http.StatusOK)
	h.mustDo(http.MethodGet, "/readyz", "", nil, nil, http.StatusOK)
}

// Replicas start at the same time and all call Migrate. Without serialization
// they raced on the same DDL and the losing pod exited.
func TestConcurrentMigrationsAreSafe(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL is not set; skipping integration tests")
	}

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx := context.Background()

	// Start from a database with no schema at all, as on a first install.
	bootstrap, err := store.Open(ctx, dsn, log)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if err := bootstrap.DropSchema(ctx); err != nil {
		t.Fatalf("drop schema: %v", err)
	}
	bootstrap.Close()

	const replicas = 6
	errs := make(chan error, replicas)
	start := make(chan struct{})

	for i := 0; i < replicas; i++ {
		go func() {
			st, err := store.Open(ctx, dsn, log)
			if err != nil {
				errs <- err
				return
			}
			defer st.Close()

			<-start
			errs <- st.Migrate(ctx)
		}()
	}

	close(start)

	for i := 0; i < replicas; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("replica %d failed to migrate: %v", i, err)
		}
	}

	// The schema must be usable and the migration recorded exactly once.
	check, err := store.Open(ctx, dsn, log)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer check.Close()

	applied, err := check.AppliedMigrations(ctx)
	if err != nil {
		t.Fatalf("count migrations: %v", err)
	}

	embedded, err := store.MigrationCount()
	if err != nil {
		t.Fatalf("count embedded migrations: %v", err)
	}

	// Each migration recorded once, no matter how many replicas ran it.
	if applied != embedded {
		t.Fatalf("expected %d recorded migrations, got %d", embedded, applied)
	}
}

type profileView struct {
	DisplayName string `json:"displayName"`
	Email       string `json:"email"`
}

func TestUserCanChangeTheirOwnEmail(t *testing.T) {
	h := newHarness(t)
	adminToken := h.setupAdmin()

	_, aliceToken := h.onboard(adminToken, "alice", []string{auth.PermSecretsRead})

	var updated profileView
	h.mustDo(http.MethodPatch, "/api/v1/auth/me", aliceToken, map[string]any{
		"email": "alice@example.com",
	}, &updated, http.StatusOK)
	if updated.Email != "alice@example.com" {
		t.Fatalf("email was not applied: %s", mustJSON(updated))
	}

	// An empty address clears it rather than being ignored. Decoded into a
	// fresh value, since a stale one would mask the field being absent.
	var cleared profileView
	h.mustDo(http.MethodPatch, "/api/v1/auth/me", aliceToken, map[string]any{
		"email": "",
	}, &cleared, http.StatusOK)
	if cleared.Email != "" {
		t.Fatalf("email was not cleared, got %q", cleared.Email)
	}
}

// The display name is what other people see in group and user lists, so it is
// an administrator's to set, not the account holder's.
func TestUserCannotChangeTheirOwnDisplayName(t *testing.T) {
	h := newHarness(t)
	adminToken := h.setupAdmin()

	aliceID, aliceToken := h.onboard(adminToken, "alice", []string{auth.PermSecretsRead})

	h.mustDo(http.MethodPatch, "/api/v1/auth/me", aliceToken, map[string]any{
		"displayName": "Something Else",
	}, nil, http.StatusBadRequest)

	// An administrator still can.
	var updated profileView
	h.mustDo(http.MethodPatch, "/api/v1/users/"+aliceID, adminToken, map[string]any{
		"displayName": "Alice Bergström",
	}, &updated, http.StatusOK)
	if updated.DisplayName != "Alice Bergström" {
		t.Fatalf("admin could not set the display name: %s", mustJSON(updated))
	}
}

func TestProfileEndpointCannotEscalate(t *testing.T) {
	h := newHarness(t)
	adminToken := h.setupAdmin()

	_, aliceToken := h.onboard(adminToken, "alice", []string{auth.PermSecretsRead})

	// isAdmin and permissions are not fields of this endpoint, so a request
	// carrying them is refused outright rather than silently ignored.
	h.mustDo(http.MethodPatch, "/api/v1/auth/me", aliceToken, map[string]any{
		"isAdmin": true,
	}, nil, http.StatusBadRequest)

	h.mustDo(http.MethodPatch, "/api/v1/auth/me", aliceToken, map[string]any{
		"permissions": []string{auth.PermUsersManage},
	}, nil, http.StatusBadRequest)

	var me struct {
		User struct {
			IsAdmin     bool     `json:"isAdmin"`
			Permissions []string `json:"permissions"`
		} `json:"user"`
	}
	h.mustDo(http.MethodGet, "/api/v1/auth/me", aliceToken, nil, &me, http.StatusOK)
	if me.User.IsAdmin || len(me.User.Permissions) != 1 {
		t.Fatalf("alice escalated: %s", mustJSON(me))
	}
}

func TestRejectsMalformedEmail(t *testing.T) {
	h := newHarness(t)
	adminToken := h.setupAdmin()

	h.mustDo(http.MethodPatch, "/api/v1/auth/me", adminToken, map[string]any{
		"email": "not-an-address",
	}, nil, http.StatusBadRequest)
}

func TestAdminCanRenameGroup(t *testing.T) {
	h := newHarness(t)
	adminToken := h.setupAdmin()

	var group struct {
		ID string `json:"id"`
	}
	h.mustDo(http.MethodPost, "/api/v1/groups", adminToken, map[string]any{
		"name": "old name", "description": "before",
	}, &group, http.StatusCreated)

	var renamed struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	h.mustDo(http.MethodPatch, "/api/v1/groups/"+group.ID, adminToken, map[string]any{
		"name": "new name", "description": "after",
	}, &renamed, http.StatusOK)

	if renamed.Name != "new name" || renamed.Description != "after" {
		t.Fatalf("rename did not apply: %s", mustJSON(renamed))
	}

	// A name already taken by another group is refused.
	h.mustDo(http.MethodPost, "/api/v1/groups", adminToken, map[string]any{"name": "taken"}, nil, http.StatusCreated)
	h.mustDo(http.MethodPatch, "/api/v1/groups/"+group.ID, adminToken, map[string]any{
		"name": "taken",
	}, nil, http.StatusConflict)

	// Someone with no group rights cannot rename it.
	_, outsiderToken := h.onboard(adminToken, "outsider", []string{auth.PermSecretsRead})
	h.mustDo(http.MethodPatch, "/api/v1/groups/"+group.ID, outsiderToken, map[string]any{
		"name": "hijacked",
	}, nil, http.StatusForbidden)
}

// --- Direct shares with a person ------------------------------------------

func TestSecretSharedDirectlyWithOneUser(t *testing.T) {
	h := newHarness(t)
	adminToken := h.setupAdmin()

	sharer := []string{auth.PermSecretsRead, auth.PermSecretsCreate, auth.PermSecretsUpdate, auth.PermSecretsShare}
	_, aliceToken := h.onboard(adminToken, "alice", sharer)
	bobID, bobToken := h.onboard(adminToken, "bob", sharer)
	_, carolToken := h.onboard(adminToken, "carol", sharer)

	var secret struct {
		ID string `json:"id"`
	}
	h.mustDo(http.MethodPost, "/api/v1/secrets", aliceToken, map[string]any{
		"name": "alice laptop", "value": "alice-laptop-password",
	}, &secret, http.StatusCreated)

	// No group involved at all: Alice shares straight with Bob.
	h.mustDo(http.MethodPost, "/api/v1/secrets/"+secret.ID+"/shares", aliceToken, map[string]any{
		"userId": bobID, "canWrite": false,
	}, nil, http.StatusOK)

	var revealed struct {
		Value string `json:"value"`
	}
	h.mustDo(http.MethodGet, "/api/v1/secrets/"+secret.ID+"/reveal", bobToken, nil, &revealed, http.StatusOK)
	if revealed.Value != "alice-laptop-password" {
		t.Fatalf("bob revealed %q", revealed.Value)
	}

	// Carol was not named, so she still sees nothing.
	h.mustDo(http.MethodGet, "/api/v1/secrets/"+secret.ID, carolToken, nil, nil, http.StatusNotFound)

	// Read-only means read-only.
	h.mustDo(http.MethodPatch, "/api/v1/secrets/"+secret.ID, bobToken, map[string]any{
		"value": "bob-overwrote-this",
	}, nil, http.StatusNotFound)

	// The owner can promote the share to write.
	h.mustDo(http.MethodPost, "/api/v1/secrets/"+secret.ID+"/shares", aliceToken, map[string]any{
		"userId": bobID, "canWrite": true,
	}, nil, http.StatusOK)
	h.mustDo(http.MethodPatch, "/api/v1/secrets/"+secret.ID, bobToken, map[string]any{
		"value": "bob-rotated-this",
	}, nil, http.StatusOK)

	h.mustDo(http.MethodGet, "/api/v1/secrets/"+secret.ID+"/reveal", aliceToken, nil, &revealed, http.StatusOK)
	if revealed.Value != "bob-rotated-this" {
		t.Fatalf("after bob's write the value is %q", revealed.Value)
	}

	// Revoking closes it again.
	h.mustDo(http.MethodDelete, "/api/v1/secrets/"+secret.ID+"/shares/users/"+bobID, aliceToken, nil, nil, http.StatusNoContent)
	h.mustDo(http.MethodGet, "/api/v1/secrets/"+secret.ID, bobToken, nil, nil, http.StatusNotFound)
}

func TestSecretListsBothKindsOfShare(t *testing.T) {
	h := newHarness(t)
	adminToken := h.setupAdmin()

	bobID, _ := h.onboard(adminToken, "bob", []string{auth.PermSecretsRead})

	var group struct {
		ID string `json:"id"`
	}
	h.mustDo(http.MethodPost, "/api/v1/groups", adminToken, map[string]any{"name": "ops"}, &group, http.StatusCreated)

	var secret struct {
		ID string `json:"id"`
	}
	h.mustDo(http.MethodPost, "/api/v1/secrets", adminToken, map[string]any{
		"name": "mixed", "value": "mixed-share-value",
		"shareWith": []map[string]any{
			{"groupId": group.ID, "canWrite": false},
			{"userId": bobID, "canWrite": true},
		},
	}, &secret, http.StatusCreated)

	var view struct {
		Shares []struct {
			GroupName string `json:"groupName"`
		} `json:"shares"`
		UserShares []struct {
			Username string `json:"username"`
			CanWrite bool   `json:"canWrite"`
		} `json:"userShares"`
	}
	h.mustDo(http.MethodGet, "/api/v1/secrets/"+secret.ID, adminToken, nil, &view, http.StatusOK)

	if len(view.Shares) != 1 || view.Shares[0].GroupName != "ops" {
		t.Fatalf("group share missing: %s", mustJSON(view))
	}
	if len(view.UserShares) != 1 || view.UserShares[0].Username != "bob" || !view.UserShares[0].CanWrite {
		t.Fatalf("user share missing or wrong: %s", mustJSON(view))
	}
}

func TestOnlyOwnerOrAdminSharesDirectly(t *testing.T) {
	h := newHarness(t)
	adminToken := h.setupAdmin()

	sharer := []string{auth.PermSecretsRead, auth.PermSecretsCreate, auth.PermSecretsShare}
	_, aliceToken := h.onboard(adminToken, "alice", sharer)
	bobID, bobToken := h.onboard(adminToken, "bob", sharer)
	carolID, _ := h.onboard(adminToken, "carol", sharer)

	var secret struct {
		ID string `json:"id"`
	}
	h.mustDo(http.MethodPost, "/api/v1/secrets", aliceToken, map[string]any{
		"name": "alice only", "value": "alice-only-value",
	}, &secret, http.StatusCreated)

	h.mustDo(http.MethodPost, "/api/v1/secrets/"+secret.ID+"/shares", aliceToken, map[string]any{
		"userId": bobID,
	}, nil, http.StatusOK)

	// Bob can read it, but it is not his to pass on.
	h.mustDo(http.MethodPost, "/api/v1/secrets/"+secret.ID+"/shares", bobToken, map[string]any{
		"userId": carolID,
	}, nil, http.StatusForbidden)

	// An administrator may share anything.
	h.mustDo(http.MethodPost, "/api/v1/secrets/"+secret.ID+"/shares", adminToken, map[string]any{
		"userId": carolID,
	}, nil, http.StatusOK)
}

func TestShareRequestMustNameExactlyOneTarget(t *testing.T) {
	h := newHarness(t)
	adminToken := h.setupAdmin()

	var group struct {
		ID string `json:"id"`
	}
	h.mustDo(http.MethodPost, "/api/v1/groups", adminToken, map[string]any{"name": "ops"}, &group, http.StatusCreated)

	var secret struct {
		ID string `json:"id"`
	}
	h.mustDo(http.MethodPost, "/api/v1/secrets", adminToken, map[string]any{
		"name": "target test", "value": "target-test-value",
	}, &secret, http.StatusCreated)

	var me struct {
		User struct {
			ID string `json:"id"`
		} `json:"user"`
	}
	h.mustDo(http.MethodGet, "/api/v1/auth/me", adminToken, nil, &me, http.StatusOK)

	// Neither.
	h.mustDo(http.MethodPost, "/api/v1/secrets/"+secret.ID+"/shares", adminToken,
		map[string]any{"canWrite": true}, nil, http.StatusBadRequest)
	// Both.
	h.mustDo(http.MethodPost, "/api/v1/secrets/"+secret.ID+"/shares", adminToken,
		map[string]any{"groupId": group.ID, "userId": me.User.ID}, nil, http.StatusBadRequest)
	// Unknown person.
	h.mustDo(http.MethodPost, "/api/v1/secrets/"+secret.ID+"/shares", adminToken,
		map[string]any{"userId": "6f1b8b3e-0000-4000-8000-000000000000"}, nil, http.StatusBadRequest)
	// The owner already has it.
	h.mustDo(http.MethodPost, "/api/v1/secrets/"+secret.ID+"/shares", adminToken,
		map[string]any{"userId": me.User.ID}, nil, http.StatusBadRequest)
}

// The group-only revoke path predates per-user sharing and must keep working.
func TestLegacyGroupUnsharePathStillWorks(t *testing.T) {
	h := newHarness(t)
	adminToken := h.setupAdmin()

	var group struct {
		ID string `json:"id"`
	}
	h.mustDo(http.MethodPost, "/api/v1/groups", adminToken, map[string]any{"name": "ops"}, &group, http.StatusCreated)

	var secret struct {
		ID string `json:"id"`
	}
	h.mustDo(http.MethodPost, "/api/v1/secrets", adminToken, map[string]any{
		"name": "legacy", "value": "legacy-share-value",
		"shareWith": []map[string]any{{"groupId": group.ID}},
	}, &secret, http.StatusCreated)

	h.mustDo(http.MethodDelete, "/api/v1/secrets/"+secret.ID+"/shares/"+group.ID, adminToken, nil, nil, http.StatusNoContent)

	var view struct {
		Shares []any `json:"shares"`
	}
	h.mustDo(http.MethodGet, "/api/v1/secrets/"+secret.ID, adminToken, nil, &view, http.StatusOK)
	if len(view.Shares) != 0 {
		t.Fatalf("share survived the legacy revoke: %s", mustJSON(view))
	}
}

// --- Group ownership -------------------------------------------------------

func TestGroupCreatorManagesTheirGroup(t *testing.T) {
	h := newHarness(t)
	adminToken := h.setupAdmin()

	// Only the right to create a group, not to manage every group.
	_, creatorToken := h.onboard(adminToken, "creator", []string{auth.PermSecretsRead, auth.PermGroupsCreate})
	otherID, _ := h.onboard(adminToken, "other", []string{auth.PermSecretsRead})

	var group struct {
		ID string `json:"id"`
	}
	h.mustDo(http.MethodPost, "/api/v1/groups", creatorToken, map[string]any{"name": "mine"}, &group, http.StatusCreated)

	h.mustDo(http.MethodPost, "/api/v1/groups/"+group.ID+"/members", creatorToken, map[string]any{
		"userId": otherID, "role": "member",
	}, nil, http.StatusOK)

	h.mustDo(http.MethodPatch, "/api/v1/groups/"+group.ID, creatorToken, map[string]any{
		"name": "still mine",
	}, nil, http.StatusOK)

	h.mustDo(http.MethodDelete, "/api/v1/groups/"+group.ID+"/members/"+otherID, creatorToken, nil, nil, http.StatusNoContent)
}

// Being demoted from manager, or dropped from the membership entirely, must not
// lock the creator out of a group they made.
func TestGroupCreatorKeepsControlAfterDemotion(t *testing.T) {
	h := newHarness(t)
	adminToken := h.setupAdmin()

	creatorID, creatorToken := h.onboard(adminToken, "creator", []string{auth.PermSecretsRead, auth.PermGroupsCreate})
	otherID, _ := h.onboard(adminToken, "other", []string{auth.PermSecretsRead})

	var group struct {
		ID string `json:"id"`
	}
	h.mustDo(http.MethodPost, "/api/v1/groups", creatorToken, map[string]any{"name": "mine"}, &group, http.StatusCreated)

	// An administrator demotes them to an ordinary member.
	h.mustDo(http.MethodPost, "/api/v1/groups/"+group.ID+"/members", adminToken, map[string]any{
		"userId": creatorID, "role": "member",
	}, nil, http.StatusOK)

	h.mustDo(http.MethodPost, "/api/v1/groups/"+group.ID+"/members", creatorToken, map[string]any{
		"userId": otherID, "role": "member",
	}, nil, http.StatusOK)

	// And then removes them from the group altogether.
	h.mustDo(http.MethodDelete, "/api/v1/groups/"+group.ID+"/members/"+creatorID, adminToken, nil, nil, http.StatusNoContent)

	h.mustDo(http.MethodPatch, "/api/v1/groups/"+group.ID, creatorToken, map[string]any{
		"name": "renamed anyway",
	}, nil, http.StatusOK)

	// It still appears in their own group list.
	var list struct {
		Groups []struct {
			Name string `json:"name"`
		} `json:"groups"`
	}
	h.mustDo(http.MethodGet, "/api/v1/groups", creatorToken, nil, &list, http.StatusOK)
	if len(list.Groups) != 1 || list.Groups[0].Name != "renamed anyway" {
		t.Fatalf("creator lost sight of their group: %s", mustJSON(list))
	}
}

// An outsider with no relationship to the group still gets nothing.
func TestNonMemberCannotManageSomeoneElsesGroup(t *testing.T) {
	h := newHarness(t)
	adminToken := h.setupAdmin()

	_, creatorToken := h.onboard(adminToken, "creator", []string{auth.PermSecretsRead, auth.PermGroupsCreate})
	outsiderID, outsiderToken := h.onboard(adminToken, "outsider", []string{auth.PermSecretsRead, auth.PermGroupsCreate})

	var group struct {
		ID string `json:"id"`
	}
	h.mustDo(http.MethodPost, "/api/v1/groups", creatorToken, map[string]any{"name": "theirs"}, &group, http.StatusCreated)

	h.mustDo(http.MethodPost, "/api/v1/groups/"+group.ID+"/members", outsiderToken, map[string]any{
		"userId": outsiderID, "role": "manager",
	}, nil, http.StatusForbidden)
	h.mustDo(http.MethodPatch, "/api/v1/groups/"+group.ID, outsiderToken, map[string]any{
		"name": "hijacked",
	}, nil, http.StatusForbidden)
	h.mustDo(http.MethodGet, "/api/v1/groups/"+group.ID, outsiderToken, nil, nil, http.StatusNotFound)
}

// The administrator's view is unconditional: every group, editable.
func TestAdminSeesAndEditsEveryGroup(t *testing.T) {
	h := newHarness(t)
	adminToken := h.setupAdmin()

	_, creatorToken := h.onboard(adminToken, "creator", []string{auth.PermSecretsRead, auth.PermGroupsCreate})

	var group struct {
		ID string `json:"id"`
	}
	h.mustDo(http.MethodPost, "/api/v1/groups", creatorToken, map[string]any{"name": "not the admins"}, &group, http.StatusCreated)

	var list struct {
		Groups []struct {
			ID string `json:"id"`
		} `json:"groups"`
	}
	h.mustDo(http.MethodGet, "/api/v1/groups", adminToken, nil, &list, http.StatusOK)
	if len(list.Groups) != 1 || list.Groups[0].ID != group.ID {
		t.Fatalf("admin does not see the group: %s", mustJSON(list))
	}

	h.mustDo(http.MethodGet, "/api/v1/groups/"+group.ID, adminToken, nil, nil, http.StatusOK)
	h.mustDo(http.MethodPatch, "/api/v1/groups/"+group.ID, adminToken, map[string]any{
		"name": "admin renamed it",
	}, nil, http.StatusOK)
	h.mustDo(http.MethodDelete, "/api/v1/groups/"+group.ID, adminToken, nil, nil, http.StatusNoContent)
}
