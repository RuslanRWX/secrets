package api

import (
	"net/http"
	"strings"

	"github.com/ruslanrwx/secrets/backend/internal/auth"
	"github.com/ruslanrwx/secrets/backend/internal/cryptoutil"
	"github.com/ruslanrwx/secrets/backend/internal/store"
)

// handleSetupStatus tells the UI whether the install wizard should be shown.
func (s *Server) handleSetupStatus(w http.ResponseWriter, r *http.Request) {
	settings, err := s.store.Settings(r.Context())
	if err != nil {
		s.serverError(w, r, err)

		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"initialized":  settings.Initialized,
		"instanceName": settings.InstanceName,
		"version":      s.version,
	})
}

type setupRequest struct {
	InstanceName string `json:"instanceName"`
	Username     string `json:"username"`
	Password     string `json:"password"`
	Email        string `json:"email"`
	DisplayName  string `json:"displayName"`
}

// handleSetup creates the first administrator. It succeeds exactly once: after
// the installation is marked initialized this endpoint always refuses.
func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	var req setupRequest
	if err := decode(r, &req); err != nil {
		badRequest(w, err.Error())

		return
	}

	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" {
		badRequest(w, "username is required")

		return
	}
	if problem := validatePassword(req.Password); problem != "" {
		badRequest(w, problem)

		return
	}

	settings, err := s.store.Settings(r.Context())
	if err != nil {
		s.serverError(w, r, err)

		return
	}
	if settings.Initialized {
		conflict(w, "this installation has already been set up")

		return
	}

	// Guard against a race between two concurrent wizard submissions.
	count, err := s.store.CountUsers(r.Context())
	if err != nil {
		s.serverError(w, r, err)

		return
	}
	if count > 0 {
		conflict(w, "this installation has already been set up")

		return
	}

	hash, err := cryptoutil.HashPassword(req.Password)
	if err != nil {
		s.serverError(w, r, err)

		return
	}

	instanceName := strings.TrimSpace(req.InstanceName)
	if instanceName == "" {
		instanceName = "secrets"
	}

	admin, err := s.store.CreateUser(r.Context(), &store.User{
		Username:           req.Username,
		Email:              strings.TrimSpace(req.Email),
		DisplayName:        strings.TrimSpace(req.DisplayName),
		PasswordHash:       hash,
		IsAdmin:            true,
		IsActive:           true,
		MustChangePassword: false, // The admin just chose this password themselves.
		Permissions:        auth.All,
	})
	if err != nil {
		s.serverError(w, r, err)

		return
	}

	check, err := s.keys.NewKeyCheck()
	if err != nil {
		s.serverError(w, r, err)

		return
	}

	if err := s.store.MarkInitialized(r.Context(), instanceName, s.keys.KeyID(), check); err != nil {
		s.serverError(w, r, err)

		return
	}

	token, expiry, err := s.sessions.Issue(admin.ID, admin.Username, true)
	if err != nil {
		s.serverError(w, r, err)

		return
	}

	s.audit(r, &Principal{User: admin, IsAdmin: true}, "setup.completed", "instance", instanceName, nil)

	writeJSON(w, http.StatusCreated, map[string]any{
		"token":     token,
		"expiresAt": expiry,
		"user":      admin,
	})
}

// validatePassword enforces the minimum password policy and returns a message when it fails.
func validatePassword(password string) string {
	if len(password) < 12 {
		return "password must be at least 12 characters"
	}
	if len(password) > 512 {
		return "password must be at most 512 characters"
	}

	return ""
}
