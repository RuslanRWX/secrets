// Package api exposes the HTTP interface of the secrets service.
package api

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/ruslanrwx/secrets/backend/internal/auth"
	"github.com/ruslanrwx/secrets/backend/internal/config"
	"github.com/ruslanrwx/secrets/backend/internal/cryptoutil"
	"github.com/ruslanrwx/secrets/backend/internal/store"
)

// Server wires the store, keyring and session issuer into an HTTP handler.
type Server struct {
	store      *store.Store
	keys       *cryptoutil.Keyring
	sessions   *auth.Sessions
	log        *slog.Logger
	trustProxy bool
	version    string
}

// New builds the API server.
func New(cfg *config.Config, st *store.Store, keys *cryptoutil.Keyring, log *slog.Logger, version string) *Server {
	return &Server{
		store:      st,
		keys:       keys,
		sessions:   auth.NewSessions(cfg.JWTSecret, cfg.SessionTTL),
		log:        log,
		trustProxy: cfg.TrustedProxy,
		version:    version,
	}
}

// Routes returns the fully assembled router.
func (s *Server) Routes(corsOrigins []string) http.Handler {
	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))

	if len(corsOrigins) > 0 {
		r.Use(cors.Handler(cors.Options{
			AllowedOrigins:   corsOrigins,
			AllowedMethods:   []string{"GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"},
			AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type"},
			AllowCredentials: false,
			MaxAge:           300,
		}))
	}

	r.Get("/healthz", s.handleHealth)
	r.Get("/readyz", s.handleReady)

	r.Route("/api/v1", func(r chi.Router) {
		// Unauthenticated: first-run install and sign-in.
		r.Get("/setup/status", s.handleSetupStatus)
		r.Post("/setup", s.handleSetup)
		r.Post("/auth/login", s.handleLogin)

		r.Group(func(r chi.Router) {
			r.Use(s.authenticate)

			// Reachable even while a password change is pending.
			r.Get("/auth/me", s.handleMe)
			r.Post("/auth/change-password", s.handleChangePassword)
			r.Patch("/auth/me", s.handleUpdateProfile)
			r.Get("/meta/permissions", s.handlePermissionCatalog)

			r.Group(func(r chi.Router) {
				r.Use(requirePasswordChanged)

				r.Route("/secrets", func(r chi.Router) {
					r.With(requirePermission(auth.PermSecretsRead)).Get("/", s.handleListSecrets)
					r.With(requirePermission(auth.PermSecretsCreate)).Post("/", s.handleCreateSecret)
					r.With(requirePermission(auth.PermSecretsRead)).Get("/{id}", s.handleGetSecret)
					r.With(requirePermission(auth.PermSecretsRead)).Get("/{id}/reveal", s.handleRevealSecret)
					r.With(requirePermission(auth.PermSecretsRead)).Get("/{id}/versions", s.handleSecretVersions)
					r.With(requirePermission(auth.PermSecretsUpdate)).Patch("/{id}", s.handleUpdateSecret)
					r.With(requirePermission(auth.PermSecretsDelete)).Delete("/{id}", s.handleDeleteSecret)
					r.With(requirePermission(auth.PermSecretsShare)).Post("/{id}/shares", s.handleShareSecret)
					r.With(requirePermission(auth.PermSecretsShare)).Delete("/{id}/shares/{groupID}", s.handleUnshareSecret)
				})

				r.Route("/groups", func(r chi.Router) {
					r.Get("/", s.handleListGroups)
					r.With(requirePermission(auth.PermGroupsCreate)).Post("/", s.handleCreateGroup)
					r.Get("/{id}", s.handleGetGroup)
					// These verify authority per group inside the handler, since a
					// group's own manager may act without holding groups:manage.
					r.Patch("/{id}", s.handleUpdateGroup)
					r.Delete("/{id}", s.handleDeleteGroup)
					r.Post("/{id}/members", s.handleAddGroupMember)
					r.Delete("/{id}/members/{userID}", s.handleRemoveGroupMember)
				})

				r.Route("/users", func(r chi.Router) {
					r.Get("/", s.handleListUsers)
					r.With(requirePermission(auth.PermUsersManage)).Post("/", s.handleCreateUser)
					r.With(requirePermission(auth.PermUsersManage)).Patch("/{id}", s.handleUpdateUser)
					r.With(requirePermission(auth.PermUsersManage)).Delete("/{id}", s.handleDeleteUser)
					r.With(requirePermission(auth.PermUsersManage)).Post("/{id}/reset-password", s.handleResetPassword)
				})

				r.Route("/tokens", func(r chi.Router) {
					r.Get("/", s.handleListTokens)
					r.With(requirePermission(auth.PermTokensCreate)).Post("/", s.handleCreateToken)
					r.Delete("/{id}", s.handleRevokeToken)
				})

				r.With(requireAdmin).Get("/audit", s.handleAudit)
			})
		})
	})

	return r
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "version": s.version})
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	if err := s.store.Ping(r.Context()); err != nil {
		writeError(w, http.StatusServiceUnavailable, "not_ready", "database is unreachable")

		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func (s *Server) handlePermissionCatalog(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"permissions": auth.All, "defaults": auth.Defaults})
}

// audit appends an entry, logging rather than failing the request when it cannot be written.
func (s *Server) audit(r *http.Request, p *Principal, action, targetType, targetID string, detail map[string]any) {
	record := store.AuditRecord{
		Action:     action,
		TargetType: targetType,
		TargetID:   targetID,
		Detail:     detail,
		IP:         s.clientIP(r),
	}
	if p != nil {
		record.ActorUserID = p.UserID()
		record.ActorTokenID = p.TokenID()
		record.ActorLabel = p.Label()
	}

	if err := s.store.AppendAudit(r.Context(), record); err != nil {
		s.log.Error("append audit entry", "action", action, "error", err)
	}
}
