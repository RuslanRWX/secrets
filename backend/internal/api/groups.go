package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/ruslanrwx/secrets/backend/internal/auth"
	"github.com/ruslanrwx/secrets/backend/internal/store"
)

// handleListGroups shows all groups to managers and only the caller's own groups otherwise.
func (s *Server) handleListGroups(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())

	scope := p.UserID()
	if p.Can(auth.PermGroupsManage) || p.Can(auth.PermUsersManage) {
		scope = nil // See everything.
	}

	groups, err := s.store.ListGroups(r.Context(), scope)
	if err != nil {
		s.serverError(w, r, err)

		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"groups": groups})
}

type createGroupRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// handleCreateGroup creates a group and makes the creator its first manager.
func (s *Server) handleCreateGroup(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if p.User == nil {
		forbidden(w, "a group token cannot create groups")

		return
	}

	var req createGroupRequest
	if err := decode(r, &req); err != nil {
		badRequest(w, err.Error())

		return
	}
	if strings.TrimSpace(req.Name) == "" {
		badRequest(w, "group name is required")

		return
	}

	group, err := s.store.CreateGroup(r.Context(), req.Name, req.Description, p.User.ID)
	if err != nil {
		if isUniqueViolation(err) {
			conflict(w, "a group with that name already exists")

			return
		}
		s.serverError(w, r, err)

		return
	}

	if err := s.store.AddGroupMember(r.Context(), group.ID, p.User.ID, "manager", &p.User.ID); err != nil {
		s.serverError(w, r, err)

		return
	}

	s.audit(r, p, "group.created", "group", group.ID.String(), map[string]any{"name": group.Name})

	full, err := s.store.GroupByID(r.Context(), group.ID)
	if err != nil {
		s.serverError(w, r, err)

		return
	}

	writeJSON(w, http.StatusCreated, full)
}

// handleGetGroup returns a group with its members, if the caller may see it.
func (s *Server) handleGetGroup(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())

	id, ok := pathUUID(w, chi.URLParam(r, "id"))
	if !ok {
		return
	}

	group, err := s.store.GroupByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			notFound(w)

			return
		}
		s.serverError(w, r, err)

		return
	}

	visible, err := s.canSeeGroup(r, p, id)
	if err != nil {
		s.serverError(w, r, err)

		return
	}
	if !visible {
		notFound(w)

		return
	}

	writeJSON(w, http.StatusOK, group)
}

type updateGroupRequest struct {
	Name        *string `json:"name"`
	Description *string `json:"description"`
}

// handleUpdateGroup renames a group or edits its description.
func (s *Server) handleUpdateGroup(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())

	id, ok := pathUUID(w, chi.URLParam(r, "id"))
	if !ok {
		return
	}

	allowed, err := s.canManageGroup(r, p, id)
	if err != nil {
		s.serverError(w, r, err)

		return
	}
	if !allowed {
		forbidden(w, "you must be an administrator or a manager of this group")

		return
	}

	var req updateGroupRequest
	if err := decode(r, &req); err != nil {
		badRequest(w, err.Error())

		return
	}

	group, err := s.store.UpdateGroup(r.Context(), id, req.Name, req.Description)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			notFound(w)

			return
		}
		if isUniqueViolation(err) {
			conflict(w, "a group with that name already exists")

			return
		}
		s.serverError(w, r, err)

		return
	}

	s.audit(r, p, "group.updated", "group", id.String(), map[string]any{"name": group.Name})

	writeJSON(w, http.StatusOK, group)
}

// handleDeleteGroup removes a group; secrets shared with it stay with their owners.
func (s *Server) handleDeleteGroup(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())

	id, ok := pathUUID(w, chi.URLParam(r, "id"))
	if !ok {
		return
	}

	allowed, err := s.canManageGroup(r, p, id)
	if err != nil {
		s.serverError(w, r, err)

		return
	}
	if !allowed {
		forbidden(w, "you must be an administrator or a manager of this group")

		return
	}

	if err := s.store.DeleteGroup(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			notFound(w)

			return
		}
		s.serverError(w, r, err)

		return
	}

	s.audit(r, p, "group.deleted", "group", id.String(), nil)

	w.WriteHeader(http.StatusNoContent)
}

type addMemberRequest struct {
	UserID string `json:"userId"`
	Role   string `json:"role"`
}

// handleAddGroupMember adds a user to a group as member or manager.
func (s *Server) handleAddGroupMember(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())

	groupID, ok := pathUUID(w, chi.URLParam(r, "id"))
	if !ok {
		return
	}

	allowed, err := s.canManageGroup(r, p, groupID)
	if err != nil {
		s.serverError(w, r, err)

		return
	}
	if !allowed {
		forbidden(w, "you must be an administrator or a manager of this group")

		return
	}

	var req addMemberRequest
	if err := decode(r, &req); err != nil {
		badRequest(w, err.Error())

		return
	}

	userID, ok := pathUUID(w, req.UserID)
	if !ok {
		return
	}

	role := req.Role
	if role == "" {
		role = "member"
	}
	if role != "member" && role != "manager" {
		badRequest(w, `role must be either "member" or "manager"`)

		return
	}

	if _, err := s.store.UserByID(r.Context(), userID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			badRequest(w, "that user does not exist")

			return
		}
		s.serverError(w, r, err)

		return
	}

	if err := s.store.AddGroupMember(r.Context(), groupID, userID, role, p.UserID()); err != nil {
		s.serverError(w, r, err)

		return
	}

	s.audit(r, p, "group.member_added", "group", groupID.String(),
		map[string]any{"userId": userID.String(), "role": role})

	group, err := s.store.GroupByID(r.Context(), groupID)
	if err != nil {
		s.serverError(w, r, err)

		return
	}

	writeJSON(w, http.StatusOK, group)
}

// handleRemoveGroupMember drops a membership.
func (s *Server) handleRemoveGroupMember(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())

	groupID, ok := pathUUID(w, chi.URLParam(r, "id"))
	if !ok {
		return
	}
	userID, ok := pathUUID(w, chi.URLParam(r, "userID"))
	if !ok {
		return
	}

	allowed, err := s.canManageGroup(r, p, groupID)
	if err != nil {
		s.serverError(w, r, err)

		return
	}
	if !allowed {
		forbidden(w, "you must be an administrator or a manager of this group")

		return
	}

	if err := s.store.RemoveGroupMember(r.Context(), groupID, userID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			notFound(w)

			return
		}
		s.serverError(w, r, err)

		return
	}

	s.audit(r, p, "group.member_removed", "group", groupID.String(),
		map[string]any{"userId": userID.String()})

	w.WriteHeader(http.StatusNoContent)
}

// canManageGroup allows administrators, holders of groups:manage, the group's
// managers, and whoever created it. Creation is recorded permanently, so
// someone cannot be locked out of a group they made by being demoted or
// removed from its membership.
func (s *Server) canManageGroup(r *http.Request, p *Principal, groupID uuid.UUID) (bool, error) {
	if p.IsAdmin && p.Token == nil {
		return true, nil
	}
	if p.User == nil {
		return false, nil
	}

	if p.Can(auth.PermGroupsManage) {
		return true, nil
	}

	group, err := s.store.GroupByID(r.Context(), groupID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return false, nil
		}

		return false, err
	}
	if group.CreatedBy != nil && *group.CreatedBy == p.User.ID {
		return true, nil
	}

	role, err := s.store.GroupRole(r.Context(), groupID, p.User.ID)
	if err != nil {
		return false, err
	}

	return role == "manager", nil
}

// canSeeGroup allows anyone who can manage groups, plus the group's own members.
func (s *Server) canSeeGroup(r *http.Request, p *Principal, groupID uuid.UUID) (bool, error) {
	if p.IsAdmin || p.Can(auth.PermGroupsManage) || p.Can(auth.PermUsersManage) {
		return true, nil
	}
	if p.GroupID != nil && *p.GroupID == groupID {
		return true, nil
	}
	if p.User == nil {
		return false, nil
	}

	manages, err := s.canManageGroup(r, p, groupID)
	if err != nil || manages {
		return manages, err
	}

	role, err := s.store.GroupRole(r.Context(), groupID, p.User.ID)

	return role != "", err
}
