package api

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/google/uuid"
)

// errorBody is the single error shape every endpoint returns.
type errorBody struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if body == nil {
		return
	}
	if err := json.NewEncoder(w).Encode(body); err != nil {
		slog.Error("write response", "error", err)
	}
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, errorBody{Error: code, Message: message})
}

func badRequest(w http.ResponseWriter, message string) {
	writeError(w, http.StatusBadRequest, "bad_request", message)
}

func notFound(w http.ResponseWriter) {
	writeError(w, http.StatusNotFound, "not_found", "the requested item does not exist or is not visible to you")
}

func forbidden(w http.ResponseWriter, message string) {
	writeError(w, http.StatusForbidden, "forbidden", message)
}

func unauthorized(w http.ResponseWriter, message string) {
	writeError(w, http.StatusUnauthorized, "unauthorized", message)
}

func conflict(w http.ResponseWriter, message string) {
	writeError(w, http.StatusConflict, "conflict", message)
}

// serverError logs the cause and returns an opaque message to the caller.
func (s *Server) serverError(w http.ResponseWriter, r *http.Request, err error) {
	s.log.Error("request failed", "method", r.Method, "path", r.URL.Path, "error", err)
	writeError(w, http.StatusInternalServerError, "internal_error", "something went wrong on the server")
}

// decode reads a JSON body, rejecting unknown fields so typos surface early.
func decode(r *http.Request, dst any) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return errors.New("request body is not valid JSON for this endpoint")
	}

	return nil
}

// pathUUID parses a UUID path parameter, writing a 400 when it is malformed.
func pathUUID(w http.ResponseWriter, raw string) (uuid.UUID, bool) {
	id, err := uuid.Parse(raw)
	if err != nil {
		badRequest(w, "identifier in the URL is not a valid UUID")

		return uuid.Nil, false
	}

	return id, true
}
