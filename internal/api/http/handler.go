package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"

	"github.com/thinkpixelgr/thinkpixelgr/internal/auth"
	"github.com/thinkpixelgr/thinkpixelgr/internal/domain"
	"github.com/thinkpixelgr/thinkpixelgr/internal/engine"
	"github.com/thinkpixelgr/thinkpixelgr/internal/policy"
)

const maxBodyBytes = 1 << 20

type handler struct {
	evaluator *engine.Evaluator
	resolver  *policy.Resolver
	access    auth.Controller
}

func New(evaluator *engine.Evaluator, resolver *policy.Resolver, access auth.Controller) http.Handler {
	h := &handler{evaluator: evaluator, resolver: resolver, access: access}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health/live", h.health)
	mux.HandleFunc("GET /health/ready", h.health)
	mux.Handle("GET /v1/policies", h.requireAuthentication(http.HandlerFunc(h.policies)))
	mux.Handle("POST /v1/evaluations", h.requireAuthentication(http.HandlerFunc(h.evaluate)))
	return requestLog(mux)
}

func (h *handler) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *handler) policies(w http.ResponseWriter, r *http.Request) {
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok || h.access.AuthorizePolicyList(r.Context(), principal) != nil {
		writeError(w, http.StatusForbidden, "FORBIDDEN", "operation is not authorized")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"policies": h.resolver.PolicyIDs()})
}

func (h *handler) evaluate(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	counted := &countingReader{reader: r.Body}
	decoder := json.NewDecoder(counted)
	decoder.DisallowUnknownFields()
	var req domain.EvaluationRequest
	if err := decoder.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "request must contain one JSON object")
		return
	}
	if req.RequestID == "" {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "request_id is required")
		return
	}
	if !req.Stage.Valid() {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "stage is invalid")
		return
	}
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok || h.access.AuthorizeTenant(r.Context(), principal, req.TenantID) != nil {
		writeError(w, http.StatusForbidden, "FORBIDDEN", "tenant is not authorized")
		return
	}
	req.EncodedBytes = counted.bytes
	result, err := h.evaluator.Evaluate(r.Context(), req)
	if err != nil {
		if errors.Is(err, r.Context().Err()) {
			writeError(w, http.StatusGatewayTimeout, "EVALUATION_DEADLINE_EXCEEDED", err.Error())
			return
		}
		writeError(w, http.StatusBadRequest, "UNKNOWN_POLICY", err.Error())
		return
	}
	slog.Info("evaluation completed", "evaluation_id", result.EvaluationID, "request_id", result.RequestID, "action", result.Decision.Action, "findings", len(result.Findings), "detector_failures", len(result.DetectorFailures), "duration_ms", result.Timing.TotalMS)
	writeJSON(w, http.StatusOK, result)
}

func (h *handler) requireAuthentication(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, err := h.access.Authenticate(r.Context(), r.Header.Get("Authorization"))
		if err != nil {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeError(w, http.StatusUnauthorized, "UNAUTHENTICATED", "valid bearer authentication is required")
			return
		}
		next.ServeHTTP(w, r.WithContext(auth.WithPrincipal(r.Context(), principal)))
	})
}

type countingReader struct {
	reader io.Reader
	bytes  int
}

func (r *countingReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	r.bytes += n
	return n, err
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{"error": map[string]any{"code": code, "message": message, "retryable": false}})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func requestLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slog.Debug("http request", "method", r.Method, "path", r.URL.Path)
		next.ServeHTTP(w, r)
	})
}
