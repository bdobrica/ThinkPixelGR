package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/thinkpixelgr/thinkpixelgr/internal/auth"
	"github.com/thinkpixelgr/thinkpixelgr/internal/domain"
	"github.com/thinkpixelgr/thinkpixelgr/internal/engine"
	"github.com/thinkpixelgr/thinkpixelgr/internal/observability"
	"github.com/thinkpixelgr/thinkpixelgr/internal/policy"
)

const maxBodyBytes = 1 << 20

type handler struct {
	evaluator *engine.Evaluator
	resolver  *policy.Resolver
	access    auth.Controller
	observer  observability.Observer
}

func New(evaluator *engine.Evaluator, resolver *policy.Resolver, access auth.Controller, observers ...observability.Observer) http.Handler {
	observer := observability.Observer(observability.Nop{})
	if len(observers) > 0 && observers[0] != nil {
		observer = observers[0]
	}
	h := &handler{evaluator: evaluator, resolver: resolver, access: access, observer: observer}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health/live", h.health)
	mux.HandleFunc("GET /health/ready", h.health)
	mux.Handle("GET /v1/policies", h.requireAuthentication(http.HandlerFunc(h.policies)))
	mux.Handle("POST /v1/evaluations", h.requireAuthentication(http.HandlerFunc(h.evaluate)))
	mux.Handle("GET /metrics", h.requireAuthentication(http.HandlerFunc(h.metrics)))
	return h.observeHTTP(mux)
}

func (h *handler) metrics(w http.ResponseWriter, r *http.Request) {
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok || h.access.AuthorizeMetrics(r.Context(), principal) != nil {
		writeError(w, http.StatusForbidden, "FORBIDDEN", "operation is not authorized")
		return
	}
	h.observer.MetricsHandler().ServeHTTP(w, r)
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
	started := time.Now()
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	counted := &countingReader{reader: r.Body}
	decoder := json.NewDecoder(counted)
	decoder.DisallowUnknownFields()
	var req domain.EvaluationRequest
	if err := decoder.Decode(&req); err != nil {
		h.recordRejectedEvaluation(r.Context(), req, "INVALID_REQUEST", started)
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		h.recordRejectedEvaluation(r.Context(), req, "INVALID_REQUEST", started)
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "request must contain one JSON object")
		return
	}
	if req.RequestID == "" {
		h.recordRejectedEvaluation(r.Context(), req, "INVALID_REQUEST", started)
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "request_id is required")
		return
	}
	if !req.Stage.Valid() {
		h.recordRejectedEvaluation(r.Context(), req, "INVALID_REQUEST", started)
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "stage is invalid")
		return
	}
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok || h.access.AuthorizeTenant(r.Context(), principal, req.TenantID) != nil {
		h.recordRejectedEvaluation(r.Context(), req, "FORBIDDEN", started)
		writeError(w, http.StatusForbidden, "FORBIDDEN", "tenant is not authorized")
		return
	}
	req.EncodedBytes = counted.bytes
	result, err := h.evaluator.Evaluate(r.Context(), req)
	if err != nil {
		if errors.Is(err, r.Context().Err()) {
			h.recordRejectedEvaluation(r.Context(), req, "EVALUATION_DEADLINE_EXCEEDED", started)
			writeError(w, http.StatusGatewayTimeout, "EVALUATION_DEADLINE_EXCEEDED", err.Error())
			return
		}
		h.recordRejectedEvaluation(r.Context(), req, "UNKNOWN_POLICY", started)
		writeError(w, http.StatusBadRequest, "UNKNOWN_POLICY", err.Error())
		return
	}
	h.recordCompletedEvaluation(r.Context(), principal, req, result, time.Since(started))
	writeJSON(w, http.StatusOK, result)
}

func (h *handler) requireAuthentication(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, err := h.access.Authenticate(r.Context(), r.Header.Get("Authorization"))
		if err != nil {
			h.recordAudit(r.Context(), observability.AuditEvent{Type: "api_access", Outcome: "denied", ErrorCode: "UNAUTHENTICATED", TotalMS: -1})
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeError(w, http.StatusUnauthorized, "UNAUTHENTICATED", "valid bearer authentication is required")
			return
		}
		next.ServeHTTP(w, r.WithContext(auth.WithPrincipal(r.Context(), principal)))
	})
}

func (h *handler) recordCompletedEvaluation(ctx context.Context, principal auth.Principal, req domain.EvaluationRequest, result domain.EvaluationResponse, duration time.Duration) {
	findings := make([]observability.FindingSummary, 0, len(result.Findings))
	categories := make([]string, 0, len(result.Findings))
	for _, finding := range result.Findings {
		findings = append(findings, observability.FindingSummary{DetectorID: finding.DetectorID, Category: finding.Category, Confidence: finding.Confidence, Severity: finding.Severity})
		categories = append(categories, finding.Category)
	}
	failures := failureSummaries(result.DetectorFailures)
	h.observer.RecordEvaluation(observability.EvaluationObservation{
		Stage: string(req.Stage), Outcome: "completed", Action: string(result.Decision.Action), Duration: duration,
		FindingCategories: categories, DetectorTimings: result.Timing.Detectors, Failures: failures,
	})
	h.recordAudit(ctx, observability.AuditEvent{
		Type: "evaluation", Outcome: "completed", EvaluationID: result.EvaluationID, RequestIDHash: observability.IdentifierDigest(result.RequestID),
		TenantID: req.TenantID, PrincipalID: principal.ID, Stage: string(req.Stage), Action: string(result.Decision.Action),
		AppliedPolicies: result.AppliedPolicies, Findings: findings, Failures: failures, TotalMS: result.Timing.TotalMS,
		PolicyTimingsMS: result.Timing.Policies, DetectorTimingsMS: result.Timing.Detectors,
	})
}

func (h *handler) recordRejectedEvaluation(ctx context.Context, req domain.EvaluationRequest, code string, started time.Time) {
	principal, _ := auth.PrincipalFromContext(ctx)
	duration := time.Since(started)
	h.observer.RecordEvaluation(observability.EvaluationObservation{Stage: string(req.Stage), Outcome: "rejected", Duration: duration})
	stage := ""
	if req.Stage.Valid() {
		stage = string(req.Stage)
	}
	h.recordAudit(ctx, observability.AuditEvent{
		Type: "evaluation", Outcome: "rejected", ErrorCode: code, RequestIDHash: observability.IdentifierDigest(req.RequestID),
		PrincipalID: principal.ID, Stage: stage, TotalMS: duration.Milliseconds(),
	})
}

func failureSummaries(failures []domain.DetectorFailure) []observability.FailureSummary {
	summaries := make([]observability.FailureSummary, 0, len(failures))
	for _, failure := range failures {
		summaries = append(summaries, observability.FailureSummary{
			PolicyID: failure.PolicyID, DetectorID: failure.DetectorID, Scope: string(failure.Scope),
			Code: string(failure.Code), Mode: string(failure.FailureMode),
		})
	}
	return summaries
}

func (h *handler) recordAudit(ctx context.Context, event observability.AuditEvent) {
	ctx, span := h.observer.StartSpan(ctx, "audit.emit", observability.SpanAttributes{Stage: event.Stage})
	h.observer.RecordAudit(ctx, event)
	span.End("ok")
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

func (h *handler) observeHTTP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		route := metricRoute(r.URL.Path)
		ctx := h.observer.ContinueTrace(r.Context(), r.Header.Get("traceparent"))
		ctx, span := h.observer.StartSpan(ctx, "http.server", observability.SpanAttributes{Operation: route})
		if traceparent := h.observer.Traceparent(ctx); traceparent != "" {
			w.Header().Set("traceparent", traceparent)
		}
		observed := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(observed, r.WithContext(ctx))
		h.observer.RecordHTTP(observability.HTTPObservation{Method: r.Method, Route: route, Status: observed.status})
		status := "ok"
		if observed.status >= http.StatusInternalServerError {
			status = "error"
		}
		span.End(status)
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func metricRoute(path string) string {
	switch path {
	case "/health/live", "/health/ready", "/v1/policies", "/v1/evaluations", "/metrics":
		return path
	default:
		return "unmatched"
	}
}
