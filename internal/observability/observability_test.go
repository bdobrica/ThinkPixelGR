package observability

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestMetricsUseBoundedDimensionsAndPrometheusHistograms(t *testing.T) {
	service := New(slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))
	service.RecordHTTP(HTTPObservation{Method: http.MethodPost, Route: "/v1/evaluations", Status: http.StatusOK})
	service.RecordEvaluation(EvaluationObservation{
		Stage: "pre_model", Outcome: "completed", Action: "redact", Duration: 12 * time.Millisecond,
		FindingCategories: []string{"pii.email"}, DetectorTimings: map[string]int64{"builtin/email@1": 4},
		Failures: []FailureSummary{{Code: "DETECTOR_TIMEOUT", Mode: "closed"}},
	})
	recorder := httptest.NewRecorder()
	service.MetricsHandler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := recorder.Body.String()
	for _, expected := range []string{
		`thinkpixelgr_http_requests_total{method="POST",route="/v1/evaluations",status="200"} 1`,
		`thinkpixelgr_evaluations_total{action="redact",outcome="completed",stage="pre_model"} 1`,
		`thinkpixelgr_evaluation_duration_seconds_bucket{stage="pre_model",le="0.025"} 1`,
		`thinkpixelgr_detector_duration_seconds_count{detector="builtin/email@1"} 1`,
		`thinkpixelgr_findings_total{category="pii.email"} 1`,
		`thinkpixelgr_detector_failures_total{code="DETECTOR_TIMEOUT",failure_mode="closed"} 1`,
	} {
		if !strings.Contains(body, expected) {
			t.Errorf("metrics missing %q:\n%s", expected, body)
		}
	}
	for _, forbidden := range []string{"request_id", "tenant_id", "principal_id", "content"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("metrics contain forbidden dimension %q", forbidden)
		}
	}
}

func TestAuditUsesAllowlistedStructuredFields(t *testing.T) {
	var output bytes.Buffer
	service := New(slog.New(slog.NewJSONHandler(&output, nil)))
	ctx := service.ContinueTrace(context.Background(), "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	ctx, span := service.StartSpan(ctx, "audit.emit", SpanAttributes{})
	service.RecordAudit(ctx, AuditEvent{
		Type: "evaluation", Outcome: "completed", EvaluationID: "eval-1", RequestIDHash: IdentifierDigest("req-1"),
		TenantID: "tenant-a", PrincipalID: "gateway", Stage: "pre_model", Action: "allow",
		AppliedPolicies: []string{}, Findings: []FindingSummary{}, Failures: []FailureSummary{}, TotalMS: 1,
	})
	span.End("ok")
	log := output.String()
	for _, expected := range []string{AuditSchemaVersion, `"event_type":"evaluation"`, `"trace_id":"4bf92f3577b34da6a3ce929d0e0e4736"`, `"request_id_hash":"sha256:`} {
		if !strings.Contains(log, expected) {
			t.Errorf("audit log missing %q: %s", expected, log)
		}
	}
}

func TestMetricEnumsCollapseUntrustedValues(t *testing.T) {
	service := New(slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))
	secret := "raw-secret-MUST-NOT-BECOME-A-LABEL"
	service.RecordEvaluation(EvaluationObservation{Stage: secret, Outcome: secret, Action: secret, Failures: []FailureSummary{{Code: secret, Mode: secret}}})
	recorder := httptest.NewRecorder()
	service.MetricsHandler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if strings.Contains(recorder.Body.String(), secret) {
		t.Fatalf("metrics exposed untrusted value: %s", recorder.Body.String())
	}
}

func TestInvalidTraceparentIsNotPropagated(t *testing.T) {
	service := New(slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))
	ctx := service.ContinueTrace(context.Background(), "00-raw-secret-that-is-not-a-valid-traceparent")
	ctx, span := service.StartSpan(ctx, "http.server", SpanAttributes{})
	defer span.End("ok")
	traceparent := service.Traceparent(ctx)
	if traceparent == "" || strings.Contains(traceparent, "raw-secret") || len(traceparent) != 55 {
		t.Fatalf("traceparent = %q", traceparent)
	}
}
