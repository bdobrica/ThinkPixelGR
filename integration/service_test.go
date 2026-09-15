package integration_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	httpapi "github.com/thinkpixelgr/thinkpixelgr/internal/api/http"
	"github.com/thinkpixelgr/thinkpixelgr/internal/auth"
	"github.com/thinkpixelgr/thinkpixelgr/internal/config"
	"github.com/thinkpixelgr/thinkpixelgr/internal/engine"
	"github.com/thinkpixelgr/thinkpixelgr/internal/observability"
	"github.com/thinkpixelgr/thinkpixelgr/internal/policy"
)

func TestAuthenticatedEvaluationConformsToPublicContract(t *testing.T) {
	const (
		rawContent  = "Contact sensitive.person@example.test"
		traceID     = "4bf92f3577b34da6a3ce929d0e0e4736"
		traceparent = "00-" + traceID + "-00f067aa0ba902b7-01"
	)
	token := strings.Repeat("t", 32)
	t.Setenv("THINKPIXELGR_DEMO_TOKEN", token)

	cfg, err := config.Load("../configs/config.yaml")
	if err != nil {
		t.Fatalf("load example config: %v", err)
	}
	resolver, err := policy.NewResolver(cfg)
	if err != nil {
		t.Fatalf("compile example policies: %v", err)
	}
	access, err := auth.NewStaticBearer(cfg.Auth, os.LookupEnv)
	if err != nil {
		t.Fatalf("configure authentication: %v", err)
	}
	var logs bytes.Buffer
	observer := observability.New(slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	handler := httpapi.New(engine.New(resolver, observer), resolver, access, observer)

	contract := loadContract(t)
	assertStatus(t, doRequest(t, handler, http.MethodGet, "/health/live", "", "", ""), http.StatusOK)

	requestBody := []byte(`{"request_id":"integration-1","stage":"pre_model","tenant_id":"demo","guardrails":{"profile":"baseline@1"},"content":{"text":"` + rawContent + `"}}`)
	validateRequestBody(t, contract, "/v1/evaluations", requestBody)

	unauthenticated := doRequest(t, handler, http.MethodPost, "/v1/evaluations", string(requestBody), "", "")
	assertStatus(t, unauthenticated, http.StatusUnauthorized)
	validateResponseBody(t, contract, "/v1/evaluations", http.StatusUnauthorized, unauthenticated.body)

	forbiddenBody := strings.Replace(string(requestBody), `"tenant_id":"demo"`, `"tenant_id":"other","subject":{"roles":["admin"]}`, 1)
	forbidden := doRequest(t, handler, http.MethodPost, "/v1/evaluations", forbiddenBody, token, "")
	assertStatus(t, forbidden, http.StatusForbidden)
	validateResponseBody(t, contract, "/v1/evaluations", http.StatusForbidden, forbidden.body)

	completed := doRequest(t, handler, http.MethodPost, "/v1/evaluations", string(requestBody), token, traceparent)
	assertStatus(t, completed, http.StatusOK)
	validateResponseBody(t, contract, "/v1/evaluations", http.StatusOK, completed.body)
	if got := completed.header.Get("traceparent"); !strings.HasPrefix(got, "00-"+traceID+"-") {
		t.Fatalf("response traceparent = %q", got)
	}
	response := decodeJSON(t, completed.body).(map[string]any)
	decision := response["decision"].(map[string]any)
	if decision["action"] != "redact" {
		t.Fatalf("decision = %#v", decision)
	}
	if strings.Contains(string(completed.body), "sensitive.person@example.test") {
		t.Fatalf("response transformation retained sensitive content: %s", completed.body)
	}

	metrics := doRequest(t, handler, http.MethodGet, "/metrics", "", token, "")
	assertStatus(t, metrics, http.StatusOK)
	for _, metric := range []string{"thinkpixelgr_evaluations_total", "thinkpixelgr_findings_total", "thinkpixelgr_evaluation_duration_seconds"} {
		if !strings.Contains(string(metrics.body), metric) {
			t.Errorf("metrics missing %q", metric)
		}
	}
	observabilityOutput := logs.String() + string(metrics.body)
	if strings.Contains(observabilityOutput, rawContent) || strings.Contains(observabilityOutput, token) {
		t.Fatal("audit, metrics, or trace output exposed evaluated content or credentials")
	}
	if !strings.Contains(logs.String(), observability.AuditSchemaVersion) {
		t.Fatal("completed flow did not emit the versioned audit event")
	}
}

type response struct {
	status int
	header http.Header
	body   []byte
}

func doRequest(t *testing.T, handler http.Handler, method, path, body, token, traceparent string) response {
	t.Helper()
	request := httptest.NewRequest(method, "http://thinkpixel.test"+path, strings.NewReader(body))
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	if traceparent != "" {
		request.Header.Set("traceparent", traceparent)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return response{status: recorder.Code, header: recorder.Header().Clone(), body: recorder.Body.Bytes()}
}

func assertStatus(t *testing.T, response response, expected int) {
	t.Helper()
	if response.status != expected {
		t.Fatalf("status = %d, want %d: %s", response.status, expected, response.body)
	}
}

func loadContract(t *testing.T) *openapi3.T {
	t.Helper()
	document, err := openapi3.NewLoader().LoadFromFile("../api/openapi.yaml")
	if err != nil {
		t.Fatalf("load public contract: %v", err)
	}
	if err := document.Validate(context.Background()); err != nil {
		t.Fatalf("validate public contract: %v", err)
	}
	return document
}

func validateRequestBody(t *testing.T, document *openapi3.T, path string, body []byte) {
	t.Helper()
	operation := document.Paths.Find(path).Post
	schema := operation.RequestBody.Value.Content.Get("application/json").Schema.Value
	if err := schema.VisitJSON(decodeJSON(t, body), openapi3.VisitAsRequest()); err != nil {
		t.Fatalf("request does not conform to %s: %v", path, err)
	}
}

func validateResponseBody(t *testing.T, document *openapi3.T, path string, status int, body []byte) {
	t.Helper()
	operation := document.Paths.Find(path).Post
	contractResponse := operation.Responses.Status(status)
	if contractResponse == nil || contractResponse.Value == nil {
		t.Fatalf("contract has no response for %s status %d", path, status)
	}
	schema := contractResponse.Value.Content.Get("application/json").Schema.Value
	if err := schema.VisitJSON(decodeJSON(t, body), openapi3.VisitAsResponse()); err != nil {
		t.Fatalf("response does not conform to %s status %d: %v\n%s", path, status, err, body)
	}
}

func decodeJSON(t *testing.T, body []byte) any {
	t.Helper()
	var value any
	if err := json.Unmarshal(body, &value); err != nil {
		t.Fatalf("decode JSON: %v\n%s", err, body)
	}
	return value
}
