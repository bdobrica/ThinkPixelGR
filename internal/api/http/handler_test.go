package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/thinkpixelgr/thinkpixelgr/internal/config"
	"github.com/thinkpixelgr/thinkpixelgr/internal/domain"
	"github.com/thinkpixelgr/thinkpixelgr/internal/engine"
	"github.com/thinkpixelgr/thinkpixelgr/internal/policy"
)

func testHandler(t *testing.T) http.Handler {
	t.Helper()
	r, err := policy.NewResolver(&config.Config{})
	if err != nil {
		t.Fatal(err)
	}
	return New(engine.New(r), r)
}

func TestEvaluateRequestLimitUsesReceivedBodyBytes(t *testing.T) {
	const policyID = "limits@1"
	cfg := &config.Config{Platform: config.PlatformConfig{MandatoryPolicies: []string{policyID}}, Policies: []config.Policy{{
		Metadata: config.Metadata{ID: "limits", Version: 1}, Spec: config.PolicySpec{
			Stages: []domain.Stage{domain.StagePreModel}, Action: domain.ActionBlock,
			Detectors: []config.Detector{{ID: "request-limits@1", RequestLimits: &config.RequestLimits{MaxRequestBytes: 10}}},
		},
	}}}
	resolver, err := policy.NewResolver(cfg)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("  \n" + `{"request_id":"r1","stage":"pre_model","content":{"text":"hello"}}` + " \n")
	recorder := httptest.NewRecorder()
	New(engine.New(resolver), resolver).ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/v1/evaluations", bytes.NewReader(body)))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", recorder.Code, recorder.Body.String())
	}
	var response domain.EvaluationResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Findings) != 1 || response.Findings[0].Attributes["actual"] != float64(len(body)) {
		t.Fatalf("findings = %#v; body bytes = %d", response.Findings, len(body))
	}
}

func TestHealth(t *testing.T) {
	recorder := httptest.NewRecorder()
	testHandler(t).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/health/ready", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d", recorder.Code)
	}
}

func TestEvaluateValidatesStage(t *testing.T) {
	body := bytes.NewBufferString(`{"request_id":"r1","stage":"bad","content":{"text":"hello"}}`)
	recorder := httptest.NewRecorder()
	testHandler(t).ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/v1/evaluations", body))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d: %s", recorder.Code, recorder.Body.String())
	}
}
