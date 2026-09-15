package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/thinkpixelgr/thinkpixelgr/internal/auth"
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
	return New(engine.New(r), r, auth.Disabled{})
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
	New(engine.New(resolver), resolver, auth.Disabled{}).ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/v1/evaluations", bytes.NewReader(body)))
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

func TestEvaluateReturnsGatewayTimeoutForCallerCancellation(t *testing.T) {
	body := bytes.NewBufferString(`{"request_id":"r1","stage":"pre_model","content":{"text":"hello"}}`)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	request := httptest.NewRequest(http.MethodPost, "/v1/evaluations", body).WithContext(ctx)
	recorder := httptest.NewRecorder()
	testHandler(t).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusGatewayTimeout {
		t.Fatalf("status = %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestHealthDoesNotRequireAuthentication(t *testing.T) {
	handler, _ := securedTestHandler(t, config.AuthPrincipal{ID: "gateway", TokenEnv: "TEST_TOKEN"})
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/health/live", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestEvaluationRequiresValidBearerAuthentication(t *testing.T) {
	handler, token := securedTestHandler(t, config.AuthPrincipal{ID: "gateway", TokenEnv: "TEST_TOKEN", Tenants: []string{"demo"}})
	body := `{"request_id":"r1","stage":"pre_model","tenant_id":"demo","content":{"text":"hello"}}`
	for _, header := range []string{"", "Bearer invalid"} {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, "/v1/evaluations", strings.NewReader(body))
		request.Header.Set("Authorization", header)
		handler.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusUnauthorized {
			t.Errorf("header %q status = %d: %s", header, recorder.Code, recorder.Body.String())
		}
		if recorder.Header().Get("WWW-Authenticate") != "Bearer" {
			t.Errorf("header %q challenge = %q", header, recorder.Header().Get("WWW-Authenticate"))
		}
	}

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/v1/evaluations", strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+token)
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("valid credential status = %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestEvaluationTenantAuthorizationIgnoresCallerSuppliedRoles(t *testing.T) {
	handler, token := securedTestHandler(t, config.AuthPrincipal{ID: "gateway", TokenEnv: "TEST_TOKEN", Tenants: []string{"tenant-a"}})
	body := `{"request_id":"r1","stage":"pre_model","tenant_id":"tenant-b","subject":{"roles":["admin","tenant-b-owner"]},"content":{"text":"hello"}}`
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/v1/evaluations", strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+token)
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestTenantlessEvaluationRequiresExplicitScope(t *testing.T) {
	body := `{"request_id":"r1","stage":"pre_model","content":{"text":"hello"}}`
	for _, allowTenantless := range []bool{false, true} {
		handler, token := securedTestHandler(t, config.AuthPrincipal{
			ID: "gateway", TokenEnv: "TEST_TOKEN", AllowTenantless: allowTenantless,
		})
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, "/v1/evaluations", strings.NewReader(body))
		request.Header.Set("Authorization", "Bearer "+token)
		handler.ServeHTTP(recorder, request)
		want := http.StatusForbidden
		if allowTenantless {
			want = http.StatusOK
		}
		if recorder.Code != want {
			t.Errorf("allowTenantless=%t status = %d: %s", allowTenantless, recorder.Code, recorder.Body.String())
		}
	}
}

func TestPolicyEnumerationRequiresExplicitCapability(t *testing.T) {
	for _, policyReader := range []bool{false, true} {
		handler, token := securedTestHandler(t, config.AuthPrincipal{
			ID: "gateway", TokenEnv: "TEST_TOKEN", Tenants: []string{"demo"}, PolicyReader: policyReader,
		})
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/v1/policies", nil)
		request.Header.Set("Authorization", "Bearer "+token)
		handler.ServeHTTP(recorder, request)
		want := http.StatusForbidden
		if policyReader {
			want = http.StatusOK
		}
		if recorder.Code != want {
			t.Errorf("policyReader=%t status = %d: %s", policyReader, recorder.Code, recorder.Body.String())
		}
	}
}

func securedTestHandler(t *testing.T, principal config.AuthPrincipal) (http.Handler, string) {
	t.Helper()
	token := strings.Repeat("t", 32)
	access, err := auth.NewStaticBearer(config.AuthConfig{Enabled: true, Principals: []config.AuthPrincipal{principal}}, func(name string) (string, bool) {
		return token, name == principal.TokenEnv
	})
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := policy.NewResolver(&config.Config{})
	if err != nil {
		t.Fatal(err)
	}
	return New(engine.New(resolver), resolver, access), token
}
