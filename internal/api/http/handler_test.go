package httpapi

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/thinkpixelgr/thinkpixelgr/internal/config"
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
