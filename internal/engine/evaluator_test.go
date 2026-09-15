package engine

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/thinkpixelgr/thinkpixelgr/internal/config"
	"github.com/thinkpixelgr/thinkpixelgr/internal/domain"
	"github.com/thinkpixelgr/thinkpixelgr/internal/policy"
)

func TestEvaluatorRedactsMandatoryPolicy(t *testing.T) {
	cfg := &config.Config{
		Platform: config.PlatformConfig{MandatoryPolicies: []string{"platform/email@1"}},
		Policies: []config.Policy{{Metadata: config.Metadata{ID: "platform/email", Version: 1}, Spec: config.PolicySpec{
			Stages: []domain.Stage{domain.StagePreModel}, Action: domain.ActionRedact,
			Detectors: []config.Detector{{ID: "email@1", Regex: &config.Regex{Pattern: `[^ ]+@[^ ]+`, Category: "pii.email", Replacement: "<EMAIL>"}}},
		}}},
	}
	resolver, err := policy.NewResolver(cfg)
	if err != nil {
		t.Fatal(err)
	}
	result, err := New(resolver).Evaluate(context.Background(), domain.EvaluationRequest{
		RequestID: "req_1", Stage: domain.StagePreModel,
		Content: domain.ContentEnvelope{Messages: []domain.Message{{Role: "user", Content: "email me at person@example.com"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Decision.Action != domain.ActionRedact {
		t.Fatalf("action = %q", result.Decision.Action)
	}
	got := result.Decision.TransformedContent.Messages[0].Content
	if got != "email me at <EMAIL>" {
		t.Fatalf("content = %q", got)
	}
	if len(result.Findings) != 1 || result.Findings[0].Locations[0].Start != 12 {
		t.Fatalf("findings = %#v", result.Findings)
	}
}

func TestRequestLimitsDetector(t *testing.T) {
	detector := config.Detector{ID: "limits@1", RequestLimits: &config.RequestLimits{
		MaxRequestBytes: 100, MaxMessages: 1, MaxMessageBytes: 3, MaxTools: 1,
		MaxAttachments: 1, MaxEstimatedTokens: 2, AllowedMIMETypes: []string{"text/plain"},
	}}
	result := evaluateSingle(t, detector, domain.EvaluationRequest{
		EncodedBytes: 101,
		Content: domain.ContentEnvelope{Type: "application/json", Messages: []domain.Message{{Content: "long"}, {Content: "also long"}}, Data: map[string]any{
			"tools": []any{"a", "b"}, "attachments": []any{map[string]any{"mime_type": "image/png"}, map[string]any{}},
		}},
	})
	if result.Decision.Action != domain.ActionBlock || len(result.Findings) != 10 {
		t.Fatalf("action/findings = %q/%#v", result.Decision.Action, result.Findings)
	}
	for _, finding := range result.Findings {
		if finding.Category != "request.limit" || finding.Attributes["limit"] == nil {
			t.Fatalf("finding = %#v", finding)
		}
	}
}

func TestAllowDenyDetector(t *testing.T) {
	tests := []struct {
		name     string
		selector string
		allow    []string
		deny     []string
		req      domain.EvaluationRequest
	}{
		{"model allowlist", "target.model", []string{"approved"}, nil, domain.EvaluationRequest{Target: map[string]any{"model": "other"}}},
		{"role denylist", "subject.roles", nil, []string{"admin"}, domain.EvaluationRequest{Subject: map[string]any{"roles": []any{"Admin"}}}},
		{"tool denylist", "content.tools", nil, []string{"shell"}, domain.EvaluationRequest{Content: domain.ContentEnvelope{Data: map[string]any{"tools": []any{map[string]any{"name": "shell"}}}}}},
		{"domain denylist", "content.domains", nil, []string{"example.test"}, domain.EvaluationRequest{Content: domain.ContentEnvelope{Data: map[string]any{"domains": []any{"example.test"}}}}},
		{"file type allowlist", "content.file_types", []string{"pdf"}, nil, domain.EvaluationRequest{Content: domain.ContentEnvelope{Data: map[string]any{"attachments": []any{map[string]any{"file_type": "exe"}}}}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			detector := config.Detector{ID: "list@1", AllowDeny: &config.AllowDeny{Selector: tt.selector, Allow: tt.allow, Deny: tt.deny}}
			result := evaluateSingle(t, detector, tt.req)
			if len(result.Findings) != 1 || result.Findings[0].Attributes["selector"] != tt.selector {
				t.Fatalf("findings = %#v", result.Findings)
			}
		})
	}
}

func TestJSONSchemaDetector(t *testing.T) {
	detector := config.Detector{ID: "schema@1", JSONSchema: &config.JSONSchema{Target: "content.data", Schema: map[string]any{
		"type": "object", "required": []any{"count"}, "properties": map[string]any{"count": map[string]any{"type": "integer", "minimum": 1}},
	}}}
	invalid := evaluateSingle(t, detector, domain.EvaluationRequest{Content: domain.ContentEnvelope{Data: map[string]any{"count": 0}}})
	if len(invalid.Findings) != 1 || invalid.Findings[0].Category != "schema.invalid" || invalid.Findings[0].Attributes["instance_location"] != "/count" {
		t.Fatalf("invalid findings = %#v", invalid.Findings)
	}
	valid := evaluateSingle(t, detector, domain.EvaluationRequest{Content: domain.ContentEnvelope{Data: map[string]any{"count": 1}}})
	if len(valid.Findings) != 0 {
		t.Fatalf("valid findings = %#v", valid.Findings)
	}
}

func TestStructuredSecretDetectorRedactsNestedData(t *testing.T) {
	detector := config.Detector{ID: "secrets@1", Secrets: &config.Secrets{}}
	original := "token = AbCdEfGhIjKlMnOpQrStUvWxYz012345"
	request := domain.EvaluationRequest{Content: domain.ContentEnvelope{Data: map[string]any{"credentials": []any{
		"Authorization: Bearer abcdefghijklmnopqrst", original, "AKIAABCDEFGHIJKLMNOP",
		"postgres://user:password@db.example.test/app",
		"-----BEGIN PRIVATE KEY-----\nZmFrZQ==\n-----END PRIVATE KEY-----",
	}}}}
	result := evaluateSingleWithAction(t, detector, request, domain.ActionRedact)
	if len(result.Findings) != 5 {
		t.Fatalf("findings = %#v", result.Findings)
	}
	transformed := result.Decision.TransformedContent.Data["credentials"].([]any)
	if transformed[0] != "<SECRET>" || transformed[1] != "token = <SECRET>" || transformed[2] != "<SECRET>" || transformed[3] != "<SECRET>" || transformed[4] != "<SECRET>" {
		t.Fatalf("transformed = %#v", transformed)
	}
	if request.Content.Data["credentials"].([]any)[1] != original {
		t.Fatal("evaluation mutated request content")
	}
	for _, finding := range result.Findings {
		if strings.Contains(toString(finding.Attributes), "AbCdEf") {
			t.Fatalf("finding leaked a secret: %#v", finding)
		}
	}
}

func TestEntropySecretRequiresContext(t *testing.T) {
	detector := config.Detector{ID: "secrets@1", Secrets: &config.Secrets{Types: []string{"contextual_high_entropy"}}}
	result := evaluateSingle(t, detector, domain.EvaluationRequest{Content: domain.ContentEnvelope{Text: "AbCdEfGhIjKlMnOpQrStUvWxYz012345"}})
	if len(result.Findings) != 0 {
		t.Fatalf("findings = %#v", result.Findings)
	}
}

func TestDetectorTimeoutFailureModes(t *testing.T) {
	tests := []struct {
		mode   domain.FailureMode
		action domain.Action
	}{
		{domain.FailureOpen, domain.ActionAllow},
		{domain.FailureClosed, domain.ActionBlock},
		{domain.FailureMonitor, domain.ActionMonitor},
	}
	for _, tt := range tests {
		t.Run(string(tt.mode), func(t *testing.T) {
			resolver := deadlineResolver(t, 100*time.Millisecond, 5*time.Millisecond, tt.mode, []config.Detector{{ID: "slow", Keywords: &config.Keywords{Values: []string{"x"}}}})
			evaluator := &Evaluator{resolver: resolver, executor: executorFunc(func(ctx context.Context, _ policy.CompiledDetector, _ domain.EvaluationRequest) (detectorResult, error) {
				<-ctx.Done()
				return detectorResult{}, ctx.Err()
			})}
			result, err := evaluator.Evaluate(context.Background(), domain.EvaluationRequest{RequestID: "req", Stage: domain.StagePreModel})
			if err != nil {
				t.Fatal(err)
			}
			if result.Decision.Action != tt.action {
				t.Fatalf("action = %q, want %q", result.Decision.Action, tt.action)
			}
			if len(result.DetectorFailures) != 1 {
				t.Fatalf("failures = %#v", result.DetectorFailures)
			}
			failure := result.DetectorFailures[0]
			if failure.Code != domain.FailureDetectorTimeout || failure.Scope != domain.FailureScopeDetector || failure.FailureMode != tt.mode || failure.TimeoutMS != 5 || !failure.Retryable {
				t.Fatalf("failure = %#v", failure)
			}
		})
	}
}

func TestPolicyTimeoutStopsRemainingDetectors(t *testing.T) {
	detectors := []config.Detector{
		{ID: "slow", Timeout: 5 * time.Millisecond, Keywords: &config.Keywords{Values: []string{"x"}}},
		{ID: "must-not-run", Timeout: 5 * time.Millisecond, Keywords: &config.Keywords{Values: []string{"x"}}},
	}
	resolver := deadlineResolver(t, 5*time.Millisecond, 0, domain.FailureClosed, detectors)
	calls := 0
	evaluator := &Evaluator{resolver: resolver, executor: executorFunc(func(ctx context.Context, _ policy.CompiledDetector, _ domain.EvaluationRequest) (detectorResult, error) {
		calls++
		<-ctx.Done()
		return detectorResult{}, ctx.Err()
	})}
	result, err := evaluator.Evaluate(context.Background(), domain.EvaluationRequest{RequestID: "req", Stage: domain.StagePreModel})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("executor calls = %d, want 1", calls)
	}
	if result.Decision.Action != domain.ActionBlock || len(result.DetectorFailures) != 1 {
		t.Fatalf("result = %#v", result)
	}
	failure := result.DetectorFailures[0]
	if failure.Code != domain.FailurePolicyTimeout || failure.Scope != domain.FailureScopePolicy || failure.TimeoutMS != 5 {
		t.Fatalf("failure = %#v", failure)
	}
}

func TestDetectorFailureContinuesWithinPolicyBudget(t *testing.T) {
	detectors := []config.Detector{
		{ID: "unavailable", Keywords: &config.Keywords{Values: []string{"x"}}},
		{ID: "finding", Keywords: &config.Keywords{Values: []string{"x"}}},
	}
	resolver := deadlineResolver(t, 100*time.Millisecond, 20*time.Millisecond, domain.FailureOpen, detectors)
	calls := 0
	evaluator := &Evaluator{resolver: resolver, executor: executorFunc(func(_ context.Context, detector policy.CompiledDetector, _ domain.EvaluationRequest) (detectorResult, error) {
		calls++
		if detector.Config.ID == "unavailable" {
			return detectorResult{}, &DetectorError{Code: domain.FailureDetectorUnavailable, Retryable: true}
		}
		return detectorResult{findings: []domain.Finding{{DetectorID: detector.Config.ID, Category: "test", Confidence: 1}}}, nil
	})}
	result, err := evaluator.Evaluate(context.Background(), domain.EvaluationRequest{RequestID: "req", Stage: domain.StagePreModel})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 || len(result.DetectorFailures) != 1 || len(result.Findings) != 1 || result.Decision.Action != domain.ActionBlock {
		t.Fatalf("calls=%d result=%#v", calls, result)
	}
}

func TestTypedDetectorFailureIsReportedWithoutRawError(t *testing.T) {
	resolver := deadlineResolver(t, 100*time.Millisecond, 20*time.Millisecond, domain.FailureOpen, []config.Detector{{ID: "remote", Keywords: &config.Keywords{Values: []string{"x"}}}})
	evaluator := &Evaluator{resolver: resolver, executor: executorFunc(func(context.Context, policy.CompiledDetector, domain.EvaluationRequest) (detectorResult, error) {
		return detectorResult{}, &DetectorError{Code: domain.FailureDetectorUnavailable, Retryable: true, Err: errors.New("upstream included sensitive diagnostics")}
	})}
	result, err := evaluator.Evaluate(context.Background(), domain.EvaluationRequest{RequestID: "req", Stage: domain.StagePreModel})
	if err != nil {
		t.Fatal(err)
	}
	encoded := fmt.Sprint(result.DetectorFailures)
	if strings.Contains(encoded, "sensitive diagnostics") {
		t.Fatalf("failure leaked raw error: %s", encoded)
	}
	if len(result.DetectorFailures) != 1 || result.DetectorFailures[0].Code != domain.FailureDetectorUnavailable || !result.DetectorFailures[0].Retryable {
		t.Fatalf("failures = %#v", result.DetectorFailures)
	}
}

func TestCallerCancellationAbortsEvaluation(t *testing.T) {
	resolver := deadlineResolver(t, 100*time.Millisecond, 20*time.Millisecond, domain.FailureClosed, []config.Detector{{ID: "detector", Keywords: &config.Keywords{Values: []string{"x"}}}})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := (&Evaluator{resolver: resolver, executor: builtinExecutor{}}).Evaluate(ctx, domain.EvaluationRequest{RequestID: "req", Stage: domain.StagePreModel})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v", err)
	}
}

type executorFunc func(context.Context, policy.CompiledDetector, domain.EvaluationRequest) (detectorResult, error)

func (fn executorFunc) Evaluate(ctx context.Context, detector policy.CompiledDetector, req domain.EvaluationRequest) (detectorResult, error) {
	return fn(ctx, detector, req)
}

func deadlineResolver(t *testing.T, policyTimeout, detectorTimeout time.Duration, mode domain.FailureMode, detectors []config.Detector) *policy.Resolver {
	t.Helper()
	for i := range detectors {
		if detectors[i].Timeout == 0 {
			detectors[i].Timeout = detectorTimeout
		}
	}
	const policyID = "test/deadline@1"
	resolver, err := policy.NewResolver(&config.Config{
		Platform: config.PlatformConfig{MandatoryPolicies: []string{policyID}},
		Policies: []config.Policy{{Metadata: config.Metadata{ID: "test/deadline", Version: 1}, Spec: config.PolicySpec{
			Stages: []domain.Stage{domain.StagePreModel}, Action: domain.ActionBlock, FailureMode: mode,
			Timeout: policyTimeout, Detectors: detectors,
		}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return resolver
}

func evaluateSingle(t *testing.T, detector config.Detector, req domain.EvaluationRequest) domain.EvaluationResponse {
	t.Helper()
	return evaluateSingleWithAction(t, detector, req, domain.ActionBlock)
}

func evaluateSingleWithAction(t *testing.T, detector config.Detector, req domain.EvaluationRequest, action domain.Action) domain.EvaluationResponse {
	t.Helper()
	const policyID = "test/policy@1"
	cfg := &config.Config{Platform: config.PlatformConfig{MandatoryPolicies: []string{policyID}}, Policies: []config.Policy{{
		Metadata: config.Metadata{ID: "test/policy", Version: 1}, Spec: config.PolicySpec{Stages: []domain.Stage{domain.StagePreModel}, Action: action, Detectors: []config.Detector{detector}},
	}}}
	resolver, err := policy.NewResolver(cfg)
	if err != nil {
		t.Fatal(err)
	}
	req.RequestID = "req_test"
	req.Stage = domain.StagePreModel
	result, err := New(resolver).Evaluate(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func toString(value any) string { return fmt.Sprint(value) }

func TestApplyReplacementsHandlesOverlap(t *testing.T) {
	content := domain.ContentEnvelope{Text: "abcdef"}
	got := applyReplacements(content, []replacement{{path: "content.text", start: 1, end: 5, value: "X"}, {path: "content.text", start: 2, end: 4, value: "Y"}})
	if got.Text != "aXf" {
		t.Fatalf("text = %q", got.Text)
	}
}

func TestRegexUsesByteOffsets(t *testing.T) {
	re := regexp.MustCompile("é")
	spans := re.FindAllStringIndex("aé", -1)
	if spans[0][0] != 1 || spans[0][1] != 3 {
		t.Fatal(spans)
	}
}
