package engine

import (
	"context"
	"regexp"
	"testing"

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
