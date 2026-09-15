package policy

import (
	"testing"
	"time"

	"github.com/thinkpixelgr/thinkpixelgr/internal/config"
	"github.com/thinkpixelgr/thinkpixelgr/internal/domain"
)

func TestResolveDeduplicatesAndFiltersStage(t *testing.T) {
	cfg := &config.Config{
		Platform: config.PlatformConfig{MandatoryPolicies: []string{"mandatory@1"}},
		Policies: []config.Policy{
			{Metadata: config.Metadata{ID: "mandatory", Version: 1}, Spec: config.PolicySpec{Stages: []domain.Stage{domain.StagePreModel}, Action: domain.ActionBlock, Detectors: []config.Detector{{ID: "d1", Keywords: &config.Keywords{Values: []string{"x"}, Category: "x"}}}}},
			{Metadata: config.Metadata{ID: "output", Version: 1}, Spec: config.PolicySpec{Stages: []domain.Stage{domain.StagePostModel}, Action: domain.ActionMonitor, Detectors: []config.Detector{{ID: "d2", Keywords: &config.Keywords{Values: []string{"x"}, Category: "x"}}}}},
		},
	}
	r, err := NewResolver(cfg)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := r.Resolve("", "", []string{"mandatory@1", "output@1"}, domain.StagePreModel)
	if err != nil {
		t.Fatal(err)
	}
	if len(resolved) != 1 || resolved[0].Config.CanonicalID() != "mandatory@1" {
		t.Fatalf("resolved = %#v", resolved)
	}
}

func TestResolverRejectsInvalidRegex(t *testing.T) {
	cfg := &config.Config{Policies: []config.Policy{{Metadata: config.Metadata{ID: "bad", Version: 1}, Spec: config.PolicySpec{Action: domain.ActionBlock, Detectors: []config.Detector{{ID: "bad", Regex: &config.Regex{Pattern: "["}}}}}}}
	if _, err := NewResolver(cfg); err == nil {
		t.Fatal("expected error")
	}
}

func TestMatchKeywordCaseInsensitive(t *testing.T) {
	got := MatchKeyword("Please IGNORE this", "ignore", false)
	if len(got) != 1 || got[0] != [2]int{7, 13} {
		t.Fatalf("spans = %#v", got)
	}
}

func TestResolverCompilesAllDeterministicDetectorTypes(t *testing.T) {
	detectors := []config.Detector{
		{ID: "limits", RequestLimits: &config.RequestLimits{MaxMessages: 1}},
		{ID: "list", AllowDeny: &config.AllowDeny{Selector: "target.model", Allow: []string{"model"}}},
		{ID: "schema", JSONSchema: &config.JSONSchema{Target: "content.data", Schema: map[string]any{"type": "object"}}},
		{ID: "secrets", Secrets: &config.Secrets{}},
	}
	cfg := &config.Config{Policies: []config.Policy{{Metadata: config.Metadata{ID: "all", Version: 1}, Spec: config.PolicySpec{Action: domain.ActionBlock, Detectors: detectors}}}}
	r, err := NewResolver(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.policies["all@1"].Detectors) != len(detectors) || r.policies["all@1"].Detectors[2].JSONSchema == nil {
		t.Fatalf("compiled = %#v", r.policies["all@1"].Detectors)
	}
}

func TestResolverRejectsInvalidDeterministicDetectorConfiguration(t *testing.T) {
	tests := []config.Detector{
		{ID: "none"},
		{ID: "two", Keywords: &config.Keywords{Values: []string{"x"}}, Secrets: &config.Secrets{}},
		{ID: "limits", RequestLimits: &config.RequestLimits{}},
		{ID: "list", AllowDeny: &config.AllowDeny{Selector: "unsupported", Allow: []string{"x"}}},
		{ID: "schema-target", JSONSchema: &config.JSONSchema{Target: "bad", Schema: map[string]any{"type": "object"}}},
		{ID: "schema", JSONSchema: &config.JSONSchema{Target: "content.data", Schema: map[string]any{"type": "not-a-type"}}},
		{ID: "external-schema", JSONSchema: &config.JSONSchema{Target: "content.data", Schema: map[string]any{"$ref": "file:///etc/passwd"}}},
		{ID: "secret", Secrets: &config.Secrets{Types: []string{"unknown"}}},
	}
	for _, detector := range tests {
		t.Run(detector.ID, func(t *testing.T) {
			cfg := &config.Config{Policies: []config.Policy{{Metadata: config.Metadata{ID: "bad", Version: 1}, Spec: config.PolicySpec{Action: domain.ActionBlock, Detectors: []config.Detector{detector}}}}}
			if _, err := NewResolver(cfg); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestExampleConfigurationCompiles(t *testing.T) {
	cfg, err := config.Load("../../configs/config.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewResolver(cfg); err != nil {
		t.Fatal(err)
	}
}

func TestResolverRejectsRedactForNonTransformingDetector(t *testing.T) {
	cfg := &config.Config{Policies: []config.Policy{{Metadata: config.Metadata{ID: "bad", Version: 1}, Spec: config.PolicySpec{
		Action: domain.ActionRedact, Detectors: []config.Detector{{ID: "limits", RequestLimits: &config.RequestLimits{MaxMessages: 1}}},
	}}}}
	if _, err := NewResolver(cfg); err == nil {
		t.Fatal("expected error")
	}
}

func TestResolverDefaultsDeadlinesToFailClosed(t *testing.T) {
	cfg := &config.Config{Policies: []config.Policy{{Metadata: config.Metadata{ID: "defaults", Version: 1}, Spec: config.PolicySpec{
		Action: domain.ActionBlock, Detectors: []config.Detector{{ID: "detector", Keywords: &config.Keywords{Values: []string{"x"}}}},
	}}}}
	resolver, err := NewResolver(cfg)
	if err != nil {
		t.Fatal(err)
	}
	compiled := resolver.policies["defaults@1"]
	if compiled.Config.Spec.Timeout != 100*time.Millisecond || compiled.Config.Spec.FailureMode != domain.FailureClosed || compiled.Detectors[0].Config.Timeout != 100*time.Millisecond {
		t.Fatalf("compiled = %#v", compiled)
	}
}

func TestResolverRejectsInvalidDeadlineConfiguration(t *testing.T) {
	tests := []config.PolicySpec{
		{Action: domain.ActionBlock, FailureMode: "unexpected", Detectors: []config.Detector{{ID: "d", Keywords: &config.Keywords{Values: []string{"x"}}}}},
		{Action: domain.ActionBlock, Timeout: -time.Millisecond, Detectors: []config.Detector{{ID: "d", Keywords: &config.Keywords{Values: []string{"x"}}}}},
		{Action: domain.ActionBlock, Detectors: []config.Detector{{ID: "d", Timeout: -time.Millisecond, Keywords: &config.Keywords{Values: []string{"x"}}}}},
		{Action: domain.ActionBlock, Timeout: time.Millisecond, Detectors: []config.Detector{{ID: "d", Timeout: 2 * time.Millisecond, Keywords: &config.Keywords{Values: []string{"x"}}}}},
	}
	for _, spec := range tests {
		cfg := &config.Config{Policies: []config.Policy{{Metadata: config.Metadata{ID: "bad-deadline", Version: 1}, Spec: spec}}}
		if _, err := NewResolver(cfg); err == nil {
			t.Fatalf("expected error for %#v", spec)
		}
	}
}
