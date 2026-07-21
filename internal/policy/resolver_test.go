package policy

import (
	"testing"

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
