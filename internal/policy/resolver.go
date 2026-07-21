package policy

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/thinkpixelgr/thinkpixelgr/internal/config"
	"github.com/thinkpixelgr/thinkpixelgr/internal/domain"
)

type CompiledDetector struct {
	Config config.Detector
	Regex  *regexp.Regexp
}

type CompiledPolicy struct {
	Config    config.Policy
	Detectors []CompiledDetector
}

type Resolver struct {
	platform []string
	tenants  map[string]config.Tenant
	policies map[string]CompiledPolicy
	profiles map[string]config.Profile
}

func NewResolver(cfg *config.Config) (*Resolver, error) {
	r := &Resolver{platform: cfg.Platform.MandatoryPolicies, tenants: cfg.Tenants, policies: map[string]CompiledPolicy{}, profiles: map[string]config.Profile{}}
	for _, p := range cfg.Policies {
		if p.Metadata.ID == "" || p.Metadata.Version < 1 {
			return nil, fmt.Errorf("policy metadata requires an id and positive version")
		}
		if p.Spec.Action != domain.ActionAllow && p.Spec.Action != domain.ActionBlock && p.Spec.Action != domain.ActionRedact && p.Spec.Action != domain.ActionMonitor {
			return nil, fmt.Errorf("policy %q has invalid action %q", p.CanonicalID(), p.Spec.Action)
		}
		compiled := CompiledPolicy{Config: p}
		for _, detector := range p.Spec.Detectors {
			if (detector.Regex == nil) == (detector.Keywords == nil) {
				return nil, fmt.Errorf("detector %q in %q must configure exactly one detector type", detector.ID, p.CanonicalID())
			}
			cd := CompiledDetector{Config: detector}
			if detector.Regex != nil {
				re, err := regexp.Compile(detector.Regex.Pattern)
				if err != nil {
					return nil, fmt.Errorf("detector %q: %w", detector.ID, err)
				}
				cd.Regex = re
			}
			compiled.Detectors = append(compiled.Detectors, cd)
		}
		if _, exists := r.policies[p.CanonicalID()]; exists {
			return nil, fmt.Errorf("duplicate policy %q", p.CanonicalID())
		}
		r.policies[p.CanonicalID()] = compiled
	}
	for _, profile := range cfg.Profiles {
		r.profiles[profile.CanonicalID()] = profile
	}
	for _, id := range r.platform {
		if _, ok := r.policies[id]; !ok {
			return nil, fmt.Errorf("platform references unknown policy %q", id)
		}
	}
	return r, nil
}

func (r *Resolver) Resolve(tenant, profile string, selected []string, stage domain.Stage) ([]CompiledPolicy, error) {
	ids := append([]string{}, r.platform...)
	if t, ok := r.tenants[tenant]; ok {
		ids = append(ids, t.MandatoryPolicies...)
	}
	if profile != "" {
		p, ok := r.profiles[profile]
		if !ok {
			return nil, fmt.Errorf("unknown profile %q", profile)
		}
		ids = append(ids, p.Spec.Policies...)
	}
	ids = append(ids, selected...)
	seen := map[string]bool{}
	resolved := make([]CompiledPolicy, 0, len(ids))
	for _, id := range ids {
		if seen[id] {
			continue
		}
		p, ok := r.policies[id]
		if !ok {
			return nil, fmt.Errorf("unknown policy %q", id)
		}
		seen[id] = true
		if supportsStage(p.Config.Spec.Stages, stage) {
			resolved = append(resolved, p)
		}
	}
	return resolved, nil
}

func (r *Resolver) PolicyIDs() []string {
	ids := make([]string, 0, len(r.policies))
	for id := range r.policies {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func supportsStage(stages []domain.Stage, stage domain.Stage) bool {
	for _, candidate := range stages {
		if candidate == stage {
			return true
		}
	}
	return false
}

func MatchKeyword(value, keyword string, caseSensitive bool) [][2]int {
	if keyword == "" {
		return nil
	}
	haystack, needle := value, keyword
	if !caseSensitive {
		haystack, needle = strings.ToLower(value), strings.ToLower(keyword)
	}
	var spans [][2]int
	for offset := 0; offset <= len(haystack)-len(needle); {
		i := strings.Index(haystack[offset:], needle)
		if i < 0 {
			break
		}
		start := offset + i
		spans = append(spans, [2]int{start, start + len(needle)})
		offset = start + len(needle)
	}
	return spans
}
