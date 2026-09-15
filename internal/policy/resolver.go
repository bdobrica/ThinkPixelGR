package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v5"
	"github.com/thinkpixelgr/thinkpixelgr/internal/config"
	"github.com/thinkpixelgr/thinkpixelgr/internal/domain"
)

type CompiledDetector struct {
	Config     config.Detector
	Regex      *regexp.Regexp
	JSONSchema *jsonschema.Schema
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
			if detector.ID == "" {
				return nil, fmt.Errorf("detector in %q requires an id", p.CanonicalID())
			}
			configured := countConfigured(detector)
			if configured != 1 {
				return nil, fmt.Errorf("detector %q in %q must configure exactly one detector type", detector.ID, p.CanonicalID())
			}
			if p.Spec.Action == domain.ActionRedact && (detector.RequestLimits != nil || detector.AllowDeny != nil || detector.JSONSchema != nil) {
				return nil, fmt.Errorf("detector %q in %q cannot produce a redaction", detector.ID, p.CanonicalID())
			}
			cd := CompiledDetector{Config: detector}
			switch {
			case detector.Regex != nil:
				re, err := regexp.Compile(detector.Regex.Pattern)
				if err != nil {
					return nil, fmt.Errorf("detector %q: %w", detector.ID, err)
				}
				cd.Regex = re
			case detector.RequestLimits != nil:
				if err := validateRequestLimits(detector.RequestLimits); err != nil {
					return nil, fmt.Errorf("detector %q: %w", detector.ID, err)
				}
			case detector.AllowDeny != nil:
				if err := validateAllowDeny(detector.AllowDeny); err != nil {
					return nil, fmt.Errorf("detector %q: %w", detector.ID, err)
				}
			case detector.JSONSchema != nil:
				if err := validateSchemaTarget(detector.JSONSchema.Target); err != nil {
					return nil, fmt.Errorf("detector %q: %w", detector.ID, err)
				}
				if len(detector.JSONSchema.Schema) == 0 {
					return nil, fmt.Errorf("detector %q: jsonSchema.schema is required", detector.ID)
				}
				compiler := jsonschema.NewCompiler()
				compiler.LoadURL = func(url string) (io.ReadCloser, error) {
					return nil, fmt.Errorf("external schema reference %q is not allowed", url)
				}
				resource := "urn:thinkpixelgr:detector:" + detector.ID
				encoded, err := json.Marshal(detector.JSONSchema.Schema)
				if err != nil {
					return nil, fmt.Errorf("detector %q schema: %w", detector.ID, err)
				}
				if err := compiler.AddResource(resource, bytes.NewReader(encoded)); err != nil {
					return nil, fmt.Errorf("detector %q schema: %w", detector.ID, err)
				}
				sch, err := compiler.Compile(resource)
				if err != nil {
					return nil, fmt.Errorf("detector %q schema: %w", detector.ID, err)
				}
				cd.JSONSchema = sch
			case detector.Secrets != nil:
				if err := validateSecrets(detector.Secrets); err != nil {
					return nil, fmt.Errorf("detector %q: %w", detector.ID, err)
				}
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

func countConfigured(d config.Detector) int {
	count := 0
	for _, configured := range []bool{d.Regex != nil, d.Keywords != nil, d.RequestLimits != nil, d.AllowDeny != nil, d.JSONSchema != nil, d.Secrets != nil} {
		if configured {
			count++
		}
	}
	return count
}

func validateRequestLimits(l *config.RequestLimits) error {
	values := []int{l.MaxRequestBytes, l.MaxMessages, l.MaxMessageBytes, l.MaxTools, l.MaxAttachments, l.MaxEstimatedTokens}
	configured := len(l.AllowedMIMETypes) > 0
	for _, value := range values {
		if value < 0 {
			return fmt.Errorf("request limits cannot be negative")
		}
		configured = configured || value > 0
	}
	if !configured {
		return fmt.Errorf("requestLimits requires at least one limit")
	}
	return nil
}

var allowDenySelectors = map[string]bool{
	"target.model": true, "target.provider": true, "target.data_region": true,
	"subject.roles": true, "content.tools": true, "content.domains": true, "content.file_types": true,
}

func validateAllowDeny(l *config.AllowDeny) error {
	if !allowDenySelectors[l.Selector] {
		return fmt.Errorf("unsupported allowDeny.selector %q", l.Selector)
	}
	if len(l.Allow) == 0 && len(l.Deny) == 0 {
		return fmt.Errorf("allowDeny requires allow or deny values")
	}
	return nil
}

func validateSchemaTarget(target string) error {
	switch target {
	case "content", "content.data", "metadata", "subject", "target":
		return nil
	default:
		return fmt.Errorf("unsupported jsonSchema.target %q", target)
	}
}

var secretTypes = map[string]bool{
	"pem_private_key": true, "authorization": true, "connection_string": true,
	"known_token": true, "contextual_high_entropy": true,
}

func validateSecrets(s *config.Secrets) error {
	if s.MinEntropy < 0 || s.MinEntropyLength < 0 {
		return fmt.Errorf("secret entropy settings cannot be negative")
	}
	for _, typ := range s.Types {
		if !secretTypes[typ] {
			return fmt.Errorf("unsupported secret type %q", typ)
		}
	}
	return nil
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
