package engine

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"time"

	"github.com/thinkpixelgr/thinkpixelgr/internal/domain"
	"github.com/thinkpixelgr/thinkpixelgr/internal/policy"
)

type Evaluator struct{ resolver *policy.Resolver }

func New(resolver *policy.Resolver) *Evaluator { return &Evaluator{resolver: resolver} }

type replacement struct {
	path, value string
	start, end  int
}

func (e *Evaluator) Evaluate(ctx context.Context, req domain.EvaluationRequest) (domain.EvaluationResponse, error) {
	started := time.Now()
	policies, err := e.resolver.Resolve(req.TenantID, req.Guardrails.Profile, req.Guardrails.Policies, req.Stage)
	if err != nil {
		return domain.EvaluationResponse{}, err
	}

	response := domain.EvaluationResponse{
		EvaluationID: newID(), RequestID: req.RequestID,
		Decision: domain.Decision{Action: domain.ActionAllow, Reason: "no policy findings"},
		Findings: []domain.Finding{}, Timing: domain.Timing{Detectors: map[string]int64{}},
	}
	var replacements []replacement
	winningPolicy := ""
	for _, p := range policies {
		response.AppliedPolicies = append(response.AppliedPolicies, p.Config.CanonicalID())
		for _, detector := range p.Detectors {
			select {
			case <-ctx.Done():
				return domain.EvaluationResponse{}, ctx.Err()
			default:
			}
			detectorStart := time.Now()
			findings, foundReplacements := evaluateDetector(detector, req.Content)
			response.Timing.Detectors[detector.Config.ID] += time.Since(detectorStart).Milliseconds()
			response.Findings = append(response.Findings, findings...)
			if len(findings) == 0 {
				continue
			}
			if actionPriority(p.Config.Spec.Action) > actionPriority(response.Decision.Action) {
				response.Decision.Action = p.Config.Spec.Action
				winningPolicy = p.Config.CanonicalID()
			}
			if p.Config.Spec.Action == domain.ActionRedact {
				replacements = append(replacements, foundReplacements...)
			}
		}
	}
	if winningPolicy != "" {
		response.Decision.Reason = fmt.Sprintf("matched policy %s", winningPolicy)
	}
	if response.Decision.Action == domain.ActionRedact && len(replacements) > 0 {
		transformed := applyReplacements(req.Content, replacements)
		response.Decision.TransformedContent = &transformed
	}
	response.Timing.TotalMS = time.Since(started).Milliseconds()
	return response, nil
}

func evaluateDetector(detector policy.CompiledDetector, content domain.ContentEnvelope) ([]domain.Finding, []replacement) {
	var findings []domain.Finding
	var replacements []replacement
	visitText(content, func(path, value string) {
		if detector.Regex != nil {
			for _, span := range detector.Regex.FindAllStringIndex(value, -1) {
				cfg := detector.Config.Regex
				findings = append(findings, finding(detector.Config.ID, cfg.Category, cfg.Severity, path, span[0], span[1]))
				replacementValue := cfg.Replacement
				if replacementValue == "" {
					replacementValue = "<REDACTED>"
				}
				replacements = append(replacements, replacement{path: path, value: replacementValue, start: span[0], end: span[1]})
			}
			return
		}
		cfg := detector.Config.Keywords
		for _, keyword := range cfg.Values {
			for _, span := range policy.MatchKeyword(value, keyword, cfg.CaseSensitive) {
				findings = append(findings, finding(detector.Config.ID, cfg.Category, cfg.Severity, path, span[0], span[1]))
				replacementValue := cfg.Replacement
				if replacementValue == "" {
					replacementValue = "<REDACTED>"
				}
				replacements = append(replacements, replacement{path: path, value: replacementValue, start: span[0], end: span[1]})
			}
		}
	})
	return findings, replacements
}

func finding(id, category, severity, path string, start, end int) domain.Finding {
	return domain.Finding{DetectorID: id, Category: category, Confidence: 1, Severity: severity,
		Locations: []domain.Location{{Path: path, Start: start, End: end}}}
}

func visitText(content domain.ContentEnvelope, fn func(string, string)) {
	if content.Text != "" {
		fn("content.text", content.Text)
	}
	for i, message := range content.Messages {
		fn(fmt.Sprintf("content.messages[%d].content", i), message.Content)
	}
}

func applyReplacements(content domain.ContentEnvelope, replacements []replacement) domain.ContentEnvelope {
	byPath := map[string][]replacement{}
	for _, item := range replacements {
		byPath[item.path] = append(byPath[item.path], item)
	}
	apply := func(path, value string) string {
		items := byPath[path]
		sort.Slice(items, func(i, j int) bool {
			if items[i].start == items[j].start {
				return items[i].end > items[j].end
			}
			return items[i].start < items[j].start
		})
		selected := make([]replacement, 0, len(items))
		lastEnd := -1
		for _, item := range items {
			if item.start < 0 || item.end > len(value) || item.start < lastEnd {
				continue
			}
			selected = append(selected, item)
			lastEnd = item.end
		}
		for i := len(selected) - 1; i >= 0; i-- {
			item := selected[i]
			value = value[:item.start] + item.value + value[item.end:]
		}
		return value
	}
	content.Text = apply("content.text", content.Text)
	for i := range content.Messages {
		content.Messages[i].Content = apply(fmt.Sprintf("content.messages[%d].content", i), content.Messages[i].Content)
	}
	return content
}

func actionPriority(action domain.Action) int {
	switch action {
	case domain.ActionBlock:
		return 4
	case domain.ActionRedact:
		return 3
	case domain.ActionMonitor:
		return 2
	default:
		return 1
	}
}

func newID() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("eval_%d", time.Now().UnixNano())
	}
	return "eval_" + hex.EncodeToString(b)
}
