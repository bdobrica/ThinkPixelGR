package engine

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v5"
	"github.com/thinkpixelgr/thinkpixelgr/internal/config"
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
			findings, foundReplacements := evaluateDetector(detector, req)
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

func evaluateDetector(detector policy.CompiledDetector, req domain.EvaluationRequest) ([]domain.Finding, []replacement) {
	var findings []domain.Finding
	var replacements []replacement
	if detector.Config.RequestLimits != nil {
		return evaluateRequestLimits(detector.Config, req), nil
	}
	if detector.Config.AllowDeny != nil {
		return evaluateAllowDeny(detector.Config, req), nil
	}
	if detector.Config.JSONSchema != nil {
		return evaluateJSONSchema(detector, req), nil
	}
	if detector.Config.Secrets != nil {
		return evaluateSecrets(detector.Config, req.Content)
	}
	visitText(req.Content, func(path, value string) {
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

func evaluateRequestLimits(detector config.Detector, req domain.EvaluationRequest) []domain.Finding {
	cfg := detector.RequestLimits
	category := defaultString(cfg.Category, "request.limit")
	var findings []domain.Finding
	add := func(name, path string, actual, limit int) {
		if limit > 0 && actual > limit {
			findings = append(findings, attributeFinding(detector.ID, category, cfg.Severity, path, map[string]any{
				"limit": name, "actual": actual, "maximum": limit,
			}))
		}
	}
	requestBytes := req.EncodedBytes
	if requestBytes == 0 {
		encoded, _ := json.Marshal(req)
		requestBytes = len(encoded)
	}
	add("request_bytes", "", requestBytes, cfg.MaxRequestBytes)
	add("messages", "content.messages", len(req.Content.Messages), cfg.MaxMessages)
	for i, message := range req.Content.Messages {
		add("message_bytes", fmt.Sprintf("content.messages[%d].content", i), len(message.Content), cfg.MaxMessageBytes)
	}
	add("tools", "content.data.tools", collectionLength(req.Content.Data["tools"]), cfg.MaxTools)
	add("attachments", "content.data.attachments", collectionLength(req.Content.Data["attachments"]), cfg.MaxAttachments)
	contentBytes := 0
	visitStrings(req.Content, func(_ string, value string) { contentBytes += len(value) })
	add("estimated_tokens", "content", (contentBytes+3)/4, cfg.MaxEstimatedTokens)
	if len(cfg.AllowedMIMETypes) > 0 {
		for _, item := range contentMIMETypes(req.Content) {
			if !contains(cfg.AllowedMIMETypes, item.value, false) {
				findings = append(findings, attributeFinding(detector.ID, category, cfg.Severity, item.path, map[string]any{
					"limit": "allowed_mime_types",
				}))
			}
		}
	}
	return findings
}

type selectedValue struct{ path, value string }

func evaluateAllowDeny(detector config.Detector, req domain.EvaluationRequest) []domain.Finding {
	cfg := detector.AllowDeny
	category := defaultString(cfg.Category, "request.list")
	var findings []domain.Finding
	for _, item := range selectorValues(cfg.Selector, req) {
		rule := ""
		if contains(cfg.Deny, item.value, cfg.CaseSensitive) {
			rule = "deny"
		} else if len(cfg.Allow) > 0 && !contains(cfg.Allow, item.value, cfg.CaseSensitive) {
			rule = "allow"
		}
		if rule != "" {
			findings = append(findings, attributeFinding(detector.ID, category, cfg.Severity, item.path, map[string]any{
				"selector": cfg.Selector, "rule": rule,
			}))
		}
	}
	return findings
}

func evaluateJSONSchema(detector policy.CompiledDetector, req domain.EvaluationRequest) []domain.Finding {
	cfg := detector.Config.JSONSchema
	value := schemaTarget(cfg.Target, req)
	if err := detector.JSONSchema.Validate(value); err != nil {
		var validationErr *jsonschema.ValidationError
		if !errors.As(err, &validationErr) {
			return []domain.Finding{attributeFinding(detector.Config.ID, defaultString(cfg.Category, "schema.invalid"), cfg.Severity, cfg.Target, nil)}
		}
		leaves := validationLeaves(validationErr)
		findings := make([]domain.Finding, 0, len(leaves))
		for _, leaf := range leaves {
			path := cfg.Target + pointerJSONPath(leaf.InstanceLocation)
			attrs := map[string]any{"instance_location": leaf.InstanceLocation, "keyword_location": leaf.KeywordLocation}
			findings = append(findings, attributeFinding(detector.Config.ID, defaultString(cfg.Category, "schema.invalid"), cfg.Severity, path, attrs))
		}
		return findings
	}
	return nil
}

var secretPatterns = []struct {
	typ, id string
	re      *regexp.Regexp
}{
	{"pem_private_key", "pem-private-key", regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----`)},
	{"authorization", "authorization-header", regexp.MustCompile(`(?i)(?:authorization\s*:\s*)?(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{12,}`)},
	{"connection_string", "uri-userinfo", regexp.MustCompile(`\b[A-Za-z][A-Za-z0-9+.-]*://[^/\s:@]+:[^/\s@]+@[^\s]+`)},
	{"known_token", "known-token-prefix", regexp.MustCompile(`\b(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,255}|github_pat_[A-Za-z0-9_]{20,255}|sk-[A-Za-z0-9_-]{20,})\b`)},
}

var contextualSecret = regexp.MustCompile(`(?i)(?:api[_-]?key|secret|token|password)\s*[:=]\s*["']?([A-Za-z0-9+/=_-]{20,})`)

func evaluateSecrets(detector config.Detector, content domain.ContentEnvelope) ([]domain.Finding, []replacement) {
	cfg := detector.Secrets
	enabled := map[string]bool{}
	for _, typ := range cfg.Types {
		enabled[typ] = true
	}
	isEnabled := func(typ string) bool { return len(enabled) == 0 || enabled[typ] }
	prefix := defaultString(cfg.CategoryPrefix, "secret")
	replacementValue := defaultString(cfg.Replacement, "<SECRET>")
	minLength := cfg.MinEntropyLength
	if minLength == 0 {
		minLength = 20
	}
	minEntropy := cfg.MinEntropy
	if minEntropy == 0 {
		minEntropy = 4.0
	}
	var findings []domain.Finding
	var replacements []replacement
	seen := map[string]bool{}
	add := func(path, typ, patternID string, start, end int) {
		key := fmt.Sprintf("%s:%d:%d", path, start, end)
		if seen[key] {
			return
		}
		seen[key] = true
		item := finding(detector.ID, prefix+"."+typ, cfg.Severity, path, start, end)
		item.Attributes = map[string]any{"secret_type": typ, "pattern_id": patternID}
		findings = append(findings, item)
		replacements = append(replacements, replacement{path: path, value: replacementValue, start: start, end: end})
	}
	visitStrings(content, func(path, value string) {
		for _, pattern := range secretPatterns {
			if !isEnabled(pattern.typ) {
				continue
			}
			for _, span := range pattern.re.FindAllStringIndex(value, -1) {
				add(path, pattern.typ, pattern.id, span[0], span[1])
			}
		}
		if isEnabled("contextual_high_entropy") {
			for _, match := range contextualSecret.FindAllStringSubmatchIndex(value, -1) {
				start, end := match[2], match[3]
				if end-start >= minLength && shannonEntropy(value[start:end]) >= minEntropy {
					add(path, "contextual_high_entropy", "contextual-entropy", start, end)
				}
			}
		}
	})
	return findings, replacements
}

func finding(id, category, severity, path string, start, end int) domain.Finding {
	return domain.Finding{DetectorID: id, Category: category, Confidence: 1, Severity: severity,
		Locations: []domain.Location{{Path: path, Start: start, End: end}}}
}

func attributeFinding(id, category, severity, path string, attributes map[string]any) domain.Finding {
	if attributes == nil {
		attributes = map[string]any{}
	}
	if path != "" {
		attributes["path"] = path
	}
	return domain.Finding{DetectorID: id, Category: category, Confidence: 1, Severity: severity, Attributes: attributes}
}

func visitText(content domain.ContentEnvelope, fn func(string, string)) {
	if content.Text != "" {
		fn("content.text", content.Text)
	}
	for i, message := range content.Messages {
		fn(fmt.Sprintf("content.messages[%d].content", i), message.Content)
	}
}

func visitStrings(content domain.ContentEnvelope, fn func(string, string)) {
	visitText(content, fn)
	visitJSONStrings(content.Data, "content.data", fn)
}

func visitJSONStrings(value any, path string, fn func(string, string)) {
	switch value := value.(type) {
	case string:
		fn(path, value)
	case []any:
		for i, item := range value {
			visitJSONStrings(item, fmt.Sprintf("%s[%d]", path, i), fn)
		}
	case map[string]any:
		keys := make([]string, 0, len(value))
		for key := range value {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			visitJSONStrings(value[key], childPath(path, key), fn)
		}
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
				if items[i].end == items[j].end {
					return items[i].value < items[j].value
				}
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
	if content.Data != nil {
		content.Data = transformJSONStrings(content.Data, "content.data", apply).(map[string]any)
	}
	return content
}

func transformJSONStrings(value any, path string, apply func(string, string) string) any {
	switch value := value.(type) {
	case string:
		return apply(path, value)
	case []any:
		result := make([]any, len(value))
		for i, item := range value {
			result[i] = transformJSONStrings(item, fmt.Sprintf("%s[%d]", path, i), apply)
		}
		return result
	case map[string]any:
		result := make(map[string]any, len(value))
		for key, item := range value {
			result[key] = transformJSONStrings(item, childPath(path, key), apply)
		}
		return result
	default:
		return value
	}
}

func childPath(parent, key string) string {
	for i, r := range key {
		if !(r == '_' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || i > 0 && r >= '0' && r <= '9') {
			return fmt.Sprintf("%s[%q]", parent, key)
		}
	}
	if key == "" {
		return parent + `[""]`
	}
	return parent + "." + key
}

func collectionLength(value any) int {
	if items, ok := value.([]any); ok {
		return len(items)
	}
	return 0
}

func contentMIMETypes(content domain.ContentEnvelope) []selectedValue {
	var result []selectedValue
	if content.Type != "" {
		result = append(result, selectedValue{"content.type", content.Type})
	}
	attachments, _ := content.Data["attachments"].([]any)
	for i, raw := range attachments {
		attachment, _ := raw.(map[string]any)
		found := false
		for _, key := range []string{"mime_type", "mimeType"} {
			if value, ok := attachment[key].(string); ok && value != "" {
				result = append(result, selectedValue{fmt.Sprintf("content.data.attachments[%d].%s", i, key), value})
				found = true
				break
			}
		}
		if !found {
			result = append(result, selectedValue{fmt.Sprintf("content.data.attachments[%d]", i), ""})
		}
	}
	return result
}

func selectorValues(selector string, req domain.EvaluationRequest) []selectedValue {
	switch selector {
	case "target.model", "target.provider", "target.data_region":
		key := strings.TrimPrefix(selector, "target.")
		if value, ok := req.Target[key].(string); ok && value != "" {
			return []selectedValue{{selector, value}}
		}
	case "subject.roles":
		return stringValues(req.Subject["roles"], selector)
	case "content.tools":
		items, _ := req.Content.Data["tools"].([]any)
		result := make([]selectedValue, 0, len(items))
		for i, item := range items {
			path := fmt.Sprintf("content.data.tools[%d]", i)
			switch item := item.(type) {
			case string:
				result = append(result, selectedValue{path, item})
			case map[string]any:
				if name, ok := item["name"].(string); ok {
					result = append(result, selectedValue{path + ".name", name})
				}
			}
		}
		return result
	case "content.domains":
		return stringValues(req.Content.Data["domains"], "content.data.domains")
	case "content.file_types":
		result := stringValues(req.Content.Data["file_types"], "content.data.file_types")
		attachments, _ := req.Content.Data["attachments"].([]any)
		for i, raw := range attachments {
			attachment, _ := raw.(map[string]any)
			for _, key := range []string{"file_type", "fileType", "extension"} {
				if value, ok := attachment[key].(string); ok && value != "" {
					result = append(result, selectedValue{fmt.Sprintf("content.data.attachments[%d].%s", i, key), value})
					break
				}
			}
		}
		return result
	}
	return nil
}

func stringValues(value any, path string) []selectedValue {
	items, ok := value.([]any)
	if !ok {
		return nil
	}
	result := make([]selectedValue, 0, len(items))
	for i, raw := range items {
		if value, ok := raw.(string); ok && value != "" {
			result = append(result, selectedValue{fmt.Sprintf("%s[%d]", path, i), value})
		}
	}
	return result
}

func contains(values []string, candidate string, caseSensitive bool) bool {
	for _, value := range values {
		if caseSensitive && value == candidate || !caseSensitive && strings.EqualFold(value, candidate) {
			return true
		}
	}
	return false
}

func schemaTarget(target string, req domain.EvaluationRequest) any {
	var value any
	switch target {
	case "content":
		value = req.Content
	case "content.data":
		value = req.Content.Data
	case "metadata":
		value = req.Metadata
	case "subject":
		value = req.Subject
	case "target":
		value = req.Target
	}
	encoded, _ := json.Marshal(value)
	var normalized any
	_ = json.Unmarshal(encoded, &normalized)
	return normalized
}

func validationLeaves(err *jsonschema.ValidationError) []*jsonschema.ValidationError {
	if len(err.Causes) == 0 {
		return []*jsonschema.ValidationError{err}
	}
	var leaves []*jsonschema.ValidationError
	for _, cause := range err.Causes {
		leaves = append(leaves, validationLeaves(cause)...)
	}
	sort.SliceStable(leaves, func(i, j int) bool {
		left := leaves[i].InstanceLocation
		right := leaves[j].InstanceLocation
		if left == right {
			return leaves[i].KeywordLocation < leaves[j].KeywordLocation
		}
		return left < right
	})
	return leaves
}

func pointerJSONPath(pointer string) string {
	var result string
	for _, part := range strings.Split(strings.TrimPrefix(pointer, "/"), "/") {
		if part == "" {
			continue
		}
		part = strings.ReplaceAll(strings.ReplaceAll(part, "~1", "/"), "~0", "~")
		if _, err := fmt.Sscanf(part, "%d", new(int)); err == nil {
			result += "[" + part + "]"
		} else {
			result = childPath(result, part)
		}
	}
	return result
}

func shannonEntropy(value string) float64 {
	if value == "" {
		return 0
	}
	counts := map[byte]int{}
	for i := 0; i < len(value); i++ {
		counts[value[i]]++
	}
	var entropy float64
	for _, count := range counts {
		probability := float64(count) / float64(len(value))
		entropy -= probability * math.Log2(probability)
	}
	return entropy
}

func defaultString(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
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
