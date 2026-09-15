package observability

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const AuditSchemaVersion = "thinkpixelgr.audit/v1"

type FindingSummary struct {
	DetectorID string  `json:"detector"`
	Category   string  `json:"category"`
	Confidence float64 `json:"confidence"`
	Severity   string  `json:"severity,omitempty"`
}

type FailureSummary struct {
	PolicyID   string `json:"policy"`
	DetectorID string `json:"detector,omitempty"`
	Scope      string `json:"scope"`
	Code       string `json:"code"`
	Mode       string `json:"failure_mode"`
}

type AuditEvent struct {
	Type              string
	Outcome           string
	ErrorCode         string
	EvaluationID      string
	RequestIDHash     string
	TenantID          string
	PrincipalID       string
	Stage             string
	Action            string
	AppliedPolicies   []string
	Findings          []FindingSummary
	Failures          []FailureSummary
	TotalMS           int64
	PolicyTimingsMS   map[string]int64
	DetectorTimingsMS map[string]int64
}

type EvaluationObservation struct {
	Stage             string
	Outcome           string
	Action            string
	Duration          time.Duration
	FindingCategories []string
	DetectorTimings   map[string]int64
	Failures          []FailureSummary
}

type HTTPObservation struct {
	Method string
	Route  string
	Status int
}

type SpanAttributes struct {
	Operation  string
	Stage      string
	PolicyID   string
	DetectorID string
}

type Span interface {
	End(status string)
}

type Tracer interface {
	ContinueTrace(context.Context, string) context.Context
	Traceparent(context.Context) string
	StartSpan(context.Context, string, SpanAttributes) (context.Context, Span)
}

type Observer interface {
	Tracer
	RecordAudit(context.Context, AuditEvent)
	RecordEvaluation(EvaluationObservation)
	RecordHTTP(HTTPObservation)
	MetricsHandler() http.Handler
}

type Service struct {
	logger *slog.Logger
	now    func() time.Time

	mu                sync.Mutex
	httpRequests      map[httpKey]uint64
	evaluations       map[evaluationKey]uint64
	evaluationLatency map[string]*histogram
	detectorLatency   map[string]*histogram
	findings          map[string]uint64
	failures          map[failureKey]uint64
}

type httpKey struct {
	method, route string
	status        int
}

type evaluationKey struct{ stage, outcome, action string }
type failureKey struct{ code, mode string }

type histogram struct {
	buckets []uint64
	count   uint64
	sum     float64
}

var latencyBuckets = []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

func New(logger *slog.Logger) *Service {
	if logger == nil {
		logger = slog.Default()
	}
	return &Service{
		logger: logger, now: time.Now,
		httpRequests: map[httpKey]uint64{}, evaluations: map[evaluationKey]uint64{},
		evaluationLatency: map[string]*histogram{}, detectorLatency: map[string]*histogram{},
		findings: map[string]uint64{}, failures: map[failureKey]uint64{},
	}
}

func (s *Service) RecordAudit(ctx context.Context, event AuditEvent) {
	attrs := []slog.Attr{
		slog.String("event_kind", "audit"), slog.String("schema", AuditSchemaVersion),
		slog.String("event_type", event.Type), slog.String("outcome", event.Outcome),
	}
	attrs = appendNonEmpty(attrs,
		slog.String("trace_id", TraceID(ctx)), slog.String("error_code", event.ErrorCode),
		slog.String("evaluation_id", event.EvaluationID), slog.String("request_id_hash", event.RequestIDHash),
		slog.String("tenant_id", event.TenantID), slog.String("principal_id", event.PrincipalID),
		slog.String("stage", event.Stage), slog.String("action", event.Action),
	)
	if event.AppliedPolicies != nil {
		attrs = append(attrs, slog.Any("applied_policies", event.AppliedPolicies))
	}
	if event.Findings != nil {
		attrs = append(attrs, slog.Any("findings", event.Findings))
	}
	if event.Failures != nil {
		attrs = append(attrs, slog.Any("detector_failures", event.Failures))
	}
	if event.TotalMS >= 0 {
		attrs = append(attrs, slog.Int64("total_ms", event.TotalMS))
	}
	if event.PolicyTimingsMS != nil {
		attrs = append(attrs, slog.Any("policy_timings_ms", event.PolicyTimingsMS))
	}
	if event.DetectorTimingsMS != nil {
		attrs = append(attrs, slog.Any("detector_timings_ms", event.DetectorTimingsMS))
	}
	s.logger.LogAttrs(ctx, slog.LevelInfo, "audit event", attrs...)
}

func appendNonEmpty(target []slog.Attr, attrs ...slog.Attr) []slog.Attr {
	for _, attr := range attrs {
		if attr.Value.String() != "" {
			target = append(target, attr)
		}
	}
	return target
}

func (s *Service) RecordEvaluation(observation EvaluationObservation) {
	stage := metricStage(observation.Stage)
	outcome := metricOutcome(observation.Outcome)
	action := metricAction(observation.Action)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.evaluations[evaluationKey{stage: stage, outcome: outcome, action: action}]++
	observeHistogram(s.evaluationLatency, stage, observation.Duration.Seconds())
	for _, category := range observation.FindingCategories {
		s.findings[boundedLabel(category, "unknown")]++
	}
	for detectorID, milliseconds := range observation.DetectorTimings {
		observeHistogram(s.detectorLatency, boundedLabel(detectorID, "unknown"), float64(milliseconds)/1000)
	}
	for _, failure := range observation.Failures {
		s.failures[failureKey{code: metricFailureCode(failure.Code), mode: metricFailureMode(failure.Mode)}]++
	}
}

func (s *Service) RecordHTTP(observation HTTPObservation) {
	status := observation.Status
	if status < 100 || status > 599 {
		status = 0
	}
	key := httpKey{method: metricMethod(observation.Method), route: boundedLabel(observation.Route, "unknown"), status: status}
	s.mu.Lock()
	s.httpRequests[key]++
	s.mu.Unlock()
}

func metricMethod(value string) string {
	if value == http.MethodGet || value == http.MethodPost {
		return value
	}
	return "OTHER"
}

func boundedLabel(value, fallback string) string {
	if value == "" {
		return fallback
	}
	if len(value) > 128 {
		return "oversized"
	}
	return value
}

func metricStage(value string) string {
	switch value {
	case "pre_request", "pre_model", "post_model", "pre_tool", "post_tool", "pre_retrieval", "post_retrieval", "ingestion":
		return value
	default:
		return "unknown"
	}
}

func metricOutcome(value string) string {
	if value == "completed" || value == "rejected" {
		return value
	}
	return "unknown"
}

func metricAction(value string) string {
	switch value {
	case "allow", "block", "redact", "monitor":
		return value
	default:
		return "none"
	}
}

func metricFailureCode(value string) string {
	switch value {
	case "POLICY_TIMEOUT", "DETECTOR_TIMEOUT", "DETECTOR_UNAVAILABLE", "DETECTOR_INVALID_RESPONSE", "DETECTOR_UNSUPPORTED_INPUT", "DETECTOR_INTERNAL_ERROR":
		return value
	default:
		return "unknown"
	}
}

func metricFailureMode(value string) string {
	if value == "open" || value == "closed" || value == "monitor" {
		return value
	}
	return "unknown"
}

func IdentifierDigest(value string) string {
	if value == "" {
		return ""
	}
	digest := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(digest[:])
}

func observeHistogram(collection map[string]*histogram, key string, value float64) {
	h := collection[key]
	if h == nil {
		h = &histogram{buckets: make([]uint64, len(latencyBuckets))}
		collection[key] = h
	}
	h.count++
	h.sum += value
	for index, upper := range latencyBuckets {
		if value <= upper {
			h.buckets[index]++
		}
	}
}

func (s *Service) MetricsHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		s.writeMetrics(w)
	})
}

func (s *Service) writeMetrics(w io.Writer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, _ = io.WriteString(w, "# HELP thinkpixelgr_http_requests_total HTTP requests by bounded route and status.\n# TYPE thinkpixelgr_http_requests_total counter\n")
	httpKeys := sortedHTTPKeys(s.httpRequests)
	for _, key := range httpKeys {
		_, _ = fmt.Fprintf(w, "thinkpixelgr_http_requests_total{method=%s,route=%s,status=%q} %d\n", quoteLabel(key.method), quoteLabel(key.route), strconv.Itoa(key.status), s.httpRequests[key])
	}
	_, _ = io.WriteString(w, "# HELP thinkpixelgr_evaluations_total Evaluation attempts by stage, outcome, and action.\n# TYPE thinkpixelgr_evaluations_total counter\n")
	evaluationKeys := sortedEvaluationKeys(s.evaluations)
	for _, key := range evaluationKeys {
		_, _ = fmt.Fprintf(w, "thinkpixelgr_evaluations_total{action=%s,outcome=%s,stage=%s} %d\n", quoteLabel(key.action), quoteLabel(key.outcome), quoteLabel(key.stage), s.evaluations[key])
	}
	writeHistograms(w, "thinkpixelgr_evaluation_duration_seconds", "Evaluation latency by stage.", "stage", s.evaluationLatency)
	writeHistograms(w, "thinkpixelgr_detector_duration_seconds", "Detector latency by configured detector identifier.", "detector", s.detectorLatency)
	_, _ = io.WriteString(w, "# HELP thinkpixelgr_findings_total Findings by configured category.\n# TYPE thinkpixelgr_findings_total counter\n")
	for _, category := range sortedStringKeys(s.findings) {
		_, _ = fmt.Fprintf(w, "thinkpixelgr_findings_total{category=%s} %d\n", quoteLabel(category), s.findings[category])
	}
	_, _ = io.WriteString(w, "# HELP thinkpixelgr_detector_failures_total Detector and policy execution failures by bounded code and mode.\n# TYPE thinkpixelgr_detector_failures_total counter\n")
	for _, key := range sortedFailureKeys(s.failures) {
		_, _ = fmt.Fprintf(w, "thinkpixelgr_detector_failures_total{code=%s,failure_mode=%s} %d\n", quoteLabel(key.code), quoteLabel(key.mode), s.failures[key])
	}
}

func writeHistograms(w io.Writer, name, help, label string, histograms map[string]*histogram) {
	_, _ = fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s histogram\n", name, help, name)
	for _, key := range sortedStringKeys(histograms) {
		h := histograms[key]
		for index, upper := range latencyBuckets {
			_, _ = fmt.Fprintf(w, "%s_bucket{%s=%s,le=%q} %d\n", name, label, quoteLabel(key), strconv.FormatFloat(upper, 'g', -1, 64), h.buckets[index])
		}
		_, _ = fmt.Fprintf(w, "%s_bucket{%s=%s,le=\"+Inf\"} %d\n", name, label, quoteLabel(key), h.count)
		_, _ = fmt.Fprintf(w, "%s_sum{%s=%s} %s\n", name, label, quoteLabel(key), strconv.FormatFloat(h.sum, 'g', -1, 64))
		_, _ = fmt.Fprintf(w, "%s_count{%s=%s} %d\n", name, label, quoteLabel(key), h.count)
	}
}

func quoteLabel(value string) string {
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, "\n", "\\n")
	value = strings.ReplaceAll(value, "\"", "\\\"")
	return "\"" + value + "\""
}

func sortedStringKeys[T any](values map[string]T) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func sortedHTTPKeys(values map[httpKey]uint64) []httpKey {
	keys := make([]httpKey, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return fmt.Sprint(keys[i]) < fmt.Sprint(keys[j]) })
	return keys
}

func sortedEvaluationKeys(values map[evaluationKey]uint64) []evaluationKey {
	keys := make([]evaluationKey, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return fmt.Sprint(keys[i]) < fmt.Sprint(keys[j]) })
	return keys
}

func sortedFailureKeys(values map[failureKey]uint64) []failureKey {
	keys := make([]failureKey, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return fmt.Sprint(keys[i]) < fmt.Sprint(keys[j]) })
	return keys
}

type traceContext struct{ traceID, spanID, flags string }
type traceContextKey struct{}

func (s *Service) ContinueTrace(ctx context.Context, traceparent string) context.Context {
	trace, ok := parseTraceparent(traceparent)
	if !ok {
		trace = traceContext{traceID: randomHex(16), flags: "01"}
	}
	return context.WithValue(ctx, traceContextKey{}, trace)
}

func (s *Service) Traceparent(ctx context.Context) string {
	trace, ok := ctx.Value(traceContextKey{}).(traceContext)
	if !ok || trace.traceID == "" || trace.spanID == "" {
		return ""
	}
	return "00-" + trace.traceID + "-" + trace.spanID + "-" + trace.flags
}

func TraceID(ctx context.Context) string {
	trace, _ := ctx.Value(traceContextKey{}).(traceContext)
	return trace.traceID
}

func (s *Service) StartSpan(ctx context.Context, name string, attrs SpanAttributes) (context.Context, Span) {
	parent, ok := ctx.Value(traceContextKey{}).(traceContext)
	if !ok || parent.traceID == "" {
		parent = traceContext{traceID: randomHex(16), flags: "01"}
	}
	current := traceContext{traceID: parent.traceID, spanID: randomHex(8), flags: parent.flags}
	span := &logSpan{logger: s.logger, now: s.now, started: s.now(), name: name, traceID: current.traceID, spanID: current.spanID, parentID: parent.spanID, attrs: attrs}
	return context.WithValue(ctx, traceContextKey{}, current), span
}

type logSpan struct {
	logger                *slog.Logger
	now                   func() time.Time
	started               time.Time
	name, traceID, spanID string
	parentID              string
	attrs                 SpanAttributes
	once                  sync.Once
}

func (s *logSpan) End(status string) {
	s.once.Do(func() {
		attrs := []slog.Attr{
			slog.String("event_kind", "trace"), slog.String("span", s.name),
			slog.String("trace_id", s.traceID), slog.String("span_id", s.spanID),
			slog.String("status", boundedLabel(status, "unset")),
			slog.Int64("duration_us", s.now().Sub(s.started).Microseconds()),
		}
		attrs = appendNonEmpty(attrs, slog.String("parent_span_id", s.parentID), slog.String("operation", s.attrs.Operation), slog.String("stage", s.attrs.Stage), slog.String("policy_id", s.attrs.PolicyID), slog.String("detector_id", s.attrs.DetectorID))
		s.logger.LogAttrs(context.Background(), slog.LevelDebug, "trace span", attrs...)
	})
}

func parseTraceparent(value string) (traceContext, bool) {
	if len(value) != 55 || value[2] != '-' || value[35] != '-' || value[52] != '-' || value[:2] != "00" {
		return traceContext{}, false
	}
	traceID, spanID, flags := value[3:35], value[36:52], value[53:55]
	if !validLowerHex(traceID) || !validLowerHex(spanID) || !validLowerHex(flags) || allZero(traceID) || allZero(spanID) {
		return traceContext{}, false
	}
	return traceContext{traceID: traceID, spanID: spanID, flags: flags}, true
}

func validLowerHex(value string) bool {
	for _, char := range value {
		if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f')) {
			return false
		}
	}
	return true
}

func allZero(value string) bool { return strings.Trim(value, "0") == "" }

var fallbackID uint64

func randomHex(bytes int) string {
	value := make([]byte, bytes)
	if _, err := rand.Read(value); err == nil {
		return hex.EncodeToString(value)
	}
	sequence := atomic.AddUint64(&fallbackID, 1)
	return fmt.Sprintf("%0*x", bytes*2, sequence)
}

type Nop struct{}

func (Nop) ContinueTrace(ctx context.Context, _ string) context.Context { return ctx }
func (Nop) Traceparent(context.Context) string                          { return "" }
func (Nop) StartSpan(ctx context.Context, _ string, _ SpanAttributes) (context.Context, Span) {
	return ctx, nopSpan{}
}
func (Nop) RecordAudit(context.Context, AuditEvent) {}
func (Nop) RecordEvaluation(EvaluationObservation)  {}
func (Nop) RecordHTTP(HTTPObservation)              {}
func (Nop) MetricsHandler() http.Handler            { return http.NotFoundHandler() }

type nopSpan struct{}

func (nopSpan) End(string) {}
