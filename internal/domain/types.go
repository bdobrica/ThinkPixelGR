package domain

type Stage string

const (
	StagePreRequest    Stage = "pre_request"
	StagePreModel      Stage = "pre_model"
	StagePostModel     Stage = "post_model"
	StagePreTool       Stage = "pre_tool"
	StagePostTool      Stage = "post_tool"
	StagePreRetrieval  Stage = "pre_retrieval"
	StagePostRetrieval Stage = "post_retrieval"
	StageIngestion     Stage = "ingestion"
)

func (s Stage) Valid() bool {
	switch s {
	case StagePreRequest, StagePreModel, StagePostModel, StagePreTool, StagePostTool,
		StagePreRetrieval, StagePostRetrieval, StageIngestion:
		return true
	default:
		return false
	}
}

type Action string

const (
	ActionAllow   Action = "allow"
	ActionBlock   Action = "block"
	ActionRedact  Action = "redact"
	ActionMonitor Action = "monitor"
)

type FailureMode string

const (
	FailureOpen    FailureMode = "open"
	FailureClosed  FailureMode = "closed"
	FailureMonitor FailureMode = "monitor"
)

func (m FailureMode) Valid() bool {
	return m == FailureOpen || m == FailureClosed || m == FailureMonitor
}

type EvaluationRequest struct {
	RequestID    string            `json:"request_id"`
	Stage        Stage             `json:"stage"`
	TenantID     string            `json:"tenant_id,omitempty"`
	Subject      map[string]any    `json:"subject,omitempty"`
	Target       map[string]any    `json:"target,omitempty"`
	Guardrails   GuardrailSelector `json:"guardrails,omitempty"`
	Content      ContentEnvelope   `json:"content"`
	Metadata     map[string]any    `json:"metadata,omitempty"`
	EncodedBytes int               `json:"-"`
}

type GuardrailSelector struct {
	Profile  string   `json:"profile,omitempty"`
	Policies []string `json:"policies,omitempty"`
}

type ContentEnvelope struct {
	Type     string         `json:"type,omitempty"`
	Text     string         `json:"text,omitempty"`
	Messages []Message      `json:"messages,omitempty"`
	Data     map[string]any `json:"data,omitempty"`
}

type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type Location struct {
	Path  string `json:"path"`
	Start int    `json:"start"`
	End   int    `json:"end"`
}

type Finding struct {
	DetectorID string         `json:"detector"`
	Category   string         `json:"category"`
	Confidence float64        `json:"confidence"`
	Severity   string         `json:"severity,omitempty"`
	Locations  []Location     `json:"locations,omitempty"`
	Attributes map[string]any `json:"attributes,omitempty"`
}

type Decision struct {
	Action             Action           `json:"action"`
	Reason             string           `json:"reason"`
	TransformedContent *ContentEnvelope `json:"transformed_content,omitempty"`
}

type Timing struct {
	TotalMS   int64            `json:"total_ms"`
	Detectors map[string]int64 `json:"detectors"`
	Policies  map[string]int64 `json:"policies"`
}

type FailureScope string

const (
	FailureScopePolicy   FailureScope = "policy"
	FailureScopeDetector FailureScope = "detector"
)

type FailureCode string

const (
	FailurePolicyTimeout           FailureCode = "POLICY_TIMEOUT"
	FailureDetectorTimeout         FailureCode = "DETECTOR_TIMEOUT"
	FailureDetectorUnavailable     FailureCode = "DETECTOR_UNAVAILABLE"
	FailureDetectorInvalidResponse FailureCode = "DETECTOR_INVALID_RESPONSE"
	FailureDetectorUnsupported     FailureCode = "DETECTOR_UNSUPPORTED_INPUT"
	FailureDetectorInternal        FailureCode = "DETECTOR_INTERNAL_ERROR"
)

func (c FailureCode) Valid() bool {
	switch c {
	case FailurePolicyTimeout, FailureDetectorTimeout, FailureDetectorUnavailable,
		FailureDetectorInvalidResponse, FailureDetectorUnsupported, FailureDetectorInternal:
		return true
	default:
		return false
	}
}

type DetectorFailure struct {
	PolicyID    string       `json:"policy"`
	DetectorID  string       `json:"detector,omitempty"`
	Scope       FailureScope `json:"scope"`
	Code        FailureCode  `json:"code"`
	FailureMode FailureMode  `json:"failure_mode"`
	TimeoutMS   int64        `json:"timeout_ms,omitempty"`
	Retryable   bool         `json:"retryable"`
}

type EvaluationResponse struct {
	EvaluationID     string            `json:"evaluation_id"`
	RequestID        string            `json:"request_id"`
	Decision         Decision          `json:"decision"`
	AppliedPolicies  []string          `json:"applied_policies"`
	Findings         []Finding         `json:"findings"`
	DetectorFailures []DetectorFailure `json:"detector_failures,omitempty"`
	Timing           Timing            `json:"timing"`
}
