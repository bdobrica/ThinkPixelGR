package config

import (
	"fmt"
	"os"
	"time"

	"github.com/thinkpixelgr/thinkpixelgr/internal/domain"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Platform PlatformConfig    `yaml:"platform"`
	Tenants  map[string]Tenant `yaml:"tenants"`
	Policies []Policy          `yaml:"policies"`
	Profiles []Profile         `yaml:"profiles"`
}

type PlatformConfig struct {
	MandatoryPolicies []string `yaml:"mandatoryPolicies"`
}

type Tenant struct {
	MandatoryPolicies []string `yaml:"mandatoryPolicies"`
}

type Metadata struct {
	ID      string `yaml:"id"`
	Version int    `yaml:"version"`
}

type Policy struct {
	Metadata Metadata   `yaml:"metadata"`
	Spec     PolicySpec `yaml:"spec"`
}

func (p Policy) CanonicalID() string { return fmt.Sprintf("%s@%d", p.Metadata.ID, p.Metadata.Version) }

type PolicySpec struct {
	Stages     []domain.Stage `yaml:"stages"`
	Action     domain.Action  `yaml:"action"`
	Timeout    time.Duration  `yaml:"-"`
	TimeoutRaw string         `yaml:"timeout"`
	Detectors  []Detector     `yaml:"detectors"`
}

type Detector struct {
	ID            string         `yaml:"id"`
	Regex         *Regex         `yaml:"regex,omitempty"`
	Keywords      *Keywords      `yaml:"keywords,omitempty"`
	RequestLimits *RequestLimits `yaml:"requestLimits,omitempty"`
	AllowDeny     *AllowDeny     `yaml:"allowDeny,omitempty"`
	JSONSchema    *JSONSchema    `yaml:"jsonSchema,omitempty"`
	Secrets       *Secrets       `yaml:"secrets,omitempty"`
}

type Regex struct {
	Pattern     string `yaml:"pattern"`
	Category    string `yaml:"category"`
	Replacement string `yaml:"replacement,omitempty"`
	Severity    string `yaml:"severity,omitempty"`
}

type Keywords struct {
	Values        []string `yaml:"values"`
	Category      string   `yaml:"category"`
	CaseSensitive bool     `yaml:"caseSensitive,omitempty"`
	Replacement   string   `yaml:"replacement,omitempty"`
	Severity      string   `yaml:"severity,omitempty"`
}

type RequestLimits struct {
	MaxRequestBytes    int      `yaml:"maxRequestBytes,omitempty"`
	MaxMessages        int      `yaml:"maxMessages,omitempty"`
	MaxMessageBytes    int      `yaml:"maxMessageBytes,omitempty"`
	MaxTools           int      `yaml:"maxTools,omitempty"`
	MaxAttachments     int      `yaml:"maxAttachments,omitempty"`
	MaxEstimatedTokens int      `yaml:"maxEstimatedTokens,omitempty"`
	AllowedMIMETypes   []string `yaml:"allowedMIMETypes,omitempty"`
	Category           string   `yaml:"category,omitempty"`
	Severity           string   `yaml:"severity,omitempty"`
}

type AllowDeny struct {
	Selector      string   `yaml:"selector"`
	Allow         []string `yaml:"allow,omitempty"`
	Deny          []string `yaml:"deny,omitempty"`
	CaseSensitive bool     `yaml:"caseSensitive,omitempty"`
	Category      string   `yaml:"category,omitempty"`
	Severity      string   `yaml:"severity,omitempty"`
}

type JSONSchema struct {
	Target   string         `yaml:"target"`
	Schema   map[string]any `yaml:"schema"`
	Category string         `yaml:"category,omitempty"`
	Severity string         `yaml:"severity,omitempty"`
}

type Secrets struct {
	Types            []string `yaml:"types,omitempty"`
	MinEntropy       float64  `yaml:"minEntropy,omitempty"`
	MinEntropyLength int      `yaml:"minEntropyLength,omitempty"`
	CategoryPrefix   string   `yaml:"categoryPrefix,omitempty"`
	Replacement      string   `yaml:"replacement,omitempty"`
	Severity         string   `yaml:"severity,omitempty"`
}

type Profile struct {
	Metadata Metadata    `yaml:"metadata"`
	Spec     ProfileSpec `yaml:"spec"`
}

func (p Profile) CanonicalID() string { return fmt.Sprintf("%s@%d", p.Metadata.ID, p.Metadata.Version) }

type ProfileSpec struct {
	Policies []string `yaml:"policies"`
}

func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	for i := range cfg.Policies {
		rawTimeout := cfg.Policies[i].Spec.TimeoutRaw
		if rawTimeout == "" {
			cfg.Policies[i].Spec.Timeout = 100 * time.Millisecond
			continue
		}
		d, err := time.ParseDuration(rawTimeout)
		if err != nil {
			return nil, fmt.Errorf("policy %q timeout: %w", cfg.Policies[i].CanonicalID(), err)
		}
		cfg.Policies[i].Spec.Timeout = d
	}
	return &cfg, nil
}
