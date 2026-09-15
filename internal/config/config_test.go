package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/thinkpixelgr/thinkpixelgr/internal/domain"
)

func TestLoadParsesPolicyAndDetectorTimeouts(t *testing.T) {
	path := writeConfig(t, `policies:
  - metadata: {id: test/policy, version: 1}
    spec:
      action: block
      failureMode: monitor
      timeout: 25ms
      detectors:
        - id: detector
          timeout: 5ms
          keywords: {values: [test], category: test}
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	policy := cfg.Policies[0]
	if policy.Spec.Timeout != 25*time.Millisecond || policy.Spec.FailureMode != domain.FailureMonitor || policy.Spec.Detectors[0].Timeout != 5*time.Millisecond {
		t.Fatalf("policy = %#v", policy)
	}
}

func TestLoadParsesAuthenticationPrincipalScopes(t *testing.T) {
	path := writeConfig(t, `auth:
  enabled: true
  principals:
    - id: gateway
      tokenEnv: TEST_GATEWAY_TOKEN
      tenants: [tenant-a]
      allowTenantless: true
      policyReader: true
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Auth.Enabled || len(cfg.Auth.Principals) != 1 {
		t.Fatalf("auth = %#v", cfg.Auth)
	}
	principal := cfg.Auth.Principals[0]
	if principal.ID != "gateway" || principal.TokenEnv != "TEST_GATEWAY_TOKEN" || len(principal.Tenants) != 1 || principal.Tenants[0] != "tenant-a" || !principal.AllowTenantless || !principal.PolicyReader {
		t.Fatalf("principal = %#v", principal)
	}
}

func TestLoadRejectsInvalidDetectorTimeout(t *testing.T) {
	path := writeConfig(t, `policies:
  - metadata: {id: test/policy, version: 1}
    spec:
      action: block
      detectors:
        - id: detector
          timeout: eventually
          keywords: {values: [test], category: test}
`)
	if _, err := Load(path); err == nil {
		t.Fatal("expected invalid detector timeout error")
	}
}

func TestLoadRejectsNonPositiveTimeouts(t *testing.T) {
	for name, body := range map[string]string{
		"policy": `policies:
  - metadata: {id: test/policy, version: 1}
    spec: {action: block, timeout: 0s}
`,
		"detector": `policies:
  - metadata: {id: test/policy, version: 1}
    spec:
      action: block
      detectors:
        - id: detector
          timeout: -1ms
          keywords: {values: [test], category: test}
`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(writeConfig(t, body)); err == nil {
				t.Fatal("expected non-positive timeout error")
			}
		})
	}
}

func writeConfig(t *testing.T, value string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
