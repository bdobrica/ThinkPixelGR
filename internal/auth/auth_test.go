package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/thinkpixelgr/thinkpixelgr/internal/config"
)

func TestStaticBearerAuthenticatesAndAuthorizesConfiguredScope(t *testing.T) {
	token := strings.Repeat("t", 32)
	controller, err := NewStaticBearer(config.AuthConfig{Enabled: true, Principals: []config.AuthPrincipal{{
		ID: "gateway", TokenEnv: "TEST_TOKEN", Tenants: []string{"tenant-a"}, PolicyReader: true,
	}}}, func(name string) (string, bool) { return token, name == "TEST_TOKEN" })
	if err != nil {
		t.Fatal(err)
	}
	principal, err := controller.Authenticate(context.Background(), "Bearer "+token)
	if err != nil || principal.ID != "gateway" {
		t.Fatalf("principal = %#v, err = %v", principal, err)
	}
	if err := controller.AuthorizeTenant(context.Background(), principal, "tenant-a"); err != nil {
		t.Fatalf("authorize configured tenant: %v", err)
	}
	if !errors.Is(controller.AuthorizeTenant(context.Background(), principal, "tenant-b"), ErrForbidden) {
		t.Fatal("unconfigured tenant was authorized")
	}
	if !errors.Is(controller.AuthorizeTenant(context.Background(), principal, ""), ErrForbidden) {
		t.Fatal("tenantless request was authorized")
	}
	if err := controller.AuthorizePolicyList(context.Background(), principal); err != nil {
		t.Fatalf("authorize policy list: %v", err)
	}
	if strings.Contains(fmt.Sprintf("%#v", controller), token) {
		t.Fatal("controller retained the raw token")
	}
}

func TestStaticBearerRejectsMissingMalformedAndUnknownCredentials(t *testing.T) {
	token := strings.Repeat("t", 32)
	controller := mustStaticBearer(t, config.AuthPrincipal{ID: "gateway", TokenEnv: "TEST_TOKEN"}, token)
	for _, header := range []string{"", token, "Basic " + token, "Bearer", "Bearer unknown"} {
		if _, err := controller.Authenticate(context.Background(), header); !errors.Is(err, ErrUnauthenticated) {
			t.Errorf("Authenticate(%q) error = %v", header, err)
		}
	}
}

func TestStaticBearerSupportsExplicitWildcardAndTenantlessScopes(t *testing.T) {
	controller := mustStaticBearer(t, config.AuthPrincipal{
		ID: "operator", TokenEnv: "TEST_TOKEN", Tenants: []string{"*"}, AllowTenantless: true,
	}, strings.Repeat("w", 32))
	principal, err := controller.Authenticate(context.Background(), "bearer "+strings.Repeat("w", 32))
	if err != nil {
		t.Fatal(err)
	}
	for _, tenant := range []string{"", "tenant-a", "tenant-b"} {
		if err := controller.AuthorizeTenant(context.Background(), principal, tenant); err != nil {
			t.Errorf("authorize tenant %q: %v", tenant, err)
		}
	}
	if !errors.Is(controller.AuthorizePolicyList(context.Background(), principal), ErrForbidden) {
		t.Fatal("principal without policyReader was authorized to list policies")
	}
}

func TestStaticBearerValidatesConfigurationWithoutExposingTokens(t *testing.T) {
	validToken := strings.Repeat("v", 32)
	tests := []struct {
		name string
		cfg  config.AuthConfig
		env  map[string]string
	}{
		{name: "disabled", cfg: config.AuthConfig{}},
		{name: "no principals", cfg: config.AuthConfig{Enabled: true}},
		{name: "missing id", cfg: config.AuthConfig{Enabled: true, Principals: []config.AuthPrincipal{{TokenEnv: "A"}}}, env: map[string]string{"A": validToken}},
		{name: "missing token env", cfg: config.AuthConfig{Enabled: true, Principals: []config.AuthPrincipal{{ID: "a"}}}},
		{name: "unset token", cfg: config.AuthConfig{Enabled: true, Principals: []config.AuthPrincipal{{ID: "a", TokenEnv: "A"}}}},
		{name: "short token", cfg: config.AuthConfig{Enabled: true, Principals: []config.AuthPrincipal{{ID: "a", TokenEnv: "A"}}}, env: map[string]string{"A": "short"}},
		{name: "token whitespace", cfg: config.AuthConfig{Enabled: true, Principals: []config.AuthPrincipal{{ID: "a", TokenEnv: "A"}}}, env: map[string]string{"A": validToken + "\n"}},
		{name: "duplicate id", cfg: config.AuthConfig{Enabled: true, Principals: []config.AuthPrincipal{{ID: "a", TokenEnv: "A"}, {ID: "a", TokenEnv: "B"}}}, env: map[string]string{"A": validToken, "B": strings.Repeat("b", 32)}},
		{name: "duplicate token", cfg: config.AuthConfig{Enabled: true, Principals: []config.AuthPrincipal{{ID: "a", TokenEnv: "A"}, {ID: "b", TokenEnv: "B"}}}, env: map[string]string{"A": validToken, "B": validToken}},
		{name: "empty tenant", cfg: config.AuthConfig{Enabled: true, Principals: []config.AuthPrincipal{{ID: "a", TokenEnv: "A", Tenants: []string{""}}}}, env: map[string]string{"A": validToken}},
		{name: "tenant whitespace", cfg: config.AuthConfig{Enabled: true, Principals: []config.AuthPrincipal{{ID: "a", TokenEnv: "A", Tenants: []string{" tenant"}}}}, env: map[string]string{"A": validToken}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewStaticBearer(tt.cfg, func(name string) (string, bool) {
				value, ok := tt.env[name]
				return value, ok
			})
			if err == nil {
				t.Fatal("expected configuration error")
			}
			for _, token := range tt.env {
				if strings.Contains(err.Error(), token) {
					t.Fatal("configuration error exposed a token")
				}
			}
		})
	}
}

func TestStaticBearerRejectsNilEnvironmentLookup(t *testing.T) {
	_, err := NewStaticBearer(config.AuthConfig{Enabled: true, Principals: []config.AuthPrincipal{{ID: "a", TokenEnv: "A"}}}, nil)
	if err == nil {
		t.Fatal("expected configuration error")
	}
}

func mustStaticBearer(t *testing.T, principal config.AuthPrincipal, token string) *StaticBearer {
	t.Helper()
	controller, err := NewStaticBearer(config.AuthConfig{Enabled: true, Principals: []config.AuthPrincipal{principal}}, func(name string) (string, bool) {
		return token, name == principal.TokenEnv
	})
	if err != nil {
		t.Fatal(err)
	}
	return controller
}
