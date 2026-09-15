package auth

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"

	"github.com/thinkpixelgr/thinkpixelgr/internal/config"
)

var (
	ErrUnauthenticated = errors.New("authentication required")
	ErrForbidden       = errors.New("operation is not authorized")
)

type Principal struct {
	ID              string
	tenants         map[string]struct{}
	allTenants      bool
	allowTenantless bool
	policyReader    bool
}

type principalContextKey struct{}

func WithPrincipal(ctx context.Context, principal Principal) context.Context {
	return context.WithValue(ctx, principalContextKey{}, principal)
}

func PrincipalFromContext(ctx context.Context) (Principal, bool) {
	principal, ok := ctx.Value(principalContextKey{}).(Principal)
	return principal, ok
}

type Controller interface {
	Authenticate(context.Context, string) (Principal, error)
	AuthorizeTenant(context.Context, Principal, string) error
	AuthorizePolicyList(context.Context, Principal) error
}

type StaticBearer struct {
	byToken map[[sha256.Size]byte]Principal
}

func NewStaticBearer(cfg config.AuthConfig, lookupEnv func(string) (string, bool)) (*StaticBearer, error) {
	if !cfg.Enabled {
		return nil, fmt.Errorf("static bearer authentication is disabled")
	}
	if len(cfg.Principals) == 0 {
		return nil, fmt.Errorf("authentication requires at least one principal")
	}
	if lookupEnv == nil {
		return nil, fmt.Errorf("authentication requires an environment lookup function")
	}
	controller := &StaticBearer{byToken: make(map[[sha256.Size]byte]Principal, len(cfg.Principals))}
	principalIDs := map[string]bool{}
	for _, configured := range cfg.Principals {
		if configured.ID == "" || strings.TrimSpace(configured.ID) != configured.ID {
			return nil, fmt.Errorf("authentication principal requires an id")
		}
		if principalIDs[configured.ID] {
			return nil, fmt.Errorf("duplicate authentication principal %q", configured.ID)
		}
		principalIDs[configured.ID] = true
		if configured.TokenEnv == "" || strings.TrimSpace(configured.TokenEnv) != configured.TokenEnv {
			return nil, fmt.Errorf("authentication principal %q requires tokenEnv", configured.ID)
		}
		token, ok := lookupEnv(configured.TokenEnv)
		if !ok || token == "" {
			return nil, fmt.Errorf("authentication principal %q token environment variable %q is not set", configured.ID, configured.TokenEnv)
		}
		if len(token) < 32 {
			return nil, fmt.Errorf("authentication principal %q token must be at least 32 bytes", configured.ID)
		}
		if strings.TrimSpace(token) != token {
			return nil, fmt.Errorf("authentication principal %q token must not have surrounding whitespace", configured.ID)
		}
		digest := sha256.Sum256([]byte(token))
		if _, exists := controller.byToken[digest]; exists {
			return nil, fmt.Errorf("authentication principals must not share a token")
		}
		principal := Principal{
			ID: configured.ID, tenants: map[string]struct{}{},
			allowTenantless: configured.AllowTenantless, policyReader: configured.PolicyReader,
		}
		for _, tenant := range configured.Tenants {
			if tenant == "" || strings.TrimSpace(tenant) != tenant {
				return nil, fmt.Errorf("authentication principal %q has an empty tenant", configured.ID)
			}
			if tenant == "*" {
				principal.allTenants = true
				continue
			}
			principal.tenants[tenant] = struct{}{}
		}
		controller.byToken[digest] = principal
	}
	return controller, nil
}

func (c *StaticBearer) Authenticate(_ context.Context, authorization string) (Principal, error) {
	token, ok := parseBearer(authorization)
	if !ok {
		return Principal{}, ErrUnauthenticated
	}
	principal, ok := c.byToken[sha256.Sum256([]byte(token))]
	if !ok {
		return Principal{}, ErrUnauthenticated
	}
	return principal, nil
}

func (c *StaticBearer) AuthorizeTenant(_ context.Context, principal Principal, tenant string) error {
	if tenant == "" {
		if principal.allowTenantless {
			return nil
		}
		return ErrForbidden
	}
	if principal.allTenants {
		return nil
	}
	if _, ok := principal.tenants[tenant]; !ok {
		return ErrForbidden
	}
	return nil
}

func (c *StaticBearer) AuthorizePolicyList(_ context.Context, principal Principal) error {
	if !principal.policyReader {
		return ErrForbidden
	}
	return nil
}

func parseBearer(authorization string) (string, bool) {
	parts := strings.Fields(authorization)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] == "" {
		return "", false
	}
	return parts[1], true
}

type Disabled struct{}

func (Disabled) Authenticate(context.Context, string) (Principal, error) {
	return Principal{ID: "authentication-disabled", allTenants: true, allowTenantless: true, policyReader: true}, nil
}

func (Disabled) AuthorizeTenant(context.Context, Principal, string) error { return nil }
func (Disabled) AuthorizePolicyList(context.Context, Principal) error     { return nil }
