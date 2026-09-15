package api

import (
	"context"
	"os"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"gopkg.in/yaml.v3"
)

func TestOpenAPIContractIsValid(t *testing.T) {
	loader := openapi3.NewLoader()
	document, err := loader.LoadFromFile("openapi.yaml")
	if err != nil {
		t.Fatalf("load OpenAPI: %v", err)
	}
	if err := document.Validate(context.Background()); err != nil {
		t.Fatalf("validate OpenAPI: %v", err)
	}
}

func TestOpenAPIExposesFindingAttributes(t *testing.T) {
	raw, err := os.ReadFile("openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := yaml.Unmarshal(raw, &document); err != nil {
		t.Fatalf("parse OpenAPI: %v", err)
	}

	attributes, ok := nestedMap(document, "components", "schemas", "EvaluationResponse", "properties", "findings", "items", "properties", "attributes")
	if !ok {
		t.Fatal("EvaluationResponse finding attributes are missing from OpenAPI")
	}
	if attributes["type"] != "object" || attributes["additionalProperties"] != true {
		t.Fatalf("finding attributes schema = %#v", attributes)
	}
}

func TestOpenAPIExposesDetectorFailuresAndPolicyTiming(t *testing.T) {
	document := readDocument(t)
	failures, ok := nestedMap(document, "components", "schemas", "EvaluationResponse", "properties", "detector_failures")
	if !ok || failures["type"] != "array" {
		t.Fatalf("detector failures schema = %#v", failures)
	}
	failureProperties, ok := nestedMap(failures, "items", "properties")
	if !ok || failureProperties["failure_mode"] == nil || failureProperties["code"] == nil {
		t.Fatalf("detector failure properties = %#v", failureProperties)
	}
	failureItems, _ := failures["items"].(map[string]any)
	if !containsString(failureItems["required"], "timeout_ms") {
		t.Fatalf("detector failure required fields = %#v", failureItems["required"])
	}
	policies, ok := nestedMap(document, "components", "schemas", "EvaluationResponse", "properties", "timing", "properties", "policies")
	if !ok || policies["type"] != "object" {
		t.Fatalf("policy timing schema = %#v", policies)
	}
}

func TestOpenAPIDocumentsDeploymentSelectedBearerAuthentication(t *testing.T) {
	document := readDocument(t)
	bearer, ok := nestedMap(document, "components", "securitySchemes", "BearerAuth")
	if !ok || bearer["type"] != "http" || bearer["scheme"] != "bearer" {
		t.Fatalf("BearerAuth scheme = %#v", bearer)
	}
	security, ok := document["security"].([]any)
	if !ok || len(security) != 2 {
		t.Fatalf("global security = %#v", document["security"])
	}
	for _, path := range []string{"/health/live", "/health/ready"} {
		operation, ok := nestedMap(document, "paths", path, "get")
		if !ok {
			t.Fatalf("missing health operation %s", path)
		}
		anonymous, ok := operation["security"].([]any)
		if !ok || len(anonymous) != 0 {
			t.Fatalf("%s security = %#v", path, operation["security"])
		}
	}
	for _, endpoint := range []struct{ path, method string }{{"/v1/evaluations", "post"}, {"/v1/policies", "get"}, {"/metrics", "get"}} {
		responses, ok := nestedMap(document, "paths", endpoint.path, endpoint.method, "responses")
		if !ok || responses["401"] == nil || responses["403"] == nil {
			t.Fatalf("%s auth responses = %#v", endpoint.path, responses)
		}
	}
}

func TestOpenAPIDocumentsMetricsAndTracePropagation(t *testing.T) {
	document := readDocument(t)
	metrics, ok := nestedMap(document, "paths", "/metrics", "get", "responses", "200", "content", "text/plain", "schema")
	if !ok || metrics["type"] != "string" {
		t.Fatalf("metrics schema = %#v", metrics)
	}
	traceparent, ok := nestedMap(document, "components", "parameters", "Traceparent")
	if !ok || traceparent["in"] != "header" || traceparent["name"] != "traceparent" {
		t.Fatalf("traceparent parameter = %#v", traceparent)
	}
	evaluation, ok := nestedMap(document, "paths", "/v1/evaluations", "post")
	if !ok || evaluation["parameters"] == nil {
		t.Fatalf("evaluation trace parameters = %#v", evaluation["parameters"])
	}
}

func containsString(value any, expected string) bool {
	items, _ := value.([]any)
	for _, item := range items {
		if item == expected {
			return true
		}
	}
	return false
}

func readDocument(t *testing.T) map[string]any {
	t.Helper()
	raw, err := os.ReadFile("openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := yaml.Unmarshal(raw, &document); err != nil {
		t.Fatalf("parse OpenAPI: %v", err)
	}
	return document
}

func nestedMap(root map[string]any, keys ...string) (map[string]any, bool) {
	current := root
	for _, key := range keys {
		next, ok := current[key].(map[string]any)
		if !ok {
			return nil, false
		}
		current = next
	}
	return current, true
}
