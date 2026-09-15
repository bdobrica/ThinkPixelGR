package api

import (
	"os"
	"testing"

	"gopkg.in/yaml.v3"
)

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
