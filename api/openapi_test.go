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
