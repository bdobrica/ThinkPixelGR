package detectorv1

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v5"
	"gopkg.in/yaml.v3"
)

func TestPublishedExamplesConformToSchemas(t *testing.T) {
	tests := []struct {
		file       string
		definition string
	}{
		{"examples/detect-request.json", "DetectionRequest"},
		{"examples/detect-response.json", "DetectionResponse"},
		{"examples/batch-request.json", "BatchDetectionRequest"},
		{"examples/batch-response.json", "BatchDetectionResponse"},
		{"examples/metadata.json", "DetectorMetadata"},
		{"examples/health.json", "Health"},
		{"examples/error.json", "Error"},
	}
	for _, tt := range tests {
		t.Run(tt.definition, func(t *testing.T) {
			sch := compileDefinition(t, tt.definition)
			if err := sch.Validate(readJSON(t, tt.file)); err != nil {
				t.Fatalf("%s: %v", tt.file, err)
			}
		})
	}
}

func TestContractRejectsAuthorityAndPolicyDecisions(t *testing.T) {
	tests := []struct {
		name       string
		definition string
		document   string
	}{
		{
			"request authority",
			"DetectionRequest",
			`{"request_id":"req","evaluation_id":"eval","stage":"pre_model","content":{"type":"text","text":"example"},"run_authority":{"tools":["shell"]}}`,
		},
		{
			"detector decision",
			"DetectionResponse",
			`{"request_id":"req","evaluation_id":"eval","detector":{"id":"detector","version":"1","revision":"sha256:revision","model":null},"findings":[],"timing":{"total_ms":1},"decision":{"action":"allow"}}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertInvalid(t, tt.definition, tt.document)
		})
	}
}

func TestContractRejectsIncompleteOrUnsafeResponses(t *testing.T) {
	tests := []struct {
		name       string
		definition string
		document   string
	}{
		{
			"confidence over one",
			"DetectionResponse",
			`{"request_id":"req","evaluation_id":"eval","detector":{"id":"detector","version":"1","revision":"sha256:revision","model":null},"findings":[{"category":"safety","confidence":1.1}],"timing":{"total_ms":1}}`,
		},
		{
			"mutable detector identity",
			"DetectorMetadata",
			`{"protocol_version":"1.0","detector":{"id":"detector","version":"1"},"preprocessing_revision":"sha256:preprocess","supported_stages":["pre_model"],"supported_content_types":["text"],"supported_languages":[],"limits":{"max_batch_size":1,"max_input_bytes":1},"taxonomy":[{"category":"safety"}],"capabilities":{"spans":false,"batch":false,"deterministic":true},"recommended_thresholds":{}}`,
		},
		{
			"empty batch",
			"BatchDetectionRequest",
			`{"requests":[]}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertInvalid(t, tt.definition, tt.document)
		})
	}
}

func TestOpenAPIPublishesRequiredEndpoints(t *testing.T) {
	document := readOpenAPI(t)
	paths, ok := document["paths"].(map[string]any)
	if !ok {
		t.Fatal("OpenAPI paths are missing")
	}
	for path, method := range map[string]string{
		"/v1/detect":       "post",
		"/v1/detect:batch": "post",
		"/v1/metadata":     "get",
		"/health/live":     "get",
		"/health/ready":    "get",
	} {
		methods, ok := paths[path].(map[string]any)
		if !ok || methods[method] == nil {
			t.Errorf("OpenAPI is missing %s %s", method, path)
		}
	}
}

func TestOpenAPIReferencesResolve(t *testing.T) {
	document := readOpenAPI(t)
	definitions := map[string]bool{}
	responses := map[string]bool{}
	var visit func(any)
	visit = func(value any) {
		switch value := value.(type) {
		case map[string]any:
			for key, child := range value {
				if key == "$ref" {
					if ref, ok := child.(string); ok && strings.HasPrefix(ref, "./schema.json#/$defs/") {
						definitions[strings.TrimPrefix(ref, "./schema.json#/$defs/")] = true
					} else if ok && strings.HasPrefix(ref, "#/components/responses/") {
						responses[strings.TrimPrefix(ref, "#/components/responses/")] = true
					}
				}
				visit(child)
			}
		case []any:
			for _, child := range value {
				visit(child)
			}
		}
	}
	visit(document)
	if len(definitions) == 0 {
		t.Fatal("OpenAPI has no external detector schema references")
	}
	for definition := range definitions {
		compileDefinition(t, definition)
	}
	components := document["components"].(map[string]any)["responses"].(map[string]any)
	for response := range responses {
		if components[response] == nil {
			t.Errorf("OpenAPI references missing response component %q", response)
		}
	}
}

func TestBatchExamplePreservesOrderAndCorrelation(t *testing.T) {
	request := readJSON(t, "examples/batch-request.json").(map[string]any)["requests"].([]any)
	response := readJSON(t, "examples/batch-response.json").(map[string]any)["responses"].([]any)
	if len(request) != len(response) {
		t.Fatalf("request count %d != response count %d", len(request), len(response))
	}
	for i := range request {
		req := request[i].(map[string]any)
		resp := response[i].(map[string]any)
		if req["request_id"] != resp["request_id"] || req["evaluation_id"] != resp["evaluation_id"] {
			t.Fatalf("batch item %d lost correlation: request=%#v response=%#v", i, req, resp)
		}
	}
}

func TestMetadataBatchCapabilityMatchesLimit(t *testing.T) {
	metadata := readJSON(t, "examples/metadata.json").(map[string]any)
	metadata["capabilities"].(map[string]any)["batch"] = false
	if err := compileDefinition(t, "DetectorMetadata").Validate(metadata); err == nil {
		t.Fatal("metadata advertised batch=false with a positive max_batch_size")
	}
	metadata["limits"].(map[string]any)["max_batch_size"] = json.Number("0")
	if err := compileDefinition(t, "DetectorMetadata").Validate(metadata); err != nil {
		t.Fatalf("batch=false metadata with max_batch_size=0: %v", err)
	}
}

func compileDefinition(t *testing.T, definition string) *jsonschema.Schema {
	t.Helper()
	raw, err := os.ReadFile("schema.json")
	if err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource("schema.json", bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	sch, err := compiler.Compile("schema.json#/$defs/" + definition)
	if err != nil {
		t.Fatalf("compile %s: %v", definition, err)
	}
	return sch
}

func readOpenAPI(t *testing.T) map[string]any {
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

func readJSON(t *testing.T, path string) any {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var document any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&document); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return document
}

func assertInvalid(t *testing.T, definition, document string) {
	t.Helper()
	var value any
	decoder := json.NewDecoder(bytes.NewBufferString(document))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		t.Fatal(err)
	}
	if err := compileDefinition(t, definition).Validate(value); err == nil {
		t.Fatalf("%s accepted invalid document: %s", definition, fmt.Sprint(value))
	}
}
