# Deterministic detector configuration

Phase 1 detectors run synchronously in the Go evaluator and emit findings for
the containing policy to aggregate. A detector entry MUST contain a stable `id`
and exactly one of `regex`, `keywords`, `requestLimits`, `allowDeny`,
`jsonSchema`, or `secrets`. Invalid detector and JSON Schema configuration is
rejected when policies are compiled at startup.

Policies using `requestLimits`, `allowDeny`, or `jsonSchema` cannot select the
`redact` action because those detectors do not produce textual replacements.

The JSON Schema implementation supports drafts 4, 6, 7, 2019-09, and 2020-12.
Schemas are compiled once at startup using
`github.com/santhosh-tekuri/jsonschema/v5`; this dependency is used to provide
standards-tested validation rather than a repository-specific subset. External
schema references are rejected so policy loading cannot read files or make
network requests. Local references within the configured schema are supported.

## Request limits

`requestLimits` supports these optional positive limits:

| Key | Measurement |
|---|---|
| `maxRequestBytes` | HTTP body bytes, or compact JSON bytes for an in-process request |
| `maxMessages` | Number of `content.messages` entries |
| `maxMessageBytes` | UTF-8 bytes in each individual message content |
| `maxTools` | Number of entries in `content.data.tools` |
| `maxAttachments` | Number of entries in `content.data.attachments` |
| `maxEstimatedTokens` | Ceiling of all content string bytes divided by four |
| `allowedMIMETypes` | Case-insensitive allowlist for `content.type` and attachment `mime_type`/`mimeType` |

At least one limit MUST be configured. A zero numeric value disables that
limit. Findings default to category `request.limit` and expose only the limit
name, actual numeric value, configured maximum, and structural path.
An attachment without either supported MIME type field violates a configured
MIME allowlist.

## Allow and deny lists

`allowDeny.selector` MUST be one of:

- `target.model`, `target.provider`, or `target.data_region`;
- `subject.roles`;
- `content.tools` (`content.data.tools`, using a string or an object's `name`);
- `content.domains` (`content.data.domains`);
- `content.file_types` (`content.data.file_types`, or attachment `file_type`,
  `fileType`, or `extension`).

`allow` and `deny` are optional string arrays, but at least one MUST be present.
Every observed value must be in a non-empty allowlist, and no observed value may
be in the denylist. Deny wins if a value appears in both. Matching is
case-insensitive unless `caseSensitive: true`. Missing selector values do not
create findings. Findings default to `request.list` and do not echo the value.

## JSON Schema

`jsonSchema.target` MUST be `content`, `content.data`, `metadata`, `subject`, or
`target`. `jsonSchema.schema` contains the inline schema. Each leaf validation
error emits a `schema.invalid` finding by default, with JSON Pointer instance
and keyword locations in attributes. Error messages and invalid values are not
returned because they may contain evaluated content.

## Structured secrets

`secrets` uses a curated, versioned bundle rather than accepting arbitrary
patterns. It recognizes `pem_private_key`, `authorization`,
`connection_string`, `known_token`, and `contextual_high_entropy`. An omitted
`types` list enables all types. High-entropy candidates require a nearby
`api_key`, `secret`, `token`, or `password` assignment marker; defaults are 20
bytes and Shannon entropy 4.0. `minEntropyLength` and `minEntropy` can tighten
or relax those defaults.

Secret findings include only `secret_type` and `pattern_id`, never the matched
value. Text spans use UTF-8 byte offsets. A redacting policy replaces matches
with `replacement` (default `<SECRET>`) in text, messages, and nested
`content.data` strings without mutating the request object.
