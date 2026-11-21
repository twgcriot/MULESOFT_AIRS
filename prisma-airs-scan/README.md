# Prisma AIRS scan policy

Flex Gateway custom policy that scans LLM, REST, and MCP payloads with the Prisma AIRS Runtime API (`POST /v1/scan/sync/request`) and enforces the returned `action`.

`allow` forwards the exchange. That includes alert mode, where the category is `malicious` and the action is still `allow`. `block` stops a request before the upstream API sees it, or replaces an upstream response before the caller sees it.

The linked proxy-wasm tutorial is for existing policies. This project uses the Omni Gateway Policy Development Kit, which compiles the same kind of Rust WebAssembly filter.

## Configure

Set `group_id` in `Cargo.toml` to your Anypoint organization ID before publishing. `profileName` or `profileId` must reference an AI security profile whose detectors are set to Block when a threat should stop traffic.

`apiKey` is sent as `x-pan-token`. In local mode, `examples/policy-binding.yaml` uses `$PRISMA_AIRS_API_KEY`.

## Build and apply

Install the PDK prerequisites, then from this directory:

```shell
make setup
make build
make show-policy-ref-name
```

`make build` writes these files under `target/wasm32-wasip1/release/`:

- `prisma_airs_scan_definition.yaml`
- `prisma_airs_scan_implementation.yaml`
- `prisma_airs_scan.wasm`

Copy the definition and implementation YAML into the gateway `conf.d` directory. Copy `examples/policy-binding.yaml` to `conf.d/custom/`, set `targetRef.name` to the API instance, and set `policyRef.name` to the value printed by `make show-policy-ref-name`.

Do not apply the policy to the API instance that proxies the Prisma AIRS Runtime API. The policy calls that API itself.

`make run` starts the local playground. Payloads are buffered up to `FLEX_DOWNSTREAM_CONNECTION_BUFFER_LIMIT_BYTES` (1 MB by default) so the verdict is known before the body is forwarded. Larger bodies are rejected by the gateway before this policy runs.

## What is scanned

| Traffic | How it is recognized | Scan body |
| --- | --- | --- |
| LLM | `/chat/completions`, `/v1/responses`, `/v1/messages`, Anthropic headers, or a chat JSON body | Native provider schema, with a text scan if AIRS returns HTTP 422 |
| MCP | `/mcp`, MCP session headers, or an MCP JSON-RPC method | Prompt text on the request and response text on the response |
| REST | Any other textual body or query string | Raw text as `prompt` or `response` |

Empty bodies are skipped. Binary bodies are skipped unless `blockUnscannable` is true. A scan transport failure or a response without `allow` or `block` returns HTTP 502 when `failClosed` is true.
