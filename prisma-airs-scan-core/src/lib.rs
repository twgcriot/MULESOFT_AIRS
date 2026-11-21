//! Classify LLM, REST, and MCP payloads and turn Prisma AIRS scan results into allow or block.

use serde_json::{json, Map, Value};

const PROMPT_LIMIT: usize = 32_000;
const RESPONSE_LIMIT: usize = 64_000;

const OPENAI_CHAT: &str = "openai.chat.completions";
const OPENAI_RESPONSES: &str = "openai.responses";
const ANTHROPIC_MESSAGES: &str = "anthropic.messages";

/// Which gateway payload the policy is looking at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    Request,
    Response,
}

/// Traffic class used to decide whether scanning is enabled and how the payload is wrapped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrafficKind {
    Llm,
    Rest,
    Mcp,
}

impl TrafficKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Llm => "llm",
            Self::Rest => "rest",
            Self::Mcp => "mcp",
        }
    }
}

/// Headers and body the gateway filter has already buffered.
#[derive(Clone, Copy, Debug)]
pub struct ScanInput<'a> {
    pub direction: Direction,
    pub method: &'a str,
    pub path: &'a str,
    pub content_type: &'a str,
    pub mcp_channel: bool,
    pub anthropic: bool,
    pub body: &'a [u8],
    pub profile_name: &'a str,
    pub profile_id: Option<&'a str>,
    pub app_name: Option<&'a str>,
    pub app_user: Option<&'a str>,
    pub user_ip: Option<&'a str>,
    pub transaction_id: Option<&'a str>,
    pub scan_llm: bool,
    pub scan_rest: bool,
    pub scan_mcp: bool,
    pub block_unscannable: bool,
    pub block_status: u16,
}

/// What the filter should do before, or instead of, calling Prisma AIRS.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Plan {
    Allow {
        headers: Vec<(String, String)>,
    },
    Block {
        status: u16,
        headers: Vec<(String, String)>,
        body: String,
    },
    Scan(PreparedScan),
}

/// One synchronous scan call, plus a text scan used when native schema scanning is rejected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedScan {
    pub traffic: TrafficKind,
    pub body: Vec<u8>,
    pub text_fallback: Option<Vec<u8>>,
}

/// Build the scan body, or an allow/block that does not need a scan call.
pub fn prepare_scan(input: &ScanInput<'_>) -> Plan {
    let query = query_string(input.path);
    let body_text = std::str::from_utf8(input.body).ok().map(str::trim);
    let body_empty = body_text.map(|text| text.is_empty()).unwrap_or(false);
    let query_empty = query.trim().is_empty();

    if body_empty && (input.direction == Direction::Response || query_empty) {
        return allow_skipped(None, "empty");
    }

    if input.body.is_empty() && !query_empty && input.direction == Direction::Request {
        return plan_text(input, query, None);
    }

    if !is_textual(input.content_type, input.body) {
        let traffic = classify(input);
        return if input.block_unscannable {
            block(
                input.block_status,
                traffic,
                "unscannable",
                "unscannable",
                "payload is not a text payload Prisma AIRS can scan",
                None,
                None,
            )
        } else {
            allow_skipped(traffic, "unscannable")
        };
    }

    let text = body_text.unwrap_or("");
    plan_text(input, text, if query_empty { None } else { Some(query) })
}

/// Interpret the synchronous scan HTTP response. `action: allow` passes, including alert mode
/// (`allow` with `category: malicious`). Only `action: block` stops the exchange.
pub fn decide_scan(
    traffic: TrafficKind,
    http_status: u16,
    response_body: &[u8],
    fail_closed: bool,
    block_status: u16,
) -> Plan {
    if !(200..300).contains(&http_status) {
        return unavailable(
            traffic,
            fail_closed,
            &format!("Prisma AIRS returned HTTP {http_status}"),
        );
    }

    let parsed: Value = match serde_json::from_slice(response_body) {
        Ok(value) => value,
        Err(_) => {
            return unavailable(
                traffic,
                fail_closed,
                "Prisma AIRS returned a response that is not JSON",
            );
        }
    };

    let action = parsed
        .get("action")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_ascii_lowercase();
    let category = parsed
        .get("category")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_string();
    let scan_id = string_field(&parsed, "scan_id");
    let report_id = string_field(&parsed, "report_id");

    if action == "block" {
        return block(
            block_status,
            Some(traffic),
            "block",
            if category == "unknown" {
                "malicious"
            } else {
                &category
            },
            "Prisma AIRS blocked this payload",
            scan_id.as_deref(),
            report_id.as_deref(),
        );
    }

    if action == "allow" {
        return Plan::Allow {
            headers: verdict_headers(
                traffic,
                "allow",
                &category,
                scan_id.as_deref(),
                report_id.as_deref(),
            ),
        };
    }

    unavailable(
        traffic,
        fail_closed,
        "Prisma AIRS response did not include an allow or block action",
    )
}

/// Scan transport failed before an HTTP status was available.
pub fn decide_transport_error(traffic: TrafficKind, fail_closed: bool, message: &str) -> Plan {
    unavailable(traffic, fail_closed, message)
}

fn plan_text(input: &ScanInput<'_>, text: &str, query: Option<&str>) -> Plan {
    let Some(traffic) = classify(input) else {
        return allow_skipped(None, "unclassified");
    };
    if !class_enabled(input, traffic) {
        return allow_skipped(Some(traffic), "disabled");
    }

    let schema = if traffic == TrafficKind::Llm {
        detect_schema(input, text)
    } else {
        None
    };

    let scanned_text = match (text.is_empty(), query) {
        (true, Some(query)) => query.to_string(),
        (false, Some(query)) => format!("{text}\n{query}"),
        _ => text.to_string(),
    };

    if scanned_text.trim().is_empty() {
        return allow_skipped(Some(traffic), "empty");
    }

    let native_body = schema.and_then(|schema| {
        serde_json::from_str::<Value>(text)
            .ok()
            .filter(|value| value.is_object())
            .map(|payload| scan_document(input, traffic, Some((schema, payload)), None))
    });

    let limit = match input.direction {
        Direction::Request => PROMPT_LIMIT,
        Direction::Response => RESPONSE_LIMIT,
    };
    let mut extracted =
        extract_text(input.direction, schema, text).unwrap_or_else(|| scanned_text.clone());
    if let Some(query) = query {
        if !extracted.contains(query) {
            if !extracted.is_empty() {
                extracted.push('\n');
            }
            extracted.push_str(query);
        }
    }
    let text_body = scan_document(input, traffic, None, Some(truncate(&extracted, limit)));

    match native_body {
        Some(body) => Plan::Scan(PreparedScan {
            traffic,
            body,
            text_fallback: Some(text_body),
        }),
        None => Plan::Scan(PreparedScan {
            traffic,
            body: text_body,
            text_fallback: None,
        }),
    }
}

fn classify(input: &ScanInput<'_>) -> Option<TrafficKind> {
    let path = input.path.to_ascii_lowercase();
    let parsed = serde_json::from_slice::<Value>(input.body).ok();

    if input.mcp_channel
        || path.contains("/mcp")
        || parsed.as_ref().is_some_and(is_mcp_jsonrpc)
    {
        return Some(TrafficKind::Mcp);
    }

    if is_llm_path(&path) || input.anthropic || parsed.as_ref().is_some_and(looks_like_llm) {
        return Some(TrafficKind::Llm);
    }

    if input.direction == Direction::Request && !query_string(input.path).trim().is_empty() {
        return Some(TrafficKind::Rest);
    }

    if !input.body.is_empty() {
        return Some(TrafficKind::Rest);
    }

    None
}

fn class_enabled(input: &ScanInput<'_>, traffic: TrafficKind) -> bool {
    match traffic {
        TrafficKind::Llm => input.scan_llm,
        TrafficKind::Rest => input.scan_rest,
        TrafficKind::Mcp => input.scan_mcp,
    }
}

fn detect_schema(input: &ScanInput<'_>, text: &str) -> Option<&'static str> {
    let path = input.path.to_ascii_lowercase();
    let parsed = serde_json::from_str::<Value>(text).ok();

    if path.contains("chat/completions") {
        return Some(OPENAI_CHAT);
    }
    if input.anthropic || path.contains("/v1/messages") || path.ends_with("/messages") {
        return Some(ANTHROPIC_MESSAGES);
    }
    if path.contains("/v1/responses") || path.ends_with("/responses") {
        return Some(OPENAI_RESPONSES);
    }

    let value = parsed?;
    if looks_like_chat(&value) {
        return Some(if input.anthropic {
            ANTHROPIC_MESSAGES
        } else {
            OPENAI_CHAT
        });
    }
    if value.get("input").is_some() && value.get("model").is_some() {
        return Some(OPENAI_RESPONSES);
    }
    None
}

fn looks_like_llm(value: &Value) -> bool {
    looks_like_chat(value) || (value.get("input").is_some() && value.get("model").is_some())
}

fn looks_like_chat(value: &Value) -> bool {
    value
        .get("messages")
        .and_then(Value::as_array)
        .is_some_and(|messages| {
            messages.iter().any(|message| {
                message
                    .get("role")
                    .and_then(Value::as_str)
                    .is_some()
            })
        })
}

fn is_mcp_jsonrpc(value: &Value) -> bool {
    match value {
        Value::Array(items) => items.iter().any(is_mcp_jsonrpc),
        Value::Object(_) => value.get("jsonrpc").and_then(Value::as_str) == Some("2.0")
            && value
                .get("method")
                .and_then(Value::as_str)
                .is_some_and(is_mcp_method),
        _ => false,
    }
}

fn is_mcp_method(method: &str) -> bool {
    method.starts_with("tools/")
        || method.starts_with("resources/")
        || method.starts_with("prompts/")
        || method.starts_with("sampling/")
        || method.starts_with("notifications/")
        || method.starts_with("completion/")
        || matches!(method, "initialize" | "ping" | "logging/setLevel")
}

fn is_llm_path(path: &str) -> bool {
    path.contains("chat/completions")
        || path.contains("/v1/responses")
        || path.ends_with("/responses")
        || path.contains("/v1/messages")
        || path.ends_with("/messages")
}

fn is_textual(content_type: &str, body: &[u8]) -> bool {
    let ct = content_type.to_ascii_lowercase();
    if ct.starts_with("image/")
        || ct.starts_with("audio/")
        || ct.starts_with("video/")
        || ct.contains("octet-stream")
        || ct.contains("application/pdf")
        || ct.contains("application/zip")
        || ct.contains("application/gzip")
        || ct.contains("protobuf")
    {
        return false;
    }
    if ct.contains("json")
        || ct.starts_with("text/")
        || ct.contains("xml")
        || ct.contains("graphql")
        || ct.contains("yaml")
        || ct.contains("form-urlencoded")
        || ct.contains("javascript")
        || ct.contains("event-stream")
        || ct.is_empty()
    {
        return std::str::from_utf8(body).is_ok();
    }
    std::str::from_utf8(body).is_ok()
}

fn scan_document(
    input: &ScanInput<'_>,
    traffic: TrafficKind,
    native: Option<(&'static str, Value)>,
    text: Option<String>,
) -> Vec<u8> {
    let mut document = Map::new();
    document.insert("ai_profile".to_string(), profile(input));

    if let Some(tr_id) = transaction_id(input) {
        document.insert("tr_id".to_string(), Value::String(truncate(&tr_id, 128)));
    }

    let metadata = metadata(input, traffic);
    if !metadata.is_empty() {
        document.insert("metadata".to_string(), Value::Object(metadata));
    }

    match native {
        Some((schema, payload)) => {
            document.insert("contents".to_string(), json!([]));
            document.insert(
                "native".to_string(),
                json!({
                    "schema": schema,
                    "direction": direction_name(input.direction),
                    "payload": payload,
                }),
            );
        }
        None => {
            let text = text.unwrap_or_default();
            let content = match input.direction {
                Direction::Request => json!({ "prompt": text }),
                Direction::Response => json!({ "response": text }),
            };
            document.insert("contents".to_string(), Value::Array(vec![content]));
        }
    }

    serde_json::to_vec(&Value::Object(document)).unwrap_or_else(|_| b"{}".to_vec())
}

fn profile(input: &ScanInput<'_>) -> Value {
    let mut profile = Map::new();
    if !input.profile_name.is_empty() {
        profile.insert(
            "profile_name".to_string(),
            Value::String(input.profile_name.to_string()),
        );
    }
    if let Some(profile_id) = input.profile_id.filter(|value| !value.is_empty()) {
        profile.insert(
            "profile_id".to_string(),
            Value::String(profile_id.to_string()),
        );
    }
    Value::Object(profile)
}

fn metadata(input: &ScanInput<'_>, traffic: TrafficKind) -> Map<String, Value> {
    let mut metadata = Map::new();
    let model = model_name(input, traffic).unwrap_or_else(|| traffic.as_str().to_string());
    metadata.insert("ai_model".to_string(), Value::String(model));
    if let Some(app_name) = input.app_name.filter(|value| !value.is_empty()) {
        metadata.insert("app_name".to_string(), Value::String(app_name.to_string()));
    }
    if let Some(app_user) = input.app_user.filter(|value| !value.is_empty()) {
        metadata.insert("app_user".to_string(), Value::String(app_user.to_string()));
    }
    if let Some(user_ip) = input.user_ip.filter(|value| !value.is_empty()) {
        metadata.insert(
            "user_ip".to_string(),
            Value::String(user_ip.split(',').next().unwrap_or(user_ip).trim().to_string()),
        );
    }
    metadata
}

fn model_name(input: &ScanInput<'_>, traffic: TrafficKind) -> Option<String> {
    let parsed = serde_json::from_slice::<Value>(input.body).ok()?;
    parsed
        .get("model")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .or({
            if traffic == TrafficKind::Mcp {
                mcp_method(input.body).map(|method| format!("mcp:{method}"))
            } else {
                None
            }
        })
}

fn mcp_method(body: &[u8]) -> Option<String> {
    let value: Value = serde_json::from_slice(body).ok()?;
    let method = match &value {
        Value::Object(_) => value.get("method").and_then(Value::as_str),
        Value::Array(items) => items.iter().find_map(|item| item.get("method").and_then(Value::as_str)),
        _ => None,
    }?;
    Some(method.to_string())
}

fn transaction_id(input: &ScanInput<'_>) -> Option<String> {
    if let Some(id) = input.transaction_id.filter(|value| !value.is_empty()) {
        return Some((*id).to_string());
    }
    let value: Value = serde_json::from_slice(input.body).ok()?;
    match value.get("id")? {
        Value::String(id) if !id.is_empty() => Some(id.clone()),
        Value::Number(id) => Some(id.to_string()),
        _ => None,
    }
}

fn extract_text(direction: Direction, schema: Option<&str>, text: &str) -> Option<String> {
    let value: Value = serde_json::from_str(text).ok()?;
    let extracted = match (direction, schema) {
        (Direction::Request, Some(OPENAI_CHAT | ANTHROPIC_MESSAGES)) => last_role_text(&value, "user"),
        (Direction::Response, Some(OPENAI_CHAT)) => choice_text(&value),
        (Direction::Response, Some(ANTHROPIC_MESSAGES)) => content_text(value.get("content")?),
        (Direction::Request, Some(OPENAI_RESPONSES)) => input_text(&value),
        (Direction::Response, Some(OPENAI_RESPONSES)) => value
            .get("output_text")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            .or_else(|| content_text(value.get("output")?)),
        (Direction::Request, _) => last_role_text(&value, "user"),
        (Direction::Response, _) => choice_text(&value)
            .or_else(|| value.get("content").and_then(content_text)),
    };
    extracted.filter(|text| !text.trim().is_empty())
}

fn last_role_text(value: &Value, role: &str) -> Option<String> {
    value
        .get("messages")?
        .as_array()?
        .iter()
        .rev()
        .find(|message| message.get("role").and_then(Value::as_str) == Some(role))
        .and_then(|message| content_text(message.get("content")?))
}

fn choice_text(value: &Value) -> Option<String> {
    let choice = value.get("choices")?.as_array()?.first()?;
    content_text(choice.get("message")?.get("content")?)
        .or_else(|| choice.get("text").and_then(Value::as_str).map(ToOwned::to_owned))
}

fn input_text(value: &Value) -> Option<String> {
    content_text(value.get("input")?)
}

fn content_text(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => Some(text.clone()),
        Value::Array(items) => {
            let text = items
                .iter()
                .filter_map(|item| {
                    item.as_str()
                        .map(ToOwned::to_owned)
                        .or_else(|| item.get("text").and_then(Value::as_str).map(ToOwned::to_owned))
                        .or_else(|| {
                            item.get("content")
                                .and_then(Value::as_str)
                                .map(ToOwned::to_owned)
                        })
                })
                .filter(|part| !part.is_empty())
                .collect::<Vec<_>>()
                .join("\n");
            if text.is_empty() {
                None
            } else {
                Some(text)
            }
        }
        Value::Object(_) => value
            .get("text")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        _ => None,
    }
}

fn direction_name(direction: Direction) -> &'static str {
    match direction {
        Direction::Request => "request",
        Direction::Response => "response",
    }
}

fn query_string(path: &str) -> &str {
    path.split_once('?').map(|(_, query)| query).unwrap_or("")
}

fn truncate(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_string();
    }
    value.chars().take(max_chars).collect()
}

fn string_field(value: &Value, name: &str) -> Option<String> {
    value
        .get(name)
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .map(ToOwned::to_owned)
}

fn unavailable(traffic: TrafficKind, fail_closed: bool, detail: &str) -> Plan {
    if fail_closed {
        block(
            502,
            Some(traffic),
            "scan_unavailable",
            "unscanned",
            detail,
            None,
            None,
        )
    } else {
        Plan::Allow {
            headers: verdict_headers(traffic, "allow", "unscanned", None, None),
        }
    }
}

fn allow_skipped(traffic: Option<TrafficKind>, reason: &str) -> Plan {
    let mut headers = vec![
        ("x-prisma-airs-action".to_string(), "skipped".to_string()),
        ("x-prisma-airs-category".to_string(), reason.to_string()),
    ];
    if let Some(traffic) = traffic {
        headers.push((
            "x-prisma-airs-traffic".to_string(),
            traffic.as_str().to_string(),
        ));
    }
    Plan::Allow { headers }
}

fn block(
    status: u16,
    traffic: Option<TrafficKind>,
    action: &str,
    category: &str,
    detail: &str,
    scan_id: Option<&str>,
    report_id: Option<&str>,
) -> Plan {
    let traffic_name = traffic.map(TrafficKind::as_str).unwrap_or("unknown");
    let body = json!({
        "error": "blocked_by_prisma_airs",
        "action": action,
        "category": category,
        "detail": detail,
        "traffic": traffic_name,
        "scan_id": scan_id,
        "report_id": report_id,
    })
    .to_string();
    let headers = match traffic {
        Some(traffic) => verdict_headers(traffic, action, category, scan_id, report_id),
        None => vec![(
            "x-prisma-airs-action".to_string(),
            action.to_string(),
        )],
    };
    Plan::Block {
        status,
        headers,
        body,
    }
}

fn verdict_headers(
    traffic: TrafficKind,
    action: &str,
    category: &str,
    scan_id: Option<&str>,
    report_id: Option<&str>,
) -> Vec<(String, String)> {
    let mut headers = vec![
        ("x-prisma-airs-action".to_string(), action.to_string()),
        ("x-prisma-airs-category".to_string(), category.to_string()),
        ("x-prisma-airs-traffic".to_string(), traffic.as_str().to_string()),
    ];
    if let Some(scan_id) = scan_id {
        headers.push(("x-prisma-airs-scan-id".to_string(), scan_id.to_string()));
    }
    if let Some(report_id) = report_id {
        headers.push(("x-prisma-airs-report-id".to_string(), report_id.to_string()));
    }
    headers
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input<'a>(direction: Direction, path: &'a str, body: &'a [u8]) -> ScanInput<'a> {
        ScanInput {
            direction,
            method: "POST",
            path,
            content_type: "application/json",
            mcp_channel: false,
            anthropic: false,
            body,
            profile_name: "runtime-profile",
            profile_id: None,
            app_name: Some("flex-gateway"),
            app_user: Some("ada"),
            user_ip: Some("203.0.113.8, 10.0.0.4"),
            transaction_id: Some("req-1"),
            scan_llm: true,
            scan_rest: true,
            scan_mcp: true,
            block_unscannable: false,
            block_status: 403,
        }
    }

    fn scanned(plan: Plan) -> Value {
        match plan {
            Plan::Scan(prepared) => serde_json::from_slice(&prepared.body).unwrap(),
            other => panic!("expected a scan, got {other:?}"),
        }
    }

    #[test]
    fn openai_chat_request_uses_native_schema_and_keeps_a_text_fallback() {
        let body = br#"{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hello"}]}"#;
        let plan = prepare_scan(&input(
            Direction::Request,
            "/v1/chat/completions",
            body,
        ));
        let Plan::Scan(prepared) = plan else {
            panic!("expected scan");
        };
        let document = serde_json::from_slice::<Value>(&prepared.body).unwrap();
        assert_eq!(document["native"]["schema"], OPENAI_CHAT);
        assert_eq!(document["native"]["direction"], "request");
        assert_eq!(document["native"]["payload"]["model"], "gpt-4o-mini");
        assert!(document["contents"].as_array().unwrap().is_empty());
        let fallback = serde_json::from_slice::<Value>(prepared.text_fallback.unwrap().as_slice()).unwrap();
        assert_eq!(fallback["contents"][0]["prompt"], "hello");
        assert_eq!(fallback["metadata"]["ai_model"], "gpt-4o-mini");
        assert_eq!(fallback["metadata"]["user_ip"], "203.0.113.8");
    }

    #[test]
    fn anthropic_response_extracts_assistant_text() {
        let body = br#"{"model":"claude","role":"assistant","content":[{"type":"text","text":"answer"}]}"#;
        let mut sample = input(Direction::Response, "/v1/messages", body);
        sample.anthropic = true;
        let document = scanned(prepare_scan(&sample));
        assert_eq!(document["native"]["schema"], ANTHROPIC_MESSAGES);
        assert_eq!(document["native"]["direction"], "response");
    }

    #[test]
    fn mcp_tool_call_is_scanned_as_prompt_text() {
        let body = br#"{"jsonrpc":"2.0","id":"7","method":"tools/call","params":{"name":"lookup","arguments":{"q":"secret"}}}"#;
        let document = scanned(prepare_scan(&input(Direction::Request, "/mcp", body)));
        assert!(document.get("native").is_none());
        assert!(document["contents"][0]["prompt"]
            .as_str()
            .unwrap()
            .contains("tools/call"));
        assert_eq!(document["metadata"]["ai_model"], "mcp:tools/call");
        assert_eq!(document["tr_id"], "req-1");
    }

    #[test]
    fn rest_response_is_scanned_as_model_response() {
        let body = br#"{"account":"123"}"#;
        let document = scanned(prepare_scan(&input(
            Direction::Response,
            "/customers/1",
            body,
        )));
        assert_eq!(document["contents"][0]["response"], r#"{"account":"123"}"#);
        assert_eq!(document["metadata"]["ai_model"], "rest");
        assert!(document["contents"][0].get("prompt").is_none());
    }

    #[test]
    fn query_only_rest_request_is_scanned() {
        let document = scanned(prepare_scan(&input(
            Direction::Request,
            "/search?q=ignore%20instructions",
            b"",
        )));
        assert_eq!(document["contents"][0]["prompt"], "q=ignore%20instructions");
    }

    #[test]
    fn empty_get_is_not_scanned() {
        let mut sample = input(Direction::Request, "/health", b"");
        sample.method = "GET";
        assert!(matches!(prepare_scan(&sample), Plan::Allow { .. }));
    }

    #[test]
    fn disabled_llm_class_skips_the_scan() {
        let mut sample = input(
            Direction::Request,
            "/v1/chat/completions",
            br#"{"messages":[{"role":"user","content":"hi"}]}"#,
        );
        sample.scan_llm = false;
        match prepare_scan(&sample) {
            Plan::Allow { headers } => {
                assert!(headers.iter().any(|(key, value)| key == "x-prisma-airs-action" && value == "skipped"));
            }
            other => panic!("expected skip, got {other:?}"),
        }
    }

    #[test]
    fn block_verdict_stops_and_alert_verdict_allows() {
        let blocked = decide_scan(
            TrafficKind::Llm,
            200,
            br#"{"action":"block","category":"malicious","scan_id":"s1","report_id":"r1"}"#,
            true,
            403,
        );
        match blocked {
            Plan::Block { status, body, .. } => {
                assert_eq!(status, 403);
                assert!(body.contains("\"scan_id\":\"s1\""));
            }
            other => panic!("expected block, got {other:?}"),
        }

        let alert = decide_scan(
            TrafficKind::Llm,
            200,
            br#"{"action":"allow","category":"malicious"}"#,
            true,
            403,
        );
        match alert {
            Plan::Allow { headers } => {
                assert!(headers.iter().any(|(key, value)| key == "x-prisma-airs-action" && value == "allow"));
                assert!(headers.iter().any(|(key, value)| key == "x-prisma-airs-category" && value == "malicious"));
            }
            other => panic!("expected allow, got {other:?}"),
        }
    }

    #[test]
    fn scanner_failure_follows_fail_closed() {
        assert!(matches!(
            decide_scan(TrafficKind::Rest, 503, b"upstream", true, 403),
            Plan::Block { status: 502, .. }
        ));
        assert!(matches!(
            decide_transport_error(TrafficKind::Rest, false, "timeout"),
            Plan::Allow { .. }
        ));
    }

    #[test]
    fn binary_payload_is_skipped_unless_unscannable_payloads_are_blocked() {
        let mut sample = input(Direction::Request, "/files", b"\x00\x01\x02");
        sample.content_type = "application/octet-stream";
        assert!(matches!(prepare_scan(&sample), Plan::Allow { .. }));
        sample.block_unscannable = true;
        assert!(matches!(prepare_scan(&sample), Plan::Block { status: 403, .. }));
    }
}
