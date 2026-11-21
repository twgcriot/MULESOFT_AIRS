mod generated;

use std::time::Duration;

use anyhow::{anyhow, Result};
use pdk::hl::*;
use pdk::logger;
use prisma_airs_scan_core::{
    decide_scan, decide_transport_error, prepare_scan, Direction, Plan, PreparedScan, ScanInput,
};

use crate::generated::config::Config;

const AIRS_HOST: &str = "service.api.aisecurity.paloaltonetworks.com";

#[entrypoint]
async fn configure(launcher: Launcher, Configuration(bytes): Configuration) -> Result<()> {
    let config: Config = serde_json::from_slice(&bytes).map_err(|err| {
        anyhow!(
            "Failed to parse configuration '{}'. Cause: {err}",
            String::from_utf8_lossy(&bytes)
        )
    })?;
    if config.api_key.is_empty() {
        return Err(anyhow!("Prisma AIRS apiKey is empty"));
    }
    if config.profile_name.is_empty()
        && config
            .profile_id
            .as_deref()
            .unwrap_or("")
            .is_empty()
    {
        return Err(anyhow!(
            "Set profileName or profileId to a Prisma AIRS AI security profile"
        ));
    }

    let filter = on_request(|request, client| request_filter(request, client, &config)).on_response(
        |response, request_data, client| {
            response_filter(response, request_data, client, &config)
        },
    );
    launcher.launch(filter).await?;
    Ok(())
}

/// Request path and protocol hints. Response headers do not carry `:path`, so the response
/// scan uses this value to recognize LLM and MCP traffic.
#[derive(Clone, Debug)]
struct ExchangeHint {
    method: String,
    path: String,
    mcp_channel: bool,
    anthropic: bool,
}

async fn request_filter(
    request_state: RequestState,
    client: HttpClient,
    config: &Config,
) -> Flow<ExchangeHint> {
    if !config.scan_requests {
        let state = request_state.into_headers_state().await;
        return Flow::Continue(hint_from(&capture(
            state.handler().headers(),
            Vec::new(),
            config,
        )));
    }

    let state = request_state.into_headers_body_state().await;
    let body = if state.contains_body() {
        state.handler().body()
    } else {
        Vec::new()
    };
    let captured = capture(state.handler().headers(), body, config);
    let hint = hint_from(&captured);
    let plan = enforce(&captured, Direction::Request, config, &client).await;
    log_plan("request", &plan);
    match plan {
        Plan::Allow { headers } => {
            for (name, value) in &headers {
                state.handler().set_header(name, value);
            }
            Flow::Continue(hint)
        }
        Plan::Block {
            status,
            headers,
            body,
        } => Flow::Break(reject_response(status, headers, body)),
        Plan::Scan(_) => Flow::Continue(hint),
    }
}

async fn response_filter(
    response_state: ResponseState,
    request_data: RequestData<ExchangeHint>,
    client: HttpClient,
    config: &Config,
) {
    let RequestData::Continue(hint) = request_data else {
        return;
    };
    if !config.scan_responses {
        return;
    }

    let state = response_state.into_headers_body_state().await;
    let body = if state.contains_body() {
        state.handler().body()
    } else {
        Vec::new()
    };
    let mut captured = capture(state.handler().headers(), body, config);
    captured.method = hint.method;
    captured.path = hint.path;
    captured.mcp_channel = captured.mcp_channel || hint.mcp_channel;
    captured.anthropic = captured.anthropic || hint.anthropic;
    let plan = enforce(&captured, Direction::Response, config, &client).await;
    log_plan("response", &plan);
    match plan {
        Plan::Allow { headers } => {
            for (name, value) in &headers {
                state.handler().set_header(name, value);
            }
        }
        Plan::Block {
            status,
            headers,
            body,
        } => {
            let handler = state.handler();
            handler.remove_header("content-encoding");
            handler.set_header(":status", &status.to_string());
            for (name, value) in &headers {
                handler.set_header(name, value);
            }
            handler.set_header("content-type", "application/json");
            if state.contains_body() {
                let _ = handler.set_sized_body(body.as_bytes());
            }
        }
        Plan::Scan(_) => {}
    }
}

async fn enforce(
    captured: &Captured,
    direction: Direction,
    config: &Config,
    client: &HttpClient,
) -> Plan {
    let input = ScanInput {
        direction,
        method: &captured.method,
        path: &captured.path,
        content_type: &captured.content_type,
        mcp_channel: captured.mcp_channel,
        anthropic: captured.anthropic,
        body: &captured.body,
        profile_name: &config.profile_name,
        profile_id: config.profile_id.as_deref(),
        app_name: config.app_name.as_deref(),
        app_user: captured.app_user.as_deref(),
        user_ip: captured.user_ip.as_deref(),
        transaction_id: captured.transaction_id.as_deref(),
        scan_llm: config.scan_llm,
        scan_rest: config.scan_rest,
        scan_mcp: config.scan_mcp,
        block_unscannable: config.block_unscannable,
        block_status: block_status(config),
    };

    match prepare_scan(&input) {
        Plan::Scan(prepared) => evaluate_scan(prepared, config, client).await,
        plan => plan,
    }
}

async fn evaluate_scan(prepared: PreparedScan, config: &Config, client: &HttpClient) -> Plan {
    let PreparedScan {
        traffic,
        body,
        text_fallback,
    } = prepared;
    let fallback = match post_scan(client, config, &body).await {
        Ok((422, _)) => text_fallback,
        Ok((status, response_body)) => {
            return decide_scan(
                traffic,
                status,
                &response_body,
                config.fail_closed,
                block_status(config),
            );
        }
        Err(error) => return decide_transport_error(traffic, config.fail_closed, &error),
    };

    let Some(fallback) = fallback else {
        return decide_scan(traffic, 422, b"", config.fail_closed, block_status(config));
    };
    match post_scan(client, config, &fallback).await {
        Ok((status, response_body)) => {
            decide_scan(
                traffic,
                status,
                &response_body,
                config.fail_closed,
                block_status(config),
            )
        }
        Err(error) => decide_transport_error(traffic, config.fail_closed, &error),
    }
}

async fn post_scan(
    client: &HttpClient,
    config: &Config,
    body: &[u8],
) -> Result<(u16, Vec<u8>), String> {
    let response = client
        .request(&config.airs_service)
        .path(&config.scan_path)
        .timeout(Duration::from_millis(timeout_ms(config)))
        .headers(vec![
            ("content-type", "application/json"),
            ("accept", "application/json"),
            ("x-pan-token", config.api_key.as_str()),
        ])
        .body(body)
        .post()
        .await
        .map_err(|error| error.to_string())?;

    let status = u16::try_from(response.status_code()).unwrap_or(502);
    Ok((status, response.body().to_vec()))
}

fn hint_from(captured: &Captured) -> ExchangeHint {
    ExchangeHint {
        method: captured.method.clone(),
        path: captured.path.clone(),
        mcp_channel: captured.mcp_channel,
        anthropic: captured.anthropic,
    }
}

struct Captured {
    method: String,
    path: String,
    content_type: String,
    mcp_channel: bool,
    anthropic: bool,
    app_user: Option<String>,
    user_ip: Option<String>,
    transaction_id: Option<String>,
    body: Vec<u8>,
}

fn capture(headers: Vec<(String, String)>, body: Vec<u8>, config: &Config) -> Captured {
    let content_type = header(&headers, "content-type").unwrap_or_default();
    let user_ip = header(&headers, "x-forwarded-for");
    let transaction_id = header(&headers, "x-request-id")
        .or_else(|| header(&headers, "x-correlation-id"))
        .or_else(|| header(&headers, "x-b3-traceid"));
    Captured {
        method: header(&headers, ":method").unwrap_or_else(|| "GET".to_string()),
        path: header(&headers, ":path").unwrap_or_else(|| "/".to_string()),
        mcp_channel: header(&headers, "mcp-session-id").is_some()
            || header(&headers, "mcp-protocol-version").is_some(),
        anthropic: header(&headers, "anthropic-version").is_some(),
        app_user: header(&headers, &config.user_header),
        user_ip,
        transaction_id,
        content_type,
        body,
    }
}

fn header(headers: &[(String, String)], name: &str) -> Option<String> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.clone())
}

fn reject_response(status: u16, headers: Vec<(String, String)>, body: String) -> Response {
    let mut response_headers = headers;
    response_headers.push(("content-type".to_string(), "application/json".to_string()));
    Response::new(u32::from(status))
        .with_headers(response_headers)
        .with_body(body)
}

fn block_status(config: &Config) -> u16 {
    u16::try_from(config.block_status_code)
        .ok()
        .filter(|status| (100..600).contains(status))
        .unwrap_or(403)
}

fn timeout_ms(config: &Config) -> u64 {
    u64::try_from(config.timeout_ms).unwrap_or(10_000).max(1)
}

fn log_plan(phase: &str, plan: &Plan) {
    match plan {
        Plan::Allow { headers } => logger::info!("Prisma AIRS {phase}: {}", header_text(headers)),
        Plan::Block {
            status, headers, ..
        } => logger::warn!(
            "Prisma AIRS {phase} blocked with HTTP {status}: {}",
            header_text(headers)
        ),
        Plan::Scan(_) => {}
    }
}

fn header_text(headers: &[(String, String)]) -> String {
    headers
        .iter()
        .filter(|(name, _)| name.starts_with("x-prisma-airs-"))
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use pdk_unit::{
        TraceBackend, UnitHttpMessage, UnitHttpRequest, UnitHttpResponse, UnitTestBuilder,
    };
    use serde_json::json;
    use std::rc::Rc;

    fn config() -> String {
        json!({
            "airsService": format!("https://{AIRS_HOST}"),
            "apiKey": "test-token",
            "profileName": "runtime-profile",
            "scanPath": "/v1/scan/sync/request",
            "scanRequests": true,
            "scanResponses": true,
            "scanLlm": true,
            "scanRest": true,
            "scanMcp": true,
            "failClosed": true,
            "blockUnscannable": false,
            "blockStatusCode": 403,
            "timeoutMs": 10000,
            "userHeader": "x-forwarded-user"
        })
        .to_string()
    }

    fn allow_scan(_: UnitHttpRequest) -> UnitHttpResponse {
        UnitHttpResponse::new(200)
            .with_body(r#"{"action":"allow","category":"benign","scan_id":"scan-allow"}"#)
    }

    fn block_scan(_: UnitHttpRequest) -> UnitHttpResponse {
        UnitHttpResponse::new(200)
            .with_body(r#"{"action":"block","category":"malicious","scan_id":"scan-block"}"#)
    }

    fn block_model_response(request: UnitHttpRequest) -> UnitHttpResponse {
        let body = String::from_utf8_lossy(request.body());
        if body.contains("\"direction\":\"response\"") || body.contains("\"response\":") {
            block_scan(request)
        } else {
            allow_scan(request)
        }
    }

    fn chat_request() -> UnitHttpRequest {
        UnitHttpRequest::post()
            .with_path("/v1/chat/completions")
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hello"}]}"#,
            )
    }

    #[test]
    fn allowed_llm_request_reaches_upstream() {
        let backend = Rc::new(TraceBackend::new(|_: UnitHttpRequest| {
            UnitHttpResponse::new(200).with_body(r#"{"ok":true}"#)
        }));
        let mut tester = UnitTestBuilder::default()
            .with_config(config())
            .with_backend(Rc::clone(&backend))
            .with_http_upstream_from_authority(AIRS_HOST, allow_scan)
            .with_entrypoint(configure);

        let response = tester.request(chat_request());

        assert_eq!(response.status_code(), 200);
        let upstream = backend.next().expect("upstream receives an allowed request");
        assert!(String::from_utf8_lossy(upstream.body()).contains("hello"));
        assert_eq!(response.header("x-prisma-airs-action"), Some("allow"));
    }

    #[test]
    fn blocked_llm_request_does_not_reach_upstream() {
        let backend = Rc::new(TraceBackend::new(UnitHttpResponse::new(200)));
        let mut tester = UnitTestBuilder::default()
            .with_config(config())
            .with_backend(Rc::clone(&backend))
            .with_http_upstream_from_authority(AIRS_HOST, block_scan)
            .with_entrypoint(configure);

        let response = tester.request(chat_request());

        assert_eq!(response.status_code(), 403);
        assert!(String::from_utf8_lossy(response.body()).contains("blocked_by_prisma_airs"));
        assert!(backend.next().is_none());
    }

    #[test]
    fn blocked_model_response_replaces_upstream_body() {
        let mut tester = UnitTestBuilder::default()
            .with_config(config())
            .with_backend(|_: UnitHttpRequest| {
                UnitHttpResponse::new(200).with_body(
                    r#"{"model":"gpt-4o-mini","choices":[{"message":{"role":"assistant","content":"leaked secret"}}]}"#,
                )
            })
            .with_http_upstream_from_authority(AIRS_HOST, block_model_response)
            .with_entrypoint(configure);

        let response = tester.request(chat_request());

        assert_eq!(response.status_code(), 403);
        let body = String::from_utf8_lossy(response.body());
        assert!(body.contains("scan-block"));
        assert!(!body.contains("leaked secret"));
    }

    #[test]
    fn scanner_outage_fails_closed() {
        let mut tester = UnitTestBuilder::default()
            .with_config(config())
            .with_http_upstream_from_authority(AIRS_HOST, |_: UnitHttpRequest| {
                UnitHttpResponse::new(503).with_body("unavailable")
            })
            .with_entrypoint(configure);

        let response = tester.request(chat_request());

        assert_eq!(response.status_code(), 502);
    }

    #[test]
    fn empty_request_skips_the_scanner() {
        let mut tester = UnitTestBuilder::default()
            .with_config(config())
            .with_backend(|_: UnitHttpRequest| UnitHttpResponse::new(204))
            .with_http_upstream_from_authority(AIRS_HOST, |_: UnitHttpRequest| {
                UnitHttpResponse::new(500)
            })
            .with_entrypoint(configure);

        let response = tester.request(UnitHttpRequest::get().with_path("/health"));

        assert_eq!(response.status_code(), 204);
    }
}
