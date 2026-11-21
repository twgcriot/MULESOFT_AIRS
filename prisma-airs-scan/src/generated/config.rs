use serde::Deserialize;

/// Generated from definition/gcl.yaml. `make build-asset-files` rewrites this file.
#[derive(Deserialize, Clone, Debug)]
pub struct Config {
    #[serde(
        alias = "airsService",
        deserialize_with = "pdk::serde::deserialize_service"
    )]
    pub airs_service: pdk::hl::Service,
    #[serde(alias = "apiKey")]
    pub api_key: String,
    #[serde(alias = "appName")]
    pub app_name: Option<String>,
    #[serde(alias = "blockStatusCode")]
    pub block_status_code: i64,
    #[serde(alias = "blockUnscannable")]
    pub block_unscannable: bool,
    #[serde(alias = "failClosed")]
    pub fail_closed: bool,
    #[serde(alias = "profileId")]
    pub profile_id: Option<String>,
    #[serde(alias = "profileName")]
    pub profile_name: String,
    #[serde(alias = "scanLlm")]
    pub scan_llm: bool,
    #[serde(alias = "scanMcp")]
    pub scan_mcp: bool,
    #[serde(alias = "scanPath")]
    pub scan_path: String,
    #[serde(alias = "scanRequests")]
    pub scan_requests: bool,
    #[serde(alias = "scanResponses")]
    pub scan_responses: bool,
    #[serde(alias = "scanRest")]
    pub scan_rest: bool,
    #[serde(alias = "timeoutMs")]
    pub timeout_ms: i64,
    #[serde(alias = "userHeader")]
    pub user_header: String,
}

#[pdk::hl::entrypoint_flex]
fn init(abi: &dyn pdk::flex_abi::api::FlexAbi) -> Result<(), anyhow::Error> {
    let config: Config = serde_json::from_slice(abi.get_configuration()).map_err(|err| {
        anyhow::anyhow!(
            "Failed to parse configuration '{}'. Cause: {}",
            String::from_utf8_lossy(abi.get_configuration()),
            err
        )
    })?;
    abi.service_create(config.airs_service)?;
    abi.setup()?;
    Ok(())
}
