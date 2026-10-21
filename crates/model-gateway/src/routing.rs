use crate::{
    GatewayError, Result, Usage,
    output_capabilities::{OutputCapabilityRegistry, OutputMode},
    transport::{EndpointTrust, ProviderEndpoint},
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, sync::Arc};
use tokio::sync::Semaphore;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Capabilities {
    pub tool_calling: bool,
    pub structured_output: bool,
    pub vision: bool,
    pub streaming: bool,
}
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Measurements {
    pub task_success_ppm: Option<u32>,
    pub first_pass_ppm: Option<u32>,
    pub repair_ppm: Option<u32>,
    pub average_tokens: Option<u64>,
    pub p95_latency_ms: Option<u64>,
    pub tool_error_ppm: Option<u32>,
    pub verification_cost_micro_usd: Option<u64>,
    pub availability_ppm: Option<u32>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PriceSource {
    Fixture,
    VerifiedHostRateCard {
        source_url: String,
        checked_at_unix_ms: u64,
    },
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateCard {
    pub source: PriceSource,
    pub input_micro_usd_per_million: u64,
    pub output_micro_usd_per_million: u64,
    pub cached_input_micro_usd_per_million: Option<u64>,
    pub cache_creation_micro_usd_per_million: Option<u64>,
}
impl RateCard {
    pub fn validate(&self, endpoint: &ProviderEndpoint) -> Result<()> {
        match &self.source {
            PriceSource::Fixture => {
                if endpoint.trust != EndpointTrust::LoopbackFixture {
                    return Err(GatewayError::invalid(
                        "fixture pricing cannot apply to a remote provider",
                    ));
                }
            }
            PriceSource::VerifiedHostRateCard {
                source_url,
                checked_at_unix_ms,
            } => {
                if *checked_at_unix_ms == 0
                    || !url::Url::parse(source_url).is_ok_and(|v| {
                        v.scheme() == "https" && v.username().is_empty() && v.password().is_none()
                    })
                {
                    return Err(GatewayError::invalid("rate-card verification metadata"));
                }
            }
        }
        Ok(())
    }
    pub fn digest(&self) -> String {
        format!(
            "blake3:{}",
            blake3::hash(&serde_json::to_vec(self).expect("rate-card serialization"))
        )
    }
    /// Conservative accounted upper bound under this host rate-card, not an invoice.
    pub fn upper_bound(&self, input: u64, output: u64) -> Result<u64> {
        let rate = self
            .input_micro_usd_per_million
            .max(
                self.cached_input_micro_usd_per_million
                    .unwrap_or(self.input_micro_usd_per_million),
            )
            .max(
                self.cache_creation_micro_usd_per_million
                    .unwrap_or(self.input_micro_usd_per_million),
            );
        let value = (input as u128)
            .checked_mul(rate as u128)
            .and_then(|v| {
                v.checked_add((output as u128) * self.output_micro_usd_per_million as u128)
            })
            .ok_or_else(|| GatewayError::invalid("price overflow"))?;
        u64::try_from(value.div_ceil(1_000_000))
            .map_err(|_| GatewayError::invalid("price does not fit budget"))
    }
    pub fn usage_upper_bound(&self, usage: &Usage) -> Result<Option<u64>> {
        match (usage.input_tokens, usage.output_tokens) {
            (Some(i), Some(o)) => self.upper_bound(i, o).map(Some),
            _ => Ok(None),
        }
    }
}
#[derive(Clone)]
pub struct ModelRegistration {
    pub registration_id: String,
    pub endpoint: ProviderEndpoint,
    pub model_id: String,
    pub capabilities: Capabilities,
    pub categories: BTreeSet<String>,
    pub context_tokens: u64,
    pub max_output_tokens: u64,
    pub timeout_ms: u64,
    pub max_concurrency: u32,
    pub rate_card: Option<RateCard>,
    pub measurements: Measurements,
    pub slots: Arc<Semaphore>,
}
impl ModelRegistration {
    pub fn validate(&self) -> Result<()> {
        if self.registration_id.trim().is_empty()
            || self.registration_id.len() > 256
            || self.model_id.trim().is_empty()
            || self.model_id.len() > 256
            || self.context_tokens == 0
            || self.max_output_tokens == 0
            || self.max_output_tokens > self.context_tokens
            || self.timeout_ms == 0
            || self.timeout_ms > 1_800_000
            || self.max_concurrency == 0
            || self.max_concurrency > 1024
            || self.slots.available_permits() > self.max_concurrency as usize
            || self.categories.is_empty()
        {
            return Err(GatewayError::invalid(
                "model capability registration bounds",
            ));
        }
        for v in [
            self.measurements.task_success_ppm,
            self.measurements.first_pass_ppm,
            self.measurements.repair_ppm,
            self.measurements.tool_error_ppm,
            self.measurements.availability_ppm,
        ]
        .into_iter()
        .flatten()
        {
            if v > 1_000_000 {
                return Err(GatewayError::invalid("measurement ratio"));
            }
        }
        if let Some(r) = &self.rate_card {
            r.validate(&self.endpoint)?;
        }
        Ok(())
    }
}
#[derive(Debug, Clone)]
pub struct RouteRequirements {
    pub category: String,
    pub tools: bool,
    pub structured_output: bool,
    pub vision: bool,
    pub minimum_success_ppm: Option<u32>,
    pub maximum_p95_ms: Option<u64>,
}
/// Classify -> capability -> required quality -> observed price/latency. Missing
/// measurements do not masquerade as success or zero latency. Ties are stable.
pub fn select_routes(
    models: &[ModelRegistration],
    requirements: &RouteRequirements,
    allowed: &BTreeSet<String>,
) -> Result<Vec<usize>> {
    select_routes_for_output_mode(
        models,
        requirements,
        allowed,
        OutputMode::NativeJsonSchema,
        &OutputCapabilityRegistry::default(),
    )
}
/// The requested structured contract remains required in either explicit mode.
pub fn select_routes_for_output_mode(
    models: &[ModelRegistration],
    requirements: &RouteRequirements,
    allowed: &BTreeSet<String>,
    mode: OutputMode,
    capabilities: &OutputCapabilityRegistry,
) -> Result<Vec<usize>> {
    capabilities.validate_models(models)?;
    let mut result = Vec::new();
    let mut ids = BTreeSet::new();
    for (index, m) in models.iter().enumerate() {
        m.validate()?;
        if !ids.insert(&m.registration_id) {
            return Err(GatewayError::invalid("duplicate model registration"));
        }
        if !allowed.contains(&m.registration_id)
            || !m.categories.contains(&requirements.category)
            || !m.capabilities.streaming
            || (requirements.tools && !m.capabilities.tool_calling)
            || (requirements.structured_output && !capabilities.supports_model(m, mode))
            || (requirements.vision && !m.capabilities.vision)
            || requirements
                .minimum_success_ppm
                .is_some_and(|v| m.measurements.task_success_ppm.is_none_or(|x| x < v))
            || requirements
                .maximum_p95_ms
                .is_some_and(|v| m.measurements.p95_latency_ms.is_none_or(|x| x > v))
        {
            continue;
        }
        result.push(index);
    }
    result.sort_by_key(|&i| {
        let m = &models[i];
        (
            std::cmp::Reverse(m.measurements.task_success_ppm.unwrap_or(0)),
            m.rate_card
                .as_ref()
                .and_then(|p| p.upper_bound(1000, 1000).ok())
                .unwrap_or(u64::MAX),
            m.measurements.p95_latency_ms.unwrap_or(u64::MAX),
            m.registration_id.clone(),
        )
    });
    if result.is_empty() {
        return Err(GatewayError::unsupported(
            "no host-authorized model satisfies requested capability/quality",
        ));
    }
    Ok(result)
}
