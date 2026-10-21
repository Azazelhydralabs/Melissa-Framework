//! Host-reviewed output modes bound to one registration and exact wire identity.
//! Selecting a JSON mode never declares that a provider supports it.
use crate::{
    GatewayError, Protocol, Result, routing::ModelRegistration, transport::ProviderEndpoint,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputMode {
    NativeJsonSchema,
    JsonObject,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutputCapabilityRegistration {
    pub registration_id: String,
    pub provider_id: String,
    pub resource_id: String,
    pub authorization_ref: String,
    pub model_id: String,
    pub protocol: Protocol,
    pub endpoint: String,
    pub json_object: bool,
    pub native_json_schema: bool,
    /// A host-owned evidence/configuration reference, never model-supplied text.
    pub evidence_ref: String,
}
impl OutputCapabilityRegistration {
    pub fn for_model(
        model: &ModelRegistration,
        json_object: bool,
        native_json_schema: bool,
        evidence_ref: String,
    ) -> Result<Self> {
        model.validate()?;
        if native_json_schema && !model.capabilities.structured_output {
            return Err(GatewayError::invalid(
                "native output capability exceeds model declaration",
            ));
        }
        let record = Self {
            registration_id: model.registration_id.clone(),
            provider_id: model.endpoint.provider_id.clone(),
            resource_id: model.endpoint.resource_id.clone(),
            authorization_ref: model.endpoint.authorization_ref.clone(),
            model_id: model.model_id.clone(),
            protocol: model.endpoint.protocol,
            endpoint: model.endpoint.url.as_str().into(),
            json_object,
            native_json_schema,
            evidence_ref,
        };
        record.validate()?;
        Ok(record)
    }
    fn validate(&self) -> Result<()> {
        for field in [
            &self.registration_id,
            &self.provider_id,
            &self.resource_id,
            &self.authorization_ref,
            &self.model_id,
            &self.evidence_ref,
        ] {
            if field.is_empty() || field.len() > 512 || !field.bytes().all(|b| b.is_ascii_graphic())
            {
                return Err(GatewayError::invalid(
                    "output capability identity/evidence bounds",
                ));
            }
        }
        let url = url::Url::parse(&self.endpoint)
            .map_err(|_| GatewayError::invalid("output capability endpoint"))?;
        if self.endpoint.len() > 2048
            || url.as_str() != self.endpoint
            || !matches!(url.scheme(), "https" | "http")
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(GatewayError::invalid("output capability endpoint identity"));
        }
        if self.json_object && self.protocol != Protocol::OpenAiResponses {
            return Err(GatewayError::unsupported(
                "JSON-object adapter requires Responses",
            ));
        }
        Ok(())
    }
    fn matches_endpoint(&self, endpoint: &ProviderEndpoint, model_id: &str) -> bool {
        self.provider_id == endpoint.provider_id
            && self.resource_id == endpoint.resource_id
            && self.authorization_ref == endpoint.authorization_ref
            && self.protocol == endpoint.protocol
            && self.endpoint == endpoint.url.as_str()
            && self.model_id == model_id
    }
    fn supports(&self, mode: OutputMode) -> bool {
        match mode {
            OutputMode::NativeJsonSchema => self.native_json_schema,
            OutputMode::JsonObject => self.json_object,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct OutputCapabilityRegistry {
    records: BTreeMap<String, OutputCapabilityRegistration>,
}
impl OutputCapabilityRegistry {
    pub fn new(records: Vec<OutputCapabilityRegistration>) -> Result<Self> {
        if records.len() > 4096 {
            return Err(GatewayError::invalid("output capability registry bounds"));
        }
        let mut out = Self::default();
        for record in records {
            record.validate()?;
            if out.records.contains_key(&record.registration_id)
                || out.records.values().any(|r| {
                    r.provider_id == record.provider_id
                        && r.model_id == record.model_id
                        && r.protocol == record.protocol
                        && r.endpoint == record.endpoint
                })
            {
                return Err(GatewayError::invalid(
                    "duplicate output capability identity",
                ));
            }
            out.records.insert(record.registration_id.clone(), record);
        }
        Ok(out)
    }
    pub fn validate_models(&self, models: &[ModelRegistration]) -> Result<()> {
        for record in self.records.values() {
            let model = models
                .iter()
                .find(|m| m.registration_id == record.registration_id)
                .ok_or_else(|| GatewayError::invalid("unknown output capability registration"))?;
            if !record.matches_endpoint(&model.endpoint, &model.model_id)
                || (record.native_json_schema && !model.capabilities.structured_output)
            {
                return Err(GatewayError::invalid(
                    "output capability differs from model binding",
                ));
            }
        }
        Ok(())
    }
    pub fn record(&self, registration_id: &str) -> Option<&OutputCapabilityRegistration> {
        self.records.get(registration_id)
    }
    pub(crate) fn supports_model(&self, model: &ModelRegistration, mode: OutputMode) -> bool {
        match self.record(&model.registration_id) {
            Some(r) => r.matches_endpoint(&model.endpoint, &model.model_id) && r.supports(mode),
            // Preserve the existing native-only declaration; it cannot imply JSON-object.
            None => mode == OutputMode::NativeJsonSchema && model.capabilities.structured_output,
        }
    }
    pub(crate) fn check_wire(
        &self,
        endpoint: &ProviderEndpoint,
        model_id: &str,
        mode: OutputMode,
    ) -> Result<()> {
        let record = self
            .records
            .values()
            .find(|r| r.matches_endpoint(endpoint, model_id));
        match record {
            Some(r) if r.supports(mode) => Ok(()),
            None if mode == OutputMode::NativeJsonSchema
                && !self
                    .records
                    .values()
                    .any(|r| r.provider_id == endpoint.provider_id && r.model_id == model_id) =>
            {
                Ok(())
            }
            _ => Err(GatewayError::unsupported(
                "output mode has no matching host capability evidence",
            )),
        }
    }
}
