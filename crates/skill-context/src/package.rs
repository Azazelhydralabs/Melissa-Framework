//! Immutable byte packages. No filesystem path is opened and no helper runs.
use crate::{Error, Result, digest, json, require};
use melissa_core_contracts::{design::*, validation::Validate};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone)]
pub struct Package {
    definition: SkillDefinition,
    version: SkillVersion,
    files: BTreeMap<String, Vec<u8>>,
}

pub fn package_digest(
    definition_bytes: &[u8],
    files: &BTreeMap<String, Vec<u8>>,
) -> Result<String> {
    let entries: Vec<_> = files
        .iter()
        .map(|(path, bytes)| (path, digest(bytes)))
        .collect();
    Ok(digest(&serde_json::to_vec(&(
        "melissa.package-bytes/v1",
        digest(definition_bytes),
        entries,
    ))?))
}

impl Package {
    /// The trusted host supplies captured bytes and its exact expected pin.
    /// Publisher/release claims inside those bytes remain unauthenticated.
    pub fn load(
        definition_bytes: &[u8],
        version_bytes: &[u8],
        files: BTreeMap<String, Vec<u8>>,
        expected: &SkillPin,
    ) -> Result<Self> {
        expected.validate()?;
        let definition: SkillDefinition = json(definition_bytes)?;
        let version: SkillVersion = json(version_bytes)?;
        version.validate_definition(&definition)?;
        require(
            &version.pin == expected
                && version.definition_digest == digest(definition_bytes)
                && version.pin.content_digest == package_digest(definition_bytes, &files)?,
            "package pin or definition digest mismatch",
        )?;
        require(
            files.len() == definition.files.len(),
            "missing or undeclared package bytes",
        )?;
        let mut total = definition_bytes
            .len()
            .checked_add(version_bytes.len())
            .ok_or_else(|| Error("package size overflow".into()))?;
        for entry in &definition.files {
            let bytes = files
                .get(&entry.path)
                .ok_or_else(|| Error("missing package file".into()))?;
            total = total
                .checked_add(bytes.len())
                .ok_or_else(|| Error("package size overflow".into()))?;
            require(
                total <= 16 * 1024 * 1024 && digest(bytes) == entry.content_digest,
                "package byte limit or content mismatch",
            )?;
            if entry.role == PackageFileRole::Schema {
                let value: serde_json::Value = json(bytes)?;
                require(
                    value.is_object() || value.is_boolean(),
                    "schema must be a JSON object or boolean",
                )?;
                melissa_model_gateway::schema::validate_schema(&value)
                    .map_err(|e| Error(e.to_string()))?;
                // This milestone does not implement external JSON-schema resolution.
                fn local(v: &serde_json::Value) -> bool {
                    match v {
                        serde_json::Value::Object(o) => o.iter().all(|(k, v)| {
                            if matches!(k.as_str(), "$ref" | "$dynamicRef") {
                                v.as_str().is_some_and(|s| s.starts_with('#'))
                            } else {
                                local(v)
                            }
                        }),
                        serde_json::Value::Array(a) => a.iter().all(local),
                        _ => true,
                    }
                }
                require(local(&value), "external schema references are disabled")?;
            }
        }
        let md = std::str::from_utf8(&files["SKILL.md"])
            .map_err(|_| Error("SKILL.md is not UTF8".into()))?;
        // Parse LF and CRLF without modifying any captured/digested bytes.
        let md = md.replace("\r\n", "\n");
        let header = md
            .strip_prefix("---\n")
            .and_then(|s| s.split_once("\n---\n").map(|(h, _)| h));
        require(
            !md.contains('\r') && header.is_some(),
            "missing Agent Skills frontmatter",
        )?;
        let header = header.expect("checked");
        let mut fields = BTreeMap::new();
        for line in header.lines() {
            let (k, v) = line.split_once(": ").ok_or_else(|| {
                Error("unsupported frontmatter; expected flat name/description".into())
            })?;
            require(
                matches!(k, "name" | "description")
                    && !v.trim().is_empty()
                    && fields.insert(k, v).is_none(),
                "duplicate, empty or unsupported frontmatter",
            )?;
        }
        let name = fields.get("name").copied().unwrap_or_default();
        require(
            fields.len() == 2
                && name.len() <= 64
                && !name.starts_with('-')
                && !name.ends_with('-')
                && !name.contains("--")
                && name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                && fields.get("description").is_some_and(|d| d.len() <= 4096),
            "invalid Agent Skills identity or description",
        )?;
        Ok(Self {
            definition,
            version,
            files,
        })
    }
    pub fn definition(&self) -> &SkillDefinition {
        &self.definition
    }
    pub fn version(&self) -> &SkillVersion {
        &self.version
    }
    pub fn file(&self, path: &str) -> Result<&[u8]> {
        self.files
            .get(path)
            .map(Vec::as_slice)
            .ok_or_else(|| Error("undeclared package file".into()))
    }
    /// Full selected instructions, schemas, references, helpers and templates.
    /// Development tests/evaluation answers stay outside model context.
    pub fn material(&self) -> Result<Material> {
        let mut files = BTreeMap::new();
        for f in &self.definition.files {
            if !matches!(f.role, PackageFileRole::Test | PackageFileRole::Evaluation) {
                let bytes = &self.files[&f.path];
                let (encoding, content) = match std::str::from_utf8(bytes) {
                    Ok(text) => ("utf8", text.to_string()),
                    Err(_) => ("hex", bytes.iter().map(|b| format!("{b:02x}")).collect()),
                };
                files.insert(
                    f.path.clone(),
                    MaterialFile {
                        encoding: encoding.into(),
                        content,
                        content_digest: digest(bytes),
                    },
                );
            }
        }
        Ok(Material {
            pin: self.version.pin.clone(),
            definition: self.definition.clone(),
            files,
            authority: "untrusted_data_no_execution_grant".into(),
        })
    }
    /// Literal single-pass JSON binding; values cannot become placeholders/code.
    pub fn render(
        &self,
        path: &str,
        input: &BTreeMap<String, serde_json::Value>,
    ) -> Result<Vec<u8>> {
        let t = self
            .definition
            .templates
            .iter()
            .find(|t| t.file_path == path)
            .ok_or_else(|| Error("not a registered template".into()))?;
        let schema: serde_json::Value = json(self.file(&t.input_schema_ref)?)?;
        melissa_model_gateway::schema::validate_output(&schema, &serde_json::to_string(input)?)
            .map_err(|e| Error(e.to_string()))?;
        let text = std::str::from_utf8(self.file(path)?)
            .map_err(|_| Error("template must be UTF8".into()))?;
        let mut rest = text;
        let mut out = String::new();
        let mut used = BTreeSet::new();
        while let Some((before, after)) = rest.split_once("{{") {
            require(!before.contains("}}"), "unmatched closing template field")?;
            out.push_str(before);
            let (key, tail) = after
                .split_once("}}")
                .ok_or_else(|| Error("unclosed template field".into()))?;
            require(
                !key.is_empty() && key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'),
                "invalid template field",
            )?;
            let value = input
                .get(key)
                .ok_or_else(|| Error("missing template field".into()))?;
            out.push_str(&serde_json::to_string(value)?);
            used.insert(key.to_string());
            rest = tail;
        }
        require(
            !rest.contains("}}") && used.len() == input.len(),
            "unknown template input or unmatched closing field",
        )?;
        out.push_str(rest);
        let schema: serde_json::Value = json(self.file(&t.output_schema_ref)?)?;
        melissa_model_gateway::schema::validate_output(&schema, &serde_json::to_string(&out)?)
            .map_err(|e| Error(e.to_string()))?;
        Ok(out.into_bytes())
    }
    pub fn validate_script_input(&self, path: &str, input: &[u8]) -> Result<String> {
        let s = self
            .definition
            .scripts
            .iter()
            .find(|s| s.file_path == path)
            .ok_or_else(|| Error("undeclared helper".into()))?;
        let schema: serde_json::Value = json(self.file(&s.input_schema_ref)?)?;
        let text =
            std::str::from_utf8(input).map_err(|_| Error("helper input is not UTF8".into()))?;
        melissa_model_gateway::schema::validate_output(&schema, text)
            .map_err(|e| Error(e.to_string()))?;
        Ok(digest(input))
    }
    /// A plan is data for the existing broker, never an execution permit.
    pub fn script_plan(
        &self,
        path: &str,
        policy: &SkillPolicy,
        input_digest: &str,
    ) -> Result<ScriptPlan> {
        policy.check(self)?;
        let s = self
            .definition
            .scripts
            .iter()
            .find(|s| s.file_path == path)
            .ok_or_else(|| Error("undeclared helper".into()))?;
        require(
            policy.allow_helpers
                && input_digest.strip_prefix("blake3:").is_some_and(|s| {
                    s.len() == 64
                        && s.bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                }),
            "helper denied or invalid input digest",
        )?;
        Ok(ScriptPlan {
            pin: self.version.pin.clone(),
            script: s.clone(),
            script_digest: digest(self.file(path)?),
            input_digest: input_digest.into(),
            policy_epoch: policy.epoch.clone(),
            requires_broker_admission: true,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Material {
    pub pin: SkillPin,
    pub definition: SkillDefinition,
    pub files: BTreeMap<String, MaterialFile>,
    pub authority: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MaterialFile {
    pub encoding: String,
    pub content: String,
    pub content_digest: String,
}
impl MaterialFile {
    pub fn bytes(&self) -> Result<Vec<u8>> {
        let bytes = match self.encoding.as_str() {
            "utf8" => self.content.as_bytes().to_vec(),
            "hex" => {
                require(
                    self.content.len().is_multiple_of(2) && self.content.is_ascii(),
                    "invalid binary material",
                )?;
                (0..self.content.len())
                    .step_by(2)
                    .map(|i| {
                        u8::from_str_radix(&self.content[i..i + 2], 16)
                            .map_err(|_| Error("invalid binary material".into()))
                    })
                    .collect::<Result<Vec<_>>>()?
            }
            _ => return Err(Error("unknown material encoding".into())),
        };
        require(
            digest(&bytes) == self.content_digest,
            "material file digest mismatch",
        )?;
        Ok(bytes)
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScriptPlan {
    pub pin: SkillPin,
    pub script: ScriptReference,
    pub script_digest: String,
    pub input_digest: String,
    pub policy_epoch: String,
    pub requires_broker_admission: bool,
}

/// Constructed by the trusted host; never deserialize from model/package data.
#[derive(Debug, Clone)]
pub struct SkillPolicy {
    pub epoch: String,
    pub reviewed: BTreeSet<String>,
    pub publishers: BTreeSet<String>,
    pub revoked: BTreeSet<String>,
    pub tools: BTreeSet<String>,
    pub capabilities: BTreeSet<String>,
    pub allow_helpers: bool,
}
impl SkillPolicy {
    pub fn check(&self, p: &Package) -> Result<()> {
        let v = p.version();
        let d = p.definition();
        require(
            !self.epoch.trim().is_empty()
                && self.reviewed.contains(&v.pin.content_digest)
                && self.publishers.contains(&v.publisher_id)
                && !self.revoked.contains(&v.pin.content_digest)
                && !self.revoked.contains(&v.publisher_id)
                && !matches!(
                    v.state,
                    SkillReleaseState::Draft | SkillReleaseState::Revoked
                ),
            "unreviewed, revoked or draft package",
        )?;
        // Cryptographic publisher/release validation is deliberately not
        // implemented by this local milestone. Never accept a signature claim.
        require(
            v.state != SkillReleaseState::SignedRelease,
            "signed release requires a cryptographic publisher verifier",
        )?;
        require(
            d.manifest
                .required_tools
                .iter()
                .all(|x| self.tools.contains(x))
                && d.manifest
                    .required_capabilities
                    .iter()
                    .all(|x| self.capabilities.contains(x)),
            "missing skill tool or capability",
        )
    }
}

#[derive(Default)]
pub struct Registry {
    packages: BTreeMap<(String, String, String), Package>,
}
fn pin_key(pin: &SkillPin) -> (String, String, String) {
    (
        pin.skill_id.clone(),
        pin.semantic_version.clone(),
        pin.content_digest.clone(),
    )
}
impl Registry {
    pub fn insert(&mut self, p: Package) -> Result<()> {
        require(
            !self.packages.values().any(|old| {
                old.version.pin.skill_id == p.version.pin.skill_id
                    && old.version.pin.semantic_version == p.version.pin.semantic_version
            }),
            "immutable skill version already registered",
        )?;
        self.packages.insert(pin_key(&p.version.pin), p);
        Ok(())
    }
    pub fn load(&self, pin: &SkillPin, policy: &SkillPolicy) -> Result<&Package> {
        let p = self
            .packages
            .get(&pin_key(pin))
            .ok_or_else(|| Error("skill pin not found".into()))?;
        require(&p.version.pin == pin, "skill identity mismatch")?;
        policy.check(p)?;
        Ok(p)
    }
    pub fn route(&self, intent: &str, policy: &SkillPolicy) -> Vec<SkillPin> {
        let mut list: Vec<_> = self
            .packages
            .values()
            .filter(|p| {
                p.definition
                    .manifest
                    .routing
                    .intents
                    .iter()
                    .any(|i| i == intent)
                    && policy.check(p).is_ok()
            })
            .collect();
        list.sort_by(|a, b| {
            b.definition
                .manifest
                .routing
                .priority
                .cmp(&a.definition.manifest.routing.priority)
                .then(a.version.pin.skill_id.cmp(&b.version.pin.skill_id))
                .then(
                    a.version
                        .pin
                        .content_digest
                        .cmp(&b.version.pin.content_digest),
                )
        });
        list.into_iter().map(|p| p.version.pin.clone()).collect()
    }
    pub fn rollback(&self, from: &SkillPin, policy: &SkillPolicy) -> Result<SkillPin> {
        let source = self
            .packages
            .get(&pin_key(from))
            .ok_or_else(|| Error("rollback source missing".into()))?;
        require(
            &source.version.pin == from,
            "rollback source identity mismatch",
        )?;
        let to = source
            .version
            .rollback_to
            .as_ref()
            .ok_or_else(|| Error("no explicit rollback target".into()))?;
        self.load(to, policy)?;
        Ok(to.clone())
    }
}
