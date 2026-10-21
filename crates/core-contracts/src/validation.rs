//! Pure contract validation. These checks do not authenticate an issuer, grant
//! authority, execute a tool, or certify evidence produced by an external host.

use std::collections::BTreeSet;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractError {
    pub path: String,
    pub message: String,
}

impl ContractError {
    pub fn new(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            message: message.into(),
        }
    }

    pub fn at(self, prefix: &str) -> Self {
        Self::new(format!("{prefix}.{}", self.path), self.message)
    }
}

impl fmt::Display for ContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.path, self.message)
    }
}

impl std::error::Error for ContractError {}

pub type ContractResult<T = ()> = Result<T, ContractError>;

pub trait Validate {
    fn validate(&self) -> ContractResult<()>;
}

pub fn require(condition: bool, path: &str, message: &str) -> ContractResult<()> {
    if condition {
        Ok(())
    } else {
        Err(ContractError::new(path, message))
    }
}

pub fn non_blank(value: &str, path: &str) -> ContractResult<()> {
    require(!value.trim().is_empty(), path, "must not be blank")
}

pub fn exact_version(value: &str, expected: &str, path: &str) -> ContractResult<()> {
    require(value == expected, path, "unsupported contract version")
}

pub fn unique_non_blank(values: &[String], path: &str, minimum: usize) -> ContractResult<()> {
    require(values.len() >= minimum, path, "too few entries")?;
    let mut seen = BTreeSet::new();
    for (index, value) in values.iter().enumerate() {
        non_blank(value, &format!("{path}[{index}]"))?;
        require(seen.insert(value), path, "duplicate entry")?;
    }
    Ok(())
}
