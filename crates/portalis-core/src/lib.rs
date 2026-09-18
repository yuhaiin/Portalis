//! The domain model and validation rules for Portalis.
//!
//! This crate deliberately has no Linux, database, HTTP, or S3 dependencies.  The daemon and
//! the frontend can therefore share the same small, deterministic configuration contract.

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeSet, HashMap},
    net::IpAddr,
};
use thiserror::Error;
use uuid::Uuid;

pub const SCHEMA_VERSION: u32 = 1;
pub const TABLE_NAME: &str = "portalis";
pub const PREROUTING_CHAIN: &str = "portalis_prerouting";
pub const POSTROUTING_CHAIN: &str = "portalis_postrouting";
pub const FORWARD_CHAIN: &str = "portalis_forward";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Config {
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    #[serde(default)]
    pub rules: Vec<ForwardRule>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            rules: Vec::new(),
        }
    }
}

fn default_schema_version() -> u32 {
    SCHEMA_VERSION
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ForwardRule {
    pub id: Uuid,
    pub name: String,
    #[serde(default)]
    pub comment: String,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub order: u32,
    #[serde(default)]
    pub allow_ssh_conflict: bool,
    pub family: AddressFamily,
    #[serde(default)]
    pub listen_address: ListenAddress,
    #[serde(default)]
    pub listen_interface: Option<String>,
    #[serde(default)]
    pub source_cidrs: Vec<IpNet>,
    pub protocols: Protocols,
    pub listen_port: PortRange,
    pub target_ip: IpAddr,
    pub target_port: PortRange,
    #[serde(default)]
    pub snat: SnatMode,
}

fn default_enabled() -> bool {
    true
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Ord, PartialOrd)]
#[serde(rename_all = "lowercase")]
pub enum AddressFamily {
    Auto,
    Ipv4,
    Ipv6,
}

impl AddressFamily {
    pub fn matches(self, address: IpAddr) -> bool {
        matches!(self, Self::Auto)
            || matches!(
                (self, address),
                (Self::Ipv4, IpAddr::V4(_)) | (Self::Ipv6, IpAddr::V6(_))
            )
    }

    pub fn effective(self, address: IpAddr) -> Self {
        match self {
            Self::Auto => {
                if address.is_ipv4() {
                    Self::Ipv4
                } else {
                    Self::Ipv6
                }
            }
            family => family,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum ListenAddress {
    #[default]
    Any,
    Address(IpAddr),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Protocols {
    #[serde(default)]
    pub tcp: bool,
    #[serde(default)]
    pub udp: bool,
}

impl Protocols {
    pub const TCP: Self = Self {
        tcp: true,
        udp: false,
    };
    pub const UDP: Self = Self {
        tcp: false,
        udp: true,
    };
    pub const BOTH: Self = Self {
        tcp: true,
        udp: true,
    };
    fn iter(self) -> impl Iterator<Item = Protocol> {
        [
            self.tcp.then_some(Protocol::Tcp),
            self.udp.then_some(Protocol::Udp),
        ]
        .into_iter()
        .flatten()
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Ord, PartialOrd)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

impl PortRange {
    pub fn new(start: u16, end: u16) -> Self {
        Self { start, end }
    }
    pub fn is_single(self) -> bool {
        self.start == self.end
    }
    pub fn len(self) -> u32 {
        if self.start > self.end {
            0
        } else {
            u32::from(self.end) - u32::from(self.start) + 1
        }
    }
    pub fn is_empty(self) -> bool {
        self.start > self.end
    }
    pub fn overlaps(self, other: Self) -> bool {
        self.start <= other.end && other.start <= self.end
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase", tag = "mode", content = "address")]
pub enum SnatMode {
    #[default]
    None,
    Masquerade,
    Fixed(IpAddr),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidationContext {
    #[serde(default)]
    pub ssh_ports: BTreeSet<u16>,
}

impl Default for ValidationContext {
    fn default() -> Self {
        Self {
            ssh_ports: [22].into_iter().collect(),
        }
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ValidationError {
    #[error("unsupported schema version {0}")]
    SchemaVersion(u32),
    #[error("rule {id} has an empty name")]
    EmptyName { id: Uuid },
    #[error("rule {id} name is too long")]
    NameTooLong { id: Uuid },
    #[error("rule {id} must enable TCP, UDP, or both")]
    NoProtocol { id: Uuid },
    #[error("rule {id} has an invalid port range {start}-{end}")]
    InvalidPortRange { id: Uuid, start: u16, end: u16 },
    #[error("rule {id} listen and target port ranges must have the same length")]
    RangeLengthMismatch { id: Uuid },
    #[error("rule {id} target address {address} does not match {family:?}")]
    TargetFamilyMismatch {
        id: Uuid,
        address: IpAddr,
        family: AddressFamily,
    },
    #[error("rule {id} listen address does not match {family:?}")]
    ListenFamilyMismatch { id: Uuid, family: AddressFamily },
    #[error("rule {id} source CIDR {cidr} does not match {family:?}")]
    SourceFamilyMismatch {
        id: Uuid,
        cidr: IpNet,
        family: AddressFamily,
    },
    #[error("rule {id} SNAT address does not match {family:?}")]
    SnatFamilyMismatch { id: Uuid, family: AddressFamily },
    #[error("rule {id} listen interface is empty")]
    EmptyInterface { id: Uuid },
    #[error("rule {id} would shadow SSH port {port}")]
    SshPortConflict { id: Uuid, port: u16 },
    #[error("rules {first} and {second} overlap for {protocol:?} port range")]
    Overlap {
        first: Uuid,
        second: Uuid,
        protocol: Protocol,
    },
    #[error("duplicate rule id {0}")]
    DuplicateId(Uuid),
}

impl Config {
    pub fn validate(&self, context: &ValidationContext) -> Result<(), Vec<ValidationError>> {
        let mut errors = Vec::new();
        if self.schema_version != SCHEMA_VERSION {
            errors.push(ValidationError::SchemaVersion(self.schema_version));
        }
        let mut seen = BTreeSet::new();
        for rule in &self.rules {
            if !seen.insert(rule.id) {
                errors.push(ValidationError::DuplicateId(rule.id));
            }
            validate_rule(rule, context, &mut errors);
        }
        let enabled: Vec<_> = self.rules.iter().filter(|r| r.enabled).collect();
        for (index, first) in enabled.iter().enumerate() {
            for second in enabled.iter().skip(index + 1) {
                for protocol in first.protocols.iter() {
                    if second
                        .protocols
                        .iter()
                        .any(|candidate| candidate == protocol)
                        && addresses_overlap(first, second)
                        && first.listen_port.overlaps(second.listen_port)
                        && source_ranges_overlap(&first.source_cidrs, &second.source_cidrs)
                    {
                        errors.push(ValidationError::Overlap {
                            first: first.id,
                            second: second.id,
                            protocol,
                        });
                    }
                }
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    pub fn active_rules(&self) -> impl Iterator<Item = &ForwardRule> {
        self.rules.iter().filter(|r| r.enabled)
    }

    pub fn requires_ipv4_forwarding(&self) -> bool {
        self.active_rules()
            .any(|r| r.family.effective(r.target_ip) == AddressFamily::Ipv4)
    }
    pub fn requires_ipv6_forwarding(&self) -> bool {
        self.active_rules()
            .any(|r| r.family.effective(r.target_ip) == AddressFamily::Ipv6)
    }
}

fn validate_rule(
    rule: &ForwardRule,
    context: &ValidationContext,
    errors: &mut Vec<ValidationError>,
) {
    if rule.name.trim().is_empty() {
        errors.push(ValidationError::EmptyName { id: rule.id });
    }
    if rule.name.chars().count() > 80 {
        errors.push(ValidationError::NameTooLong { id: rule.id });
    }
    if !rule.protocols.tcp && !rule.protocols.udp {
        errors.push(ValidationError::NoProtocol { id: rule.id });
    }
    if rule.listen_port.start == 0
        || rule.listen_port.end == 0
        || rule.listen_port.start > rule.listen_port.end
    {
        errors.push(ValidationError::InvalidPortRange {
            id: rule.id,
            start: rule.listen_port.start,
            end: rule.listen_port.end,
        });
    }
    if rule.target_port.start == 0
        || rule.target_port.end == 0
        || rule.target_port.start > rule.target_port.end
    {
        errors.push(ValidationError::InvalidPortRange {
            id: rule.id,
            start: rule.target_port.start,
            end: rule.target_port.end,
        });
    }
    if rule.listen_port.len() != rule.target_port.len() {
        errors.push(ValidationError::RangeLengthMismatch { id: rule.id });
    }
    let family = rule.family.effective(rule.target_ip);
    if !rule.family.matches(rule.target_ip) {
        errors.push(ValidationError::TargetFamilyMismatch {
            id: rule.id,
            address: rule.target_ip,
            family: rule.family,
        });
    }
    if let ListenAddress::Address(address) = rule.listen_address {
        if !family.matches(address) {
            errors.push(ValidationError::ListenFamilyMismatch {
                id: rule.id,
                family,
            });
        }
    }
    for cidr in &rule.source_cidrs {
        if !family.matches(cidr.network()) {
            errors.push(ValidationError::SourceFamilyMismatch {
                id: rule.id,
                cidr: *cidr,
                family,
            });
        }
    }
    if let SnatMode::Fixed(address) = rule.snat {
        if !family.matches(address) {
            errors.push(ValidationError::SnatFamilyMismatch {
                id: rule.id,
                family,
            });
        }
    }
    if rule
        .listen_interface
        .as_ref()
        .is_some_and(|name| name.trim().is_empty())
    {
        errors.push(ValidationError::EmptyInterface { id: rule.id });
    }
    if !rule.allow_ssh_conflict {
        for port in &context.ssh_ports {
            if rule.listen_port.start <= *port && *port <= rule.listen_port.end {
                errors.push(ValidationError::SshPortConflict {
                    id: rule.id,
                    port: *port,
                });
            }
        }
    }
}

fn addresses_overlap(first: &ForwardRule, second: &ForwardRule) -> bool {
    if first.listen_interface != second.listen_interface
        && first.listen_interface.is_some()
        && second.listen_interface.is_some()
    {
        return false;
    }
    match (&first.listen_address, &second.listen_address) {
        (ListenAddress::Any, _) | (_, ListenAddress::Any) => true,
        (ListenAddress::Address(a), ListenAddress::Address(b)) => a == b,
    }
}

fn source_ranges_overlap(first: &[IpNet], second: &[IpNet]) -> bool {
    if first.is_empty() || second.is_empty() {
        return true;
    }
    first.iter().any(|left| {
        second
            .iter()
            .any(|right| left.contains(&right.network()) || right.contains(&left.network()))
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RulePlan {
    pub rule_id: Uuid,
    pub order: u32,
    pub family: AddressFamily,
    pub protocol: Protocol,
    pub listen_address: ListenAddress,
    pub listen_interface: Option<String>,
    pub source_cidrs: Vec<IpNet>,
    pub listen_port: PortRange,
    pub target_ip: IpAddr,
    pub target_port: PortRange,
    pub snat: SnatMode,
    pub comment: String,
}

impl Config {
    pub fn plan(&self) -> Vec<RulePlan> {
        let mut rules: Vec<_> = self
            .active_rules()
            .flat_map(|rule| {
                rule.protocols.iter().map(|protocol| RulePlan {
                    rule_id: rule.id,
                    order: rule.order,
                    family: rule.family.effective(rule.target_ip),
                    protocol,
                    listen_address: rule.listen_address.clone(),
                    listen_interface: rule.listen_interface.clone(),
                    source_cidrs: rule.source_cidrs.clone(),
                    listen_port: rule.listen_port,
                    target_ip: rule.target_ip,
                    target_port: rule.target_port,
                    snat: rule.snat.clone(),
                    comment: rule.comment.clone(),
                })
            })
            .collect();
        rules.sort_by_key(|rule| (rule.order, rule.rule_id, rule.protocol));
        rules
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuleCounter {
    pub rule_id: Uuid,
    pub protocol: Protocol,
    pub packets: u64,
    pub bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KernelStatus {
    pub table_present: bool,
    pub drifted: bool,
    pub counters: Vec<RuleCounter>,
    pub observed_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidationResponse {
    pub valid: bool,
    pub errors: Vec<String>,
    pub plan: Vec<RulePlan>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServiceStatus {
    pub name: String,
    pub version: String,
    pub active_revision: Option<String>,
    pub draft_revision: Option<String>,
    pub kernel: KernelStatus,
    pub ipv4_forwarding: bool,
    pub ipv6_forwarding: bool,
    pub warnings: Vec<String>,
}

pub fn default_config() -> Config {
    Config::default()
}

pub fn parse_ssh_ports(sshd_config: &str) -> BTreeSet<u16> {
    let mut ports = BTreeSet::from([22]);
    for line in sshd_config.lines().map(str::trim) {
        if line.starts_with('#') {
            continue;
        }
        let mut fields = line.split_whitespace();
        if fields
            .next()
            .is_some_and(|field| field.eq_ignore_ascii_case("port"))
        {
            if let Some(value) = fields.next().and_then(|value| value.parse().ok()) {
                ports.insert(value);
            }
        }
    }
    ports
}

pub fn summarize_plan(plan: &[RulePlan]) -> HashMap<Uuid, usize> {
    plan.iter().fold(HashMap::new(), |mut summary, item| {
        *summary.entry(item.rule_id).or_default() += 1;
        summary
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(id: Uuid, protocol: Protocols, listen: PortRange, target: PortRange) -> ForwardRule {
        ForwardRule {
            id,
            name: "demo".into(),
            comment: String::new(),
            enabled: true,
            order: 0,
            allow_ssh_conflict: false,
            family: AddressFamily::Ipv4,
            listen_address: ListenAddress::Any,
            listen_interface: None,
            source_cidrs: Vec::new(),
            protocols: protocol,
            listen_port: listen,
            target_ip: "192.0.2.10".parse().unwrap(),
            target_port: target,
            snat: SnatMode::Masquerade,
        }
    }

    #[test]
    fn equal_length_port_ranges_are_valid() {
        let config = Config {
            schema_version: SCHEMA_VERSION,
            rules: vec![rule(
                Uuid::new_v4(),
                Protocols::TCP,
                PortRange::new(12102, 12104),
                PortRange::new(12102, 12104),
            )],
        };
        assert!(
            config
                .validate(&ValidationContext {
                    ssh_ports: BTreeSet::new()
                })
                .is_ok()
        );
        assert_eq!(config.plan().len(), 1);
    }

    #[test]
    fn mismatched_range_lengths_are_rejected() {
        let config = Config {
            schema_version: SCHEMA_VERSION,
            rules: vec![rule(
                Uuid::new_v4(),
                Protocols::TCP,
                PortRange::new(1000, 1002),
                PortRange::new(2000, 2001),
            )],
        };
        assert!(
            config
                .validate(&ValidationContext {
                    ssh_ports: BTreeSet::new()
                })
                .unwrap_err()
                .iter()
                .any(|error| matches!(error, ValidationError::RangeLengthMismatch { .. }))
        );
    }

    #[test]
    fn zero_port_is_rejected() {
        let config = Config {
            schema_version: SCHEMA_VERSION,
            rules: vec![rule(
                Uuid::new_v4(),
                Protocols::TCP,
                PortRange::new(0, 1000),
                PortRange::new(2000, 3000),
            )],
        };
        assert!(
            config
                .validate(&ValidationContext {
                    ssh_ports: BTreeSet::new()
                })
                .is_err()
        );
    }

    #[test]
    fn ssh_conflict_is_rejected_even_for_any_address() {
        let config = Config {
            schema_version: SCHEMA_VERSION,
            rules: vec![rule(
                Uuid::new_v4(),
                Protocols::TCP,
                PortRange::new(20, 24),
                PortRange::new(2020, 2024),
            )],
        };
        assert!(
            config
                .validate(&ValidationContext::default())
                .unwrap_err()
                .iter()
                .any(|error| matches!(error, ValidationError::SshPortConflict { port: 22, .. }))
        );
    }

    #[test]
    fn overlapping_rules_are_rejected() {
        let first = rule(
            Uuid::new_v4(),
            Protocols::TCP,
            PortRange::new(1000, 1003),
            PortRange::new(2000, 2003),
        );
        let second = rule(
            Uuid::new_v4(),
            Protocols::TCP,
            PortRange::new(1003, 1005),
            PortRange::new(3000, 3002),
        );
        let config = Config {
            schema_version: SCHEMA_VERSION,
            rules: vec![first, second],
        };
        assert!(
            config
                .validate(&ValidationContext {
                    ssh_ports: BTreeSet::new()
                })
                .unwrap_err()
                .iter()
                .any(|error| matches!(error, ValidationError::Overlap { .. }))
        );
    }

    #[test]
    fn parses_custom_ssh_ports() {
        assert_eq!(
            parse_ssh_ports("Port 2222\n# Port 99\n"),
            BTreeSet::from([22, 2222])
        );
    }

    #[test]
    fn auto_family_follows_target_ip() {
        let mut item = rule(
            Uuid::new_v4(),
            Protocols::TCP,
            PortRange::new(1000, 1000),
            PortRange::new(2000, 2000),
        );
        item.family = AddressFamily::Auto;
        item.target_ip = "2001:db8::10".parse().unwrap();
        let config = Config {
            schema_version: SCHEMA_VERSION,
            rules: vec![item],
        };
        assert!(
            config
                .validate(&ValidationContext {
                    ssh_ports: BTreeSet::new()
                })
                .is_ok()
        );
        assert_eq!(config.plan()[0].family, AddressFamily::Ipv6);
    }
}
