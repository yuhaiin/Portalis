//! nftables adapter.
//!
//! The rest of Portalis sees a small `NftController` interface.  This module owns the low-level
//! Netlink socket lifecycle, batch acknowledgements, expression construction, and counter dump.
//! It never shells out to `nft`.

use chrono::Utc;
use mnl::{Bus, CbResult, Socket};
use nftnl::{
    Batch, Chain, ChainType, Hook, MsgType, Policy, ProtoFamily, Rule, Table,
    expr::{
        Bitwise, Cmp, CmpOp, ConntrackStatus, Expression, Immediate, InterfaceName, NatType,
        Register,
    },
    nft_expr,
};
use nftnl_sys::{self as sys, libc};
use portalis_core::{
    AddressFamily, Config, KernelStatus, ListenAddress, PortRange, Protocol, RuleCounter, RulePlan,
    SnatMode, TABLE_NAME,
};
use std::{
    collections::{HashMap, HashSet},
    ffi::{CStr, CString, c_char},
    io,
    net::IpAddr,
    os::raw::c_int,
    ptr,
    sync::Mutex,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum NftError {
    #[error("nftables Netlink error: {0}")]
    Io(#[from] io::Error),
    #[error("nftables library error: {0}")]
    Library(String),
    #[error("nftables permission denied; Portalis needs root or CAP_NET_ADMIN")]
    Permission,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ApplyReceipt {
    pub rule_count: usize,
    pub replaced_existing_table: bool,
}

pub trait NftController: Send + Sync {
    fn apply(&self, config: &Config) -> std::result::Result<ApplyReceipt, NftError>;
    fn status(&self, config: &Config) -> std::result::Result<KernelStatus, NftError>;
    fn table_snapshot(&self) -> std::result::Result<String, NftError>;
}

pub struct NftnlController {
    lock: Mutex<()>,
}

impl NftnlController {
    pub fn new() -> Self {
        Self {
            lock: Mutex::new(()),
        }
    }
}

impl Default for NftnlController {
    fn default() -> Self {
        Self::new()
    }
}

impl NftController for NftnlController {
    fn apply(&self, config: &Config) -> std::result::Result<ApplyReceipt, NftError> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| NftError::Library("nft controller lock poisoned".into()))?;
        let had_table = list_tables()?.contains(TABLE_NAME);
        let mut batch = Batch::new();
        let table = Table::new(c"portalis", ProtoFamily::Inet);
        if had_table {
            batch.add(&table, MsgType::Del);
        }
        batch.add(&table, MsgType::Add);

        let mut prerouting = Chain::new(c"portalis_prerouting", &table);
        prerouting.set_hook(Hook::PreRouting, -100);
        prerouting.set_type(ChainType::Nat);
        prerouting.set_policy(Policy::Accept);
        batch.add(&prerouting, MsgType::Add);

        let mut postrouting = Chain::new(c"portalis_postrouting", &table);
        postrouting.set_hook(Hook::PostRouting, 100);
        postrouting.set_type(ChainType::Nat);
        postrouting.set_policy(Policy::Accept);
        batch.add(&postrouting, MsgType::Add);

        let plans = config.plan();
        for plan in &plans {
            add_prerouting_rules(&mut batch, &prerouting, plan)?;
        }
        for plan in &plans {
            if !matches!(plan.snat, SnatMode::None) {
                add_postrouting_rule(&mut batch, &postrouting, plan)?;
            }
        }

        send_batch(&batch.finalize())?;
        let rule_count = plans
            .iter()
            .map(|plan| {
                let source_count = plan.source_cidrs.len().max(1);
                let port_count = plan.listen_port.len() as usize;
                source_count * port_count
                    + if matches!(plan.snat, SnatMode::None) {
                        0
                    } else {
                        1
                    }
            })
            .sum();
        Ok(ApplyReceipt {
            rule_count,
            replaced_existing_table: had_table,
        })
    }

    fn status(&self, config: &Config) -> std::result::Result<KernelStatus, NftError> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| NftError::Library("nft controller lock poisoned".into()))?;
        let table_present = list_tables()?.contains(TABLE_NAME);
        if !table_present {
            return Ok(KernelStatus {
                table_present: false,
                drifted: !config.plan().is_empty(),
                counters: Vec::new(),
                observed_at: Utc::now().to_rfc3339(),
            });
        }
        let dump = dump_rules()?;
        let mut counters: HashMap<(uuid::Uuid, Protocol), (u64, u64)> = HashMap::new();
        let mut observed_rule_counts: HashMap<(uuid::Uuid, Protocol), usize> = HashMap::new();
        for rule in &dump {
            // Count ingress matches once. A SNAT rule has a second counter in postrouting, but
            // adding it would report every forwarded packet twice to the UI.
            if rule.chain == "portalis_prerouting" {
                if let Some((id, protocol)) = parse_comment(&rule.comment) {
                    let entry = counters.entry((id, protocol)).or_default();
                    entry.0 = entry.0.saturating_add(rule.packets);
                    entry.1 = entry.1.saturating_add(rule.bytes);
                    *observed_rule_counts.entry((id, protocol)).or_default() += 1;
                }
            }
        }
        let mut expected = HashSet::new();
        let mut expected_rule_counts = HashMap::new();
        for plan in config.plan() {
            let key = (plan.rule_id, plan.protocol);
            expected.insert(key);
            expected_rule_counts.insert(
                key,
                plan.source_cidrs.len().max(1) * plan.listen_port.len() as usize,
            );
        }
        let result = counters
            .into_iter()
            .map(|((rule_id, protocol), (packets, bytes))| RuleCounter {
                rule_id,
                protocol,
                packets,
                bytes,
            })
            .collect::<Vec<_>>();
        let observed_keys: HashSet<_> = result
            .iter()
            .map(|counter| (counter.rule_id, counter.protocol))
            .collect();
        Ok(KernelStatus {
            table_present,
            drifted: expected != observed_keys || expected_rule_counts != observed_rule_counts,
            counters: result,
            observed_at: Utc::now().to_rfc3339(),
        })
    }

    fn table_snapshot(&self) -> std::result::Result<String, NftError> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| NftError::Library("nft controller lock poisoned".into()))?;
        if !list_tables()?.contains(TABLE_NAME) {
            return Ok("[]".to_owned());
        }
        serde_json::to_string(&dump_rules()?).map_err(|error| NftError::Library(error.to_string()))
    }
}

#[derive(Debug, Clone, serde::Serialize)]
struct DumpedRule {
    chain: String,
    comment: String,
    packets: u64,
    bytes: u64,
}

fn add_prerouting_rules(
    batch: &mut Batch,
    chain: &Chain<'_>,
    plan: &RulePlan,
) -> std::result::Result<(), NftError> {
    let sources: Vec<Option<&ipnet::IpNet>> = if plan.source_cidrs.is_empty() {
        vec![None]
    } else {
        plan.source_cidrs.iter().map(Some).collect()
    };
    for offset in 0..plan.listen_port.len() {
        let listen_port = PortRange::new(
            plan.listen_port.start.saturating_add(offset as u16),
            plan.listen_port.start.saturating_add(offset as u16),
        );
        let target_port = PortRange::new(
            plan.target_port.start.saturating_add(offset as u16),
            plan.target_port.start.saturating_add(offset as u16),
        );
        for source in &sources {
            let mut rule = Rule::new(chain);
            set_rule_comment(&mut rule, plan)?;
            add_family_match(&mut rule, plan.family);
            if let Some(interface) = &plan.listen_interface {
                let name = CString::new(interface.as_str())
                    .map_err(|_| NftError::Library("interface contains NUL".into()))?;
                rule.add_expr(&nft_expr!(meta iifname));
                rule.add_expr(&Cmp::new(CmpOp::Eq, InterfaceName::Exact(name)));
            }
            if let ListenAddress::Address(address) = plan.listen_address {
                add_address_match(&mut rule, address, false);
            }
            if let Some(source) = source {
                add_cidr_match(&mut rule, **source, true);
            }
            add_protocol_match(&mut rule, plan.protocol);
            add_port_match(&mut rule, plan.protocol, listen_port);
            rule.add_expr(&nft_expr!(counter));
            add_nat_target(
                &mut rule,
                NatType::DNat,
                plan.family,
                plan.target_ip,
                Some(target_port),
            );
            batch.add(&rule, MsgType::Add);
        }
    }
    Ok(())
}

fn add_postrouting_rule(
    batch: &mut Batch,
    chain: &Chain<'_>,
    plan: &RulePlan,
) -> std::result::Result<(), NftError> {
    let mut rule = Rule::new(chain);
    set_rule_comment(&mut rule, plan)?;
    rule.add_expr(&nft_expr!(ct status));
    let mask = ConntrackStatus::DST_NAT.bits();
    rule.add_expr(&Bitwise::new(mask, 0u32));
    rule.add_expr(&Cmp::new(CmpOp::Eq, mask));
    add_family_match(&mut rule, plan.family);
    add_address_match(&mut rule, plan.target_ip, false);
    add_protocol_match(&mut rule, plan.protocol);
    add_port_match(&mut rule, plan.protocol, plan.target_port);
    rule.add_expr(&nft_expr!(counter));
    match plan.snat {
        SnatMode::None => {}
        SnatMode::Masquerade => rule.add_expr(&nft_expr!(masquerade)),
        SnatMode::Fixed(address) => {
            add_nat_target(&mut rule, NatType::SNat, plan.family, address, None)
        }
    }
    batch.add(&rule, MsgType::Add);
    Ok(())
}

fn set_rule_comment(rule: &mut Rule<'_>, plan: &RulePlan) -> std::result::Result<(), NftError> {
    let protocol = match plan.protocol {
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
    };
    let comment = CString::new(format!("portalis:{}:{}", plan.rule_id, protocol))
        .map_err(|_| NftError::Library("rule id contains NUL".into()))?;
    rule.set_comment(comment)
        .map_err(|error| NftError::Library(error.into()))
}

fn add_family_match(rule: &mut Rule<'_>, family: AddressFamily) {
    rule.add_expr(&nft_expr!(meta nfproto));
    let value = match family {
        AddressFamily::Auto => unreachable!("auto address family must be resolved in RulePlan"),
        AddressFamily::Ipv4 => libc::NFPROTO_IPV4 as u8,
        AddressFamily::Ipv6 => libc::NFPROTO_IPV6 as u8,
    };
    rule.add_expr(&Cmp::new(CmpOp::Eq, value));
}

fn add_protocol_match(rule: &mut Rule<'_>, protocol: Protocol) {
    rule.add_expr(&nft_expr!(meta l4proto));
    let value = match protocol {
        Protocol::Tcp => libc::IPPROTO_TCP as u8,
        Protocol::Udp => libc::IPPROTO_UDP as u8,
    };
    rule.add_expr(&Cmp::new(CmpOp::Eq, value));
}

fn add_port_match(rule: &mut Rule<'_>, protocol: Protocol, ports: PortRange) {
    match protocol {
        Protocol::Tcp => rule.add_expr(&nft_expr!(payload tcp dport)),
        Protocol::Udp => rule.add_expr(&nft_expr!(payload udp dport)),
    }
    rule.add_expr(&Cmp::new(CmpOp::Gte, ports.start.to_be()));
    if ports.end != ports.start {
        rule.add_expr(&Cmp::new(CmpOp::Lte, ports.end.to_be()));
    }
}

fn add_address_match(rule: &mut Rule<'_>, address: IpAddr, source: bool) {
    match address {
        IpAddr::V4(address) => {
            if source {
                rule.add_expr(&nft_expr!(payload ipv4 saddr));
            } else {
                rule.add_expr(&nft_expr!(payload ipv4 daddr));
            }
            rule.add_expr(&Cmp::new(CmpOp::Eq, address));
        }
        IpAddr::V6(address) => {
            if source {
                rule.add_expr(&nft_expr!(payload ipv6 saddr));
            } else {
                rule.add_expr(&nft_expr!(payload ipv6 daddr));
            }
            rule.add_expr(&Cmp::new(CmpOp::Eq, address));
        }
    }
}

fn add_cidr_match(rule: &mut Rule<'_>, cidr: ipnet::IpNet, _source: bool) {
    match cidr {
        ipnet::IpNet::V4(network) => {
            rule.add_expr(&nft_expr!(payload ipv4 saddr));
            let mask = network.netmask().octets();
            let address = network.network().octets();
            let xor = [0u8; 4];
            rule.add_expr(&Bitwise::new(mask.as_slice(), xor.as_slice()));
            rule.add_expr(&Cmp::new(CmpOp::Eq, std::net::Ipv4Addr::from(address)));
        }
        ipnet::IpNet::V6(network) => {
            rule.add_expr(&nft_expr!(payload ipv6 saddr));
            let mask = network.netmask().octets();
            let address = network.network().octets();
            let xor = [0u8; 16];
            rule.add_expr(&Bitwise::new(mask.as_slice(), xor.as_slice()));
            rule.add_expr(&Cmp::new(CmpOp::Eq, std::net::Ipv6Addr::from(address)));
        }
    }
}

fn add_nat_target(
    rule: &mut Rule<'_>,
    nat_type: NatType,
    family: AddressFamily,
    address: IpAddr,
    ports: Option<PortRange>,
) {
    match address {
        IpAddr::V4(address) => rule.add_expr(&Immediate::new(address.octets(), Register::Reg1)),
        IpAddr::V6(address) => rule.add_expr(&Immediate::new(address.octets(), Register::Reg1)),
    }
    if let Some(ports) = ports {
        rule.add_expr(&Immediate::new(ports.start.to_be(), Register::Reg2));
        rule.add_expr(&Immediate::new(ports.end.to_be(), Register::Reg3));
    }
    rule.add_expr(&NatTarget {
        nat_type,
        family: nft_family(family),
        ports,
    });
}

fn nft_family(family: AddressFamily) -> ProtoFamily {
    match family {
        AddressFamily::Auto => unreachable!("auto address family must be resolved in RulePlan"),
        AddressFamily::Ipv4 => ProtoFamily::Ipv4,
        AddressFamily::Ipv6 => ProtoFamily::Ipv6,
    }
}

struct NatTarget {
    nat_type: NatType,
    family: ProtoFamily,
    ports: Option<PortRange>,
}

impl Expression for NatTarget {
    fn to_expr(&self, _rule: &Rule) -> ptr::NonNull<sys::nftnl_expr> {
        let expr = unsafe {
            ptr::NonNull::new(sys::nftnl_expr_alloc(c"nat".as_ptr()))
                .expect("nftnl allocation failed")
        };
        unsafe {
            sys::nftnl_expr_set_u32(
                expr.as_ptr(),
                sys::NFTNL_EXPR_NAT_TYPE as u16,
                self.nat_type as u32,
            );
            sys::nftnl_expr_set_u32(
                expr.as_ptr(),
                sys::NFTNL_EXPR_NAT_FAMILY as u16,
                self.family as u32,
            );
            sys::nftnl_expr_set_u32(
                expr.as_ptr(),
                sys::NFTNL_EXPR_NAT_REG_ADDR_MIN as u16,
                Register::Reg1.to_raw(),
            );
            sys::nftnl_expr_set_u32(
                expr.as_ptr(),
                sys::NFTNL_EXPR_NAT_REG_ADDR_MAX as u16,
                Register::Reg1.to_raw(),
            );
            if self.ports.is_some() {
                sys::nftnl_expr_set_u32(
                    expr.as_ptr(),
                    sys::NFTNL_EXPR_NAT_REG_PROTO_MIN as u16,
                    Register::Reg2.to_raw(),
                );
                sys::nftnl_expr_set_u32(
                    expr.as_ptr(),
                    sys::NFTNL_EXPR_NAT_REG_PROTO_MAX as u16,
                    Register::Reg3.to_raw(),
                );
            }
        }
        expr
    }
}

fn send_batch(batch: &nftnl::FinalizedBatch) -> std::result::Result<(), NftError> {
    let socket = Socket::new(Bus::Netfilter)?;
    socket.send_all(batch)?;
    let mut buffer = vec![0u8; nftnl::nft_nlmsg_maxsize() as usize];
    let mut expected = batch.sequence_numbers();
    while !expected.is_empty() {
        for message in socket.recv(&mut buffer)? {
            let message = message?;
            let expected_seq = expected
                .next()
                .ok_or_else(|| NftError::Library("unexpected nftables acknowledgement".into()))?;
            match mnl::cb_run(message, expected_seq, socket.portid()) {
                Ok(CbResult::Stop | CbResult::Ok) => {}
                Err(error) => return Err(map_netlink_error(error)),
            }
        }
    }
    Ok(())
}

fn map_netlink_error(error: io::Error) -> NftError {
    if error.raw_os_error() == Some(libc::EPERM) {
        NftError::Permission
    } else {
        NftError::Io(error)
    }
}

fn list_tables() -> std::result::Result<HashSet<String>, NftError> {
    let socket = Socket::new(Bus::Netfilter)?;
    let sequence = 1;
    socket.send(&nftnl::table::get_tables_nlmsg(sequence))?;
    let mut names = HashSet::<CString>::new();
    let mut buffer = vec![0u8; nftnl::nft_nlmsg_maxsize() as usize];
    loop {
        let mut stop = false;
        for message in socket.recv(&mut buffer)? {
            let message = message?;
            if matches!(
                mnl::cb_run2(
                    message,
                    sequence,
                    socket.portid(),
                    inet_table_callback,
                    &mut names
                )?,
                CbResult::Stop
            ) {
                stop = true;
            }
        }
        if stop {
            break;
        }
    }
    Ok(names
        .into_iter()
        .map(|name| name.to_string_lossy().into_owned())
        .collect())
}

fn inet_table_callback(header: &libc::nlmsghdr, tables: &mut HashSet<CString>) -> c_int {
    unsafe {
        let table = sys::nftnl_table_alloc();
        if table.is_null() || sys::nftnl_table_nlmsg_parse(header, table) < 0 {
            if !table.is_null() {
                sys::nftnl_table_free(table);
            }
            return mnl::mnl_sys::MNL_CB_ERROR;
        }
        if sys::nftnl_table_get_u32(table, sys::NFTNL_TABLE_FAMILY as u16)
            == ProtoFamily::Inet as u32
        {
            let name = sys::nftnl_table_get_str(table, sys::NFTNL_TABLE_NAME as u16);
            if !name.is_null() {
                tables.insert(CStr::from_ptr(name).to_owned());
            }
        }
        sys::nftnl_table_free(table);
    }
    mnl::mnl_sys::MNL_CB_OK
}

fn dump_rules() -> std::result::Result<Vec<DumpedRule>, NftError> {
    let socket = Socket::new(Bus::Netfilter)?;
    let sequence = 11;
    socket.send(&rule_dump_message(sequence))?;
    let mut rules = Vec::new();
    let mut buffer = vec![0u8; nftnl::nft_nlmsg_maxsize() as usize];
    loop {
        let mut stop = false;
        for message in socket.recv(&mut buffer)? {
            let message = message?;
            if matches!(
                mnl::cb_run2(
                    message,
                    sequence,
                    socket.portid(),
                    dump_rule_callback,
                    &mut rules
                )?,
                CbResult::Stop
            ) {
                stop = true;
            }
        }
        if stop {
            break;
        }
    }
    Ok(rules)
}

fn rule_dump_message(sequence: u32) -> Vec<u8> {
    let mut buffer = vec![0u8; nftnl::nft_nlmsg_maxsize() as usize];
    let rule = unsafe { sys::nftnl_rule_alloc() };
    assert!(!rule.is_null());
    unsafe {
        sys::nftnl_rule_set_u32(
            rule,
            sys::NFTNL_RULE_FAMILY as u16,
            ProtoFamily::Inet as u32,
        );
        sys::nftnl_rule_set_str(rule, sys::NFTNL_RULE_TABLE as u16, c"portalis".as_ptr());
        let header = sys::nftnl_nlmsg_build_hdr(
            buffer.as_mut_ptr().cast::<c_char>(),
            libc::NFT_MSG_GETRULE as u16,
            ProtoFamily::Inet as u16,
            (libc::NLM_F_ROOT | libc::NLM_F_MATCH | libc::NLM_F_ACK) as u16,
            sequence,
        );
        sys::nftnl_rule_nlmsg_build_payload(header, rule);
        let length = (*header).nlmsg_len as usize;
        sys::nftnl_rule_free(rule);
        buffer.truncate(length);
    }
    buffer
}

fn dump_rule_callback(header: &libc::nlmsghdr, output: &mut Vec<DumpedRule>) -> c_int {
    unsafe {
        let rule = sys::nftnl_rule_alloc();
        if rule.is_null() {
            return mnl::mnl_sys::MNL_CB_ERROR;
        }
        if sys::nftnl_rule_nlmsg_parse(header, rule) < 0 {
            sys::nftnl_rule_free(rule);
            return mnl::mnl_sys::MNL_CB_ERROR;
        }
        let table_ptr = sys::nftnl_rule_get_str(rule, sys::NFTNL_RULE_TABLE as u16);
        if table_ptr.is_null() {
            eprintln!("nft dump rule has no table");
            sys::nftnl_rule_free(rule);
            return mnl::mnl_sys::MNL_CB_ERROR;
        }
        let table = CStr::from_ptr(table_ptr);
        if table == c"portalis" {
            let chain = CStr::from_ptr(sys::nftnl_rule_get_str(rule, sys::NFTNL_RULE_CHAIN as u16))
                .to_string_lossy()
                .into_owned();
            let mut data_len = 0u32;
            let data =
                sys::nftnl_rule_get_data(rule, sys::NFTNL_RULE_USERDATA as u16, &mut data_len);
            let comment = if data.is_null() {
                String::new()
            } else {
                let bytes = std::slice::from_raw_parts(data.cast::<u8>(), data_len as usize);
                bytes
                    .windows(9)
                    .position(|window| window == b"portalis:")
                    .map(|start| {
                        String::from_utf8_lossy(&bytes[start..])
                            .trim_end_matches('\0')
                            .to_owned()
                    })
                    .unwrap_or_default()
            };
            let mut packets = 0;
            let mut bytes = 0;
            let iterator = sys::nftnl_expr_iter_create(rule);
            if !iterator.is_null() {
                loop {
                    let expression = sys::nftnl_expr_iter_next(iterator);
                    if expression.is_null() {
                        break;
                    }
                    let name = sys::nftnl_expr_get_str(expression, sys::NFTNL_EXPR_NAME as u16);
                    if !name.is_null() && CStr::from_ptr(name) == c"counter" {
                        packets =
                            sys::nftnl_expr_get_u64(expression, sys::NFTNL_EXPR_CTR_PACKETS as u16);
                        bytes =
                            sys::nftnl_expr_get_u64(expression, sys::NFTNL_EXPR_CTR_BYTES as u16);
                    }
                }
                sys::nftnl_expr_iter_destroy(iterator);
            }
            output.push(DumpedRule {
                chain,
                comment,
                packets,
                bytes,
            });
        }
        sys::nftnl_rule_free(rule);
    }
    mnl::mnl_sys::MNL_CB_OK
}

fn parse_comment(comment: &str) -> Option<(uuid::Uuid, Protocol)> {
    let mut parts = comment.split(':');
    if parts.next()? != "portalis" {
        return None;
    }
    let id = parts.next()?.parse().ok()?;
    let protocol = match parts.next()? {
        "tcp" => Protocol::Tcp,
        "udp" => Protocol::Udp,
        _ => return None,
    };
    Some((id, protocol))
}

#[cfg(test)]
mod tests {
    use super::*;
    use portalis_core::{
        AddressFamily, Config, ForwardRule, ListenAddress, Protocols, SCHEMA_VERSION, SnatMode,
    };
    #[test]
    fn comments_round_trip_to_rule_identity() {
        let id = uuid::Uuid::new_v4();
        assert_eq!(
            parse_comment(&format!("portalis:{id}:tcp")),
            Some((id, Protocol::Tcp))
        );
        assert!(parse_comment("other:rule").is_none());
    }

    #[test]
    #[ignore = "requires CAP_NET_ADMIN in a disposable network namespace"]
    fn netlink_apply_and_counter_dump() {
        if std::env::var_os("PORTALIS_NFT_INTEGRATION").is_none() {
            return;
        }
        let id = uuid::Uuid::new_v4();
        let config = Config {
            schema_version: SCHEMA_VERSION,
            rules: vec![ForwardRule {
                id,
                name: "integration".into(),
                comment: "integration".into(),
                enabled: true,
                order: 0,
                allow_ssh_conflict: false,
                family: AddressFamily::Ipv4,
                listen_address: ListenAddress::Any,
                listen_interface: None,
                source_cidrs: Vec::new(),
                protocols: Protocols::BOTH,
                listen_port: PortRange::new(18080, 18081),
                target_ip: "127.0.0.1".parse().unwrap(),
                target_port: PortRange::new(28080, 28081),
                snat: SnatMode::Masquerade,
            }],
        };
        let controller = NftnlController::new();
        let receipt = controller
            .apply(&config)
            .expect("apply in isolated namespace");
        assert_eq!(receipt.rule_count, 6);
        let mut peer = std::process::Command::new("unshare")
            .args(["-n", "sleep", "3"])
            .spawn()
            .unwrap();
        let peer_pid = peer.id().to_string();
        for args in [
            &[
                "link",
                "add",
                "portalis-test-a",
                "type",
                "veth",
                "peer",
                "name",
                "portalis-test-b",
            ][..],
            &["addr", "add", "198.18.0.1/24", "dev", "portalis-test-a"][..],
            &["link", "set", "portalis-test-b", "netns", &peer_pid][..],
            &["link", "set", "portalis-test-a", "up"][..],
        ] {
            assert!(
                std::process::Command::new("ip")
                    .args(args)
                    .status()
                    .unwrap()
                    .success()
            );
        }
        assert!(
            std::process::Command::new("nsenter")
                .args([
                    "-t",
                    &peer_pid,
                    "-n",
                    "ip",
                    "addr",
                    "add",
                    "198.18.0.2/24",
                    "dev",
                    "portalis-test-b"
                ])
                .status()
                .unwrap()
                .success()
        );
        assert!(
            std::process::Command::new("nsenter")
                .args([
                    "-t",
                    &peer_pid,
                    "-n",
                    "ip",
                    "link",
                    "set",
                    "portalis-test-b",
                    "up"
                ])
                .status()
                .unwrap()
                .success()
        );
        assert!(
            std::process::Command::new("nsenter")
                .args([
                    "-t",
                    &peer_pid,
                    "-n",
                    "sh",
                    "-c",
                    "printf counter | nc -u -w 1 198.18.0.1 18080"
                ])
                .status()
                .unwrap()
                .success()
        );
        std::thread::sleep(std::time::Duration::from_millis(50));
        let status = controller
            .status(&config)
            .expect("dump in isolated namespace");
        assert!(status.table_present);
        assert!(!status.drifted);
        assert_eq!(status.counters.len(), 2);
        assert!(status.counters.iter().any(|counter| counter.packets > 0));
        assert!(controller.table_snapshot().unwrap().contains("portalis:"));
        let _ = peer.kill();
        let _ = peer.wait();
        if std::process::Command::new("ip")
            .args(["link", "show", "portalis-test-a"])
            .output()
            .is_ok_and(|output| output.status.success())
        {
            let _ = std::process::Command::new("ip")
                .args(["link", "del", "portalis-test-a"])
                .status();
        }
    }

    #[test]
    #[ignore = "requires CAP_NET_ADMIN in a disposable network namespace"]
    fn netlink_ipv6_apply_and_dump() {
        if std::env::var_os("PORTALIS_NFT_INTEGRATION").is_none() {
            return;
        }
        let id = uuid::Uuid::new_v4();
        let config = Config {
            schema_version: SCHEMA_VERSION,
            rules: vec![ForwardRule {
                id,
                name: "integration-v6".into(),
                comment: "integration-v6".into(),
                enabled: true,
                order: 0,
                allow_ssh_conflict: false,
                family: AddressFamily::Ipv6,
                listen_address: ListenAddress::Any,
                listen_interface: None,
                source_cidrs: Vec::new(),
                protocols: Protocols::TCP,
                listen_port: PortRange::new(19000, 19000),
                target_ip: "::1".parse().unwrap(),
                target_port: PortRange::new(29000, 29000),
                snat: SnatMode::None,
            }],
        };
        let controller = NftnlController::new();
        assert_eq!(controller.apply(&config).unwrap().rule_count, 1);
        let status = controller.status(&config).unwrap();
        assert!(status.table_present && !status.drifted);
        assert_eq!(status.counters.len(), 1);
    }
}
