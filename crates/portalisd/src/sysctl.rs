use anyhow::{Context, Result};
use portalis_core::{AddressFamily, Config};
use std::{
    collections::BTreeSet,
    fs,
    net::{IpAddr, SocketAddr, UdpSocket},
    path::Path,
};

pub fn forwarding_state(family: AddressFamily) -> bool {
    let path = match family {
        AddressFamily::Auto => return false,
        AddressFamily::Ipv4 => "/proc/sys/net/ipv4/ip_forward",
        AddressFamily::Ipv6 => "/proc/sys/net/ipv6/conf/all/forwarding",
    };
    fs::read_to_string(path).is_ok_and(|value| value.trim() == "1")
}

pub fn ensure_forwarding(config: &Config, sysctl_dir: &Path) -> Result<()> {
    let mut values = Vec::new();
    if config.requires_ipv4_forwarding() {
        if !forwarding_state(AddressFamily::Ipv4) {
            fs::write("/proc/sys/net/ipv4/ip_forward", "1").context("enable IPv4 forwarding")?;
        }
        values.push("net.ipv4.ip_forward = 1");
    }
    if config.requires_ipv6_forwarding() {
        if !forwarding_state(AddressFamily::Ipv6) {
            fs::write("/proc/sys/net/ipv6/conf/all/forwarding", "1")
                .context("enable IPv6 forwarding")?;
        }
        values.push("net.ipv6.conf.all.forwarding = 1");
    }
    if !values.is_empty() {
        fs::create_dir_all(sysctl_dir)?;
        let path = sysctl_dir.join("99-portalis.conf");
        let mut content = fs::read_to_string(&path).unwrap_or_default();
        for value in values {
            if !content.lines().any(|line| line.trim() == value) {
                if !content.is_empty() && !content.ends_with('\n') {
                    content.push('\n');
                }
                content.push_str(value);
                content.push('\n');
            }
        }
        fs::write(path, content)?;
    }
    Ok(())
}

/// Ask the kernel to select a route without sending a packet. A failure is only a warning: nft
/// rules are still valid when the destination is temporarily offline or comes up later.
pub fn route_warnings(config: &Config) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut warnings = Vec::new();
    for rule in config.active_rules() {
        if seen.contains(&rule.target_ip) {
            continue;
        }
        let bind = match rule.target_ip {
            IpAddr::V4(_) => "0.0.0.0:0",
            IpAddr::V6(_) => "[::]:0",
        };
        let target = SocketAddr::new(rule.target_ip, 0);
        if let Ok(socket) = UdpSocket::bind(bind) {
            if let Err(error) = socket.connect(target) {
                seen.insert(rule.target_ip);
                warnings.push(format!(
                    "No route to target {}: {error}; nft apply is still allowed.",
                    rule.target_ip
                ));
            }
        }
        seen.insert(rule.target_ip);
    }
    warnings
}
