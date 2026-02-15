use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use dns_lookup::lookup_host;

use crate::cli::TargetProtocolVersion;

// use google dns as default as they are anycast with low latency and accept icmp echo/reply
const DEFAULT_TARGET_IPV4: Ipv4Addr = Ipv4Addr::new(8, 8, 8, 8);
const DEFAULT_TARGET_IPV6: Ipv6Addr = Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888);

#[derive(Debug)]
pub(crate) struct TargetAddresses {
    pub ipv6: Option<Ipv6Addr>,
    pub ipv4: Option<Ipv4Addr>,
}

impl TargetAddresses {
    fn nil() -> Self {
        Self {
            ipv6: None,
            ipv4: None,
        }
    }

    pub(crate) fn is_nil(&self) -> bool {
        if self.ipv6.is_none() && self.ipv4.is_none() {
            true
        } else {
            false
        }
    }
}

pub(crate) fn lookup_target_addresses(
    version: TargetProtocolVersion,
    target: Option<&str>,
) -> std::io::Result<TargetAddresses> {
    if let Some(specified) = target {
        if let Ok(ip) = IpAddr::from_str(specified) {
            let resolved = match ip {
                IpAddr::V4(ipv4) => match version {
                    TargetProtocolVersion::DualStack | TargetProtocolVersion::V4Only => {
                        TargetAddresses {
                            ipv6: None,
                            ipv4: Some(ipv4),
                        }
                    }
                    TargetProtocolVersion::V6Only => TargetAddresses::nil(),
                },
                IpAddr::V6(ipv6) => match version {
                    TargetProtocolVersion::DualStack | TargetProtocolVersion::V6Only => {
                        TargetAddresses {
                            ipv6: Some(ipv6),
                            ipv4: None,
                        }
                    }
                    TargetProtocolVersion::V4Only => TargetAddresses::nil(),
                },
            };
            return Ok(resolved);
        }
    }

    let (resolved_ipv6, resolved_ipv4) = if let Some(specified) = target {
        let mut resolved_ipv6 = vec![];
        let mut resolved_ipv4 = vec![];

        for address in lookup_host(specified)? {
            match address {
                IpAddr::V6(ipv6) => resolved_ipv6.push(ipv6),
                IpAddr::V4(ipv4) => resolved_ipv4.push(ipv4),
            }
        }

        (resolved_ipv6, resolved_ipv4)
    } else {
        (vec![DEFAULT_TARGET_IPV6], vec![DEFAULT_TARGET_IPV4])
    };

    let ipv4 = if version.should_run_for_ipv4() {
        if resolved_ipv4.len() > 1 {
            eprintln!(
                "warning: {} has multiple IPv4 addresses",
                target.expect("target should not be none")
            )
        }

        resolved_ipv4.into_iter().take(1).next()
    } else {
        None
    };

    let ipv6 = if version.should_run_for_ipv6() {
        if resolved_ipv6.len() > 1 {
            eprintln!(
                "warning: {} has multiple IPv6 addresses",
                target.expect("target should not be none")
            )
        }

        resolved_ipv6.into_iter().take(1).next()
    } else {
        None
    };

    Ok(TargetAddresses { ipv6, ipv4 })
}
