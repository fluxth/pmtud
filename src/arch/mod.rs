use std::net::{Ipv4Addr, Ipv6Addr};

#[cfg(target_os = "macos")]
mod macos;

pub(crate) fn icmpv6_pmtud(target: Ipv6Addr) {
    #[cfg(target_os = "macos")]
    {
        macos::icmpv6::icmpv6_pmtud(target)
    }

    #[cfg(not(target_os = "macos"))]
    todo!()
}

pub(crate) fn icmp_pmtud(target: Ipv4Addr) {
    #[cfg(target_os = "macos")]
    {
        macos::icmp::icmp_pmtud(target).unwrap()
    }

    #[cfg(not(target_os = "macos"))]
    todo!()
}
