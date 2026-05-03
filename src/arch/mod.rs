use std::net::{Ipv4Addr, Ipv6Addr};

#[cfg(target_os = "macos")]
mod macos;

pub(crate) fn icmpv6_pmtud(target: Ipv6Addr) {
    #[cfg(target_os = "macos")]
    {
        macos::icmpv6::icmpv6_pmtud(target).unwrap()
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

pub(crate) fn tcp_mss_pmtud_v4(target: Ipv4Addr, port: u16) -> std::io::Result<()> {
    #[cfg(target_os = "macos")]
    {
        macos::tcp_mss::tcp_mss_pmtud_v4(target, port)?;
    }

    #[cfg(not(target_os = "macos"))]
    todo!();

    Ok(())
}

pub(crate) fn tcp_mss_pmtud_v6(target: Ipv6Addr, port: u16) -> std::io::Result<()> {
    #[cfg(target_os = "macos")]
    {
        macos::tcp_mss::tcp_mss_pmtud_v6(target, port)?;
    }

    #[cfg(not(target_os = "macos"))]
    todo!();

    Ok(())
}
