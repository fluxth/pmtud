use std::net::{Ipv4Addr, Ipv6Addr};

#[cfg(target_os = "macos")]
mod macos;

pub(crate) fn ipv6_pmtud(target: Ipv6Addr) {
    #[cfg(target_os = "macos")]
    {
        macos::ipv6::ipv6_pmtud(target)
    }

    #[cfg(not(target_os = "macos"))]
    todo!()
}

pub(crate) fn ipv4_pmtud(target: Ipv4Addr) {
    #[cfg(target_os = "macos")]
    {
        macos::ipv4::ipv4_pmtud(target)
    }

    #[cfg(not(target_os = "macos"))]
    todo!()
}
