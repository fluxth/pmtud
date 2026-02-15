mod arch;
mod cli;
mod resolver;

use std::net::{Ipv4Addr, Ipv6Addr};
use std::process::ExitCode;

fn main() -> ExitCode {
    let input = cli::parse_cli();
    let version = input.target_protocol_version();

    let target_addresses = match resolver::lookup_target_addresses(version, input.target.as_deref())
    {
        Ok(addresses) => addresses,
        Err(err) => {
            let target = input
                .target
                .expect("default targets should not fail to lookup");
            eprintln!("error: address lookup failed for {}: {}", target, err);
            return ExitCode::FAILURE;
        }
    };

    if target_addresses.is_nil() {
        let target = input
            .target
            .expect("default targets should not fail to lookup");
        eprintln!(
            "error: address lookup failed for {}: no compatible address found",
            target
        );
        return ExitCode::FAILURE;
    }

    if let Some(target) = target_addresses.ipv4 {
        run_pmtud_ipv4(target);
    }

    if let Some(target) = target_addresses.ipv6 {
        run_pmtud_ipv6(target);
    }

    ExitCode::SUCCESS
}

fn run_pmtud_ipv6(target: Ipv6Addr) {
    eprintln!("Running IPv6 path MTU discovery for {}", target);
    arch::ipv6_pmtud(target)
}

fn run_pmtud_ipv4(target: Ipv4Addr) {
    eprintln!("Running IPv4 path MTU discovery for {}", target);
    arch::ipv4_pmtud(target)
}
