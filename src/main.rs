mod arch;
mod cli;
mod resolver;

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
        eprintln!("IPv4 path MTU discovery using icmp to {}", target);
        arch::icmp_pmtud(target)
    }

    if let Some(target) = target_addresses.ipv6 {
        eprintln!("IPv6 path MTU discovery using icmpv6 to {}", target);
        arch::icmpv6_pmtud(target)
    }

    ExitCode::SUCCESS
}
