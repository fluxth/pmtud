use clap::Parser;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub(crate) struct Cli {
    /// Target hostname or IP address for path MTU discovery.
    pub target: Option<String>,

    /// Use IPv4 to run path MTU discovery.
    #[arg(short = '4', action = clap::ArgAction::SetTrue)]
    pub use_ipv4: bool,

    /// Use IPv6 to run path MTU discovery.
    #[arg(short = '6', action = clap::ArgAction::SetTrue)]
    pub use_ipv6: bool,

    /// Use TCP MSS-based MTU discovery. Optional port defaults to 443.
    #[arg(long = "tcp", num_args = 0..=1, default_missing_value = "443", value_name = "PORT")]
    pub tcp_port: Option<u16>,
}

impl Cli {
    pub(crate) fn target_protocol_version(&self) -> TargetProtocolVersion {
        match (self.use_ipv6, self.use_ipv4) {
            // not specified
            (false, false) => TargetProtocolVersion::DualStack,

            // -6 -4
            (true, true) => TargetProtocolVersion::DualStack,

            // -6
            (true, false) => TargetProtocolVersion::V6Only,

            // -4
            (false, true) => TargetProtocolVersion::V4Only,
        }
    }
}

pub(crate) enum TargetProtocolVersion {
    V6Only,
    DualStack,
    V4Only,
}

impl TargetProtocolVersion {
    pub(crate) fn should_run_for_ipv4(&self) -> bool {
        match self {
            Self::DualStack | Self::V4Only => true,
            Self::V6Only => false,
        }
    }

    pub(crate) fn should_run_for_ipv6(&self) -> bool {
        match self {
            Self::DualStack | Self::V6Only => true,
            Self::V4Only => false,
        }
    }
}

pub(crate) fn parse_cli() -> Cli {
    Cli::parse()
}
