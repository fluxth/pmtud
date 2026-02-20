use std::net::Ipv6Addr;
use std::os::unix::io::RawFd;

use pnet_packet::icmpv6::echo_request::MutableEchoRequestPacket;
use pnet_packet::icmpv6::{Icmpv6Packet, Icmpv6Types};
use pnet_packet::{MutablePacket, Packet};
use socket2::{Domain, Protocol};

use super::{Action, IcmpPmtud, run_pmtud_by_icmp};

struct Icmpv6Pinger;

impl IcmpPmtud for Icmpv6Pinger {
    type IpAddrType = Ipv6Addr;
    type MtuSizeType = u32;

    fn build_echo_request_packet(&self, size: u16, seq: u16, _target: Self::IpAddrType) -> Vec<u8> {
        // 1500 (MTU) - 40 (IPv6 Header) - 8 (ICMPv6 Header) = 1452 bytes
        let icmpv6_size = size - 40;
        let mut raw_packet = vec![0u8; icmpv6_size.into()];

        use pnet_packet::icmpv6::echo_request::Icmpv6Codes;

        let mut icmp_packet = MutableEchoRequestPacket::new(&mut raw_packet).unwrap();
        icmp_packet.set_icmpv6_type(Icmpv6Types::EchoRequest);
        icmp_packet.set_icmpv6_code(Icmpv6Codes::NoCode);
        icmp_packet.set_identifier(0); // FIXME: change
        icmp_packet.set_sequence_number(seq);

        let payload = icmp_packet.payload_mut();
        payload.fill(0x42);
        *payload.first_mut().unwrap() = 0x41;
        *payload.last_mut().unwrap() = 0x43;

        // IMPORTANT: On macOS, do NOT manually calculate the checksum for ICMPv6 raw sockets.
        // The kernel calculates it automatically using the pseudo-header.
        icmp_packet.set_checksum(0);

        raw_packet
    }

    fn handle_response_packet(&self, buf: &[u8], size: u16) -> Action<Self::MtuSizeType> {
        let Some(icmpv6_packet) = Icmpv6Packet::new(buf) else {
            return Action::Ignore;
        };

        let icmpv6_type = icmpv6_packet.get_icmpv6_type();

        match icmpv6_type {
            Icmpv6Types::EchoReply => Action::ReplyReceived,
            Icmpv6Types::PacketTooBig => {
                let payload = icmpv6_packet.payload();

                let (chunks, _) = payload.as_chunks::<4>();
                if let Some(mtu_bytes) = chunks.first() {
                    let mtu = u32::from_be_bytes(*mtu_bytes);
                    if mtu > 0 && mtu < size.into() {
                        Action::TryNextHop(mtu)
                    } else {
                        Action::TryNext
                    }
                } else {
                    Action::TryNext
                }
            }
            _ => Action::Ignore,
        }
    }

    fn get_socket_domain(&self) -> Domain {
        Domain::IPV6
    }

    fn get_socket_protocol(&self) -> Protocol {
        Protocol::ICMPV6
    }

    fn set_socket_options(&self, socket_fd: RawFd) -> std::io::Result<()> {
        let result = unsafe {
            let opt: libc::c_int = 1; // true - enabled
            libc::setsockopt(
                socket_fd,
                libc::IPPROTO_IPV6,
                libc::IPV6_DONTFRAG,
                &opt as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };

        if result == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }

    fn get_max_mtu(&self) -> u16 {
        1500
    }

    fn get_min_mtu(&self) -> u16 {
        1280
    }
}

pub(crate) fn icmpv6_pmtud(target: Ipv6Addr) -> std::io::Result<()> {
    run_pmtud_by_icmp(&Icmpv6Pinger, target)
}
