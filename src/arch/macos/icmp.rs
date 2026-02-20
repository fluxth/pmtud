use std::net::Ipv4Addr;
use std::os::unix::io::RawFd;

use pnet_packet::icmp::destination_unreachable::DestinationUnreachablePacket;
use pnet_packet::icmp::echo_request::MutableEchoRequestPacket;
use pnet_packet::icmp::{IcmpPacket, IcmpTypes};
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv4::{Ipv4Flags, MutableIpv4Packet};
use pnet_packet::{MutablePacket, Packet};
use socket2::{Domain, Protocol};

use super::{Action, IcmpPmtud, run_pmtud_by_icmp};

struct Icmpv4Pinger;

impl IcmpPmtud for Icmpv4Pinger {
    type IpAddrType = Ipv4Addr;
    type MtuSizeType = u16;

    fn build_echo_request_packet(&self, size: u16, seq: u16, target: Self::IpAddrType) -> Vec<u8> {
        let mut full_packet = vec![0u8; size.into()];

        // Build IPv4 Header
        let mut ip_packet = MutableIpv4Packet::new(&mut full_packet).unwrap();
        ip_packet.set_version(4);
        ip_packet.set_header_length(5);
        ip_packet.set_ttl(64);
        ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
        ip_packet.set_destination(target);

        ip_packet.set_total_length(size);
        ip_packet.set_fragment_offset(0);
        ip_packet.set_flags(Ipv4Flags::DontFragment);

        // Build ICMP Echo Request
        use pnet_packet::icmp::echo_request::IcmpCodes;

        let mut icmp_packet = MutableEchoRequestPacket::new(ip_packet.payload_mut()).unwrap();
        icmp_packet.set_icmp_type(IcmpTypes::EchoRequest);
        icmp_packet.set_icmp_code(IcmpCodes::NoCode);
        icmp_packet.set_identifier(0); // FIXME: change
        icmp_packet.set_sequence_number(seq);

        let payload = icmp_packet.payload_mut();
        payload.fill(0x42);
        *payload.first_mut().unwrap() = 0x41;
        *payload.last_mut().unwrap() = 0x43;

        let icmp_view = IcmpPacket::new(icmp_packet.packet()).unwrap();
        let icmp_checksum = pnet_packet::icmp::checksum(&icmp_view);
        icmp_packet.set_checksum(icmp_checksum);

        ip_packet.set_checksum(0);
        let ip_checksum = pnet_packet::ipv4::checksum(&ip_packet.to_immutable());
        ip_packet.set_checksum(ip_checksum);

        // Darwin kernel is cursed, when using IP_HDRINCL:
        // it expects these fields to be HOST ENDIAN and NOT NETWORK ENDIAN, wtf?
        // since these are u16, we can just swap the first and second byte
        // NOTE: do not swap byte order before building icmp packet since it will confuse pnet
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        {
            let raw_buf = ip_packet.packet_mut();

            let total_length = &mut raw_buf[2..4];
            total_length.swap(0, 1);

            let flags_and_fragment_offset = &mut raw_buf[6..8];
            flags_and_fragment_offset.swap(0, 1);
        }

        full_packet
    }

    fn handle_response_packet(&self, buf: &[u8], size: u16) -> Action<Self::MtuSizeType> {
        use pnet_packet::ipv4::Ipv4Packet;
        let Some(ip_packet) = Ipv4Packet::new(buf) else {
            return Action::Ignore;
        };

        if ip_packet.get_next_level_protocol() != IpNextHeaderProtocols::Icmp {
            return Action::Ignore;
        }

        let Some(icmp_packet) = IcmpPacket::new(ip_packet.payload()) else {
            return Action::Ignore;
        };

        let icmp_type = icmp_packet.get_icmp_type();
        let icmp_code = icmp_packet.get_icmp_code();

        match icmp_type {
            IcmpTypes::EchoReply => Action::ReplyReceived,
            IcmpTypes::DestinationUnreachable => {
                use pnet_packet::icmp::destination_unreachable::IcmpCodes;

                match icmp_code {
                    IcmpCodes::FragmentationRequiredAndDFFlagSet => {
                        let packet =
                            DestinationUnreachablePacket::new(icmp_packet.packet()).unwrap();
                        let next_hop_mtu = packet.get_next_hop_mtu();

                        if next_hop_mtu > 0 && next_hop_mtu < size {
                            Action::TryNextHop(next_hop_mtu)
                        } else {
                            Action::TryNext
                        }
                    }
                    _ => Action::Ignore,
                }
            }
            _ => Action::Ignore,
        }
    }

    fn get_socket_domain(&self) -> Domain {
        Domain::IPV4
    }

    fn get_socket_protocol(&self) -> Protocol {
        Protocol::ICMPV4
    }

    fn set_socket_options(&self, socket_fd: RawFd) -> std::io::Result<()> {
        let result = unsafe {
            let opt: libc::c_int = 1; // true - enabled
            libc::setsockopt(
                socket_fd,
                libc::IPPROTO_IP,
                libc::IP_HDRINCL,
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
        576
    }
}

pub(crate) fn icmp_pmtud(target: Ipv4Addr) -> std::io::Result<()> {
    run_pmtud_by_icmp(&Icmpv4Pinger, target)
}
