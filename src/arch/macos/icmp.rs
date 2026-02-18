use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::unix::io::AsRawFd;
use std::thread::sleep;
use std::time::Duration;

use pnet_packet::icmp::destination_unreachable::DestinationUnreachablePacket;
use pnet_packet::icmp::echo_request::MutableEchoRequestPacket;
use pnet_packet::icmp::{IcmpPacket, IcmpTypes};
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv4::{Ipv4Flags, Ipv4Packet, MutableIpv4Packet};
use pnet_packet::{MutablePacket, Packet};
use socket2::{Domain, Protocol, Socket, Type};

const TIMEOUT: Duration = Duration::from_millis(1000);
const IPV4_MTU_MAX: u16 = 1500;
const IPV4_MTU_MIN: u16 = 576;

fn build_icmp_echo_request_packet(size: u16, seq: u16, target: Ipv4Addr) -> Vec<u8> {
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

enum Action {
    ReplyReceived,
    TryNextHop(u16),
    TryNext,
    Ignore,
}

fn handle_response_packet(buf: &[u8], size: u16) -> Action {
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
                    let packet = DestinationUnreachablePacket::new(icmp_packet.packet()).unwrap();
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

pub(crate) fn icmp_pmtud(target: Ipv4Addr) -> std::io::Result<()> {
    let socket_addr = SocketAddr::new(IpAddr::V4(target), 0);

    let socket = Socket::new(
        Domain::IPV4,
        Type::from(libc::SOCK_RAW),
        Some(Protocol::ICMPV4),
    )?;

    socket.set_read_timeout(Some(TIMEOUT))?;

    // tell the kernel we want to build the header ourselves
    let result = unsafe {
        let opt: libc::c_int = 1; // true - enabled
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_IP,
            libc::IP_HDRINCL,
            &opt as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };

    if result != 0 {
        return Err(std::io::Error::last_os_error());
    }

    let mut max_mtu = IPV4_MTU_MAX;
    let mut min_mtu = IPV4_MTU_MIN;
    let mut probe_mtu = max_mtu;
    let mut icmp_seq = 0;
    let mut recv_buf = Box::new([std::mem::MaybeUninit::<u8>::uninit(); 9000]);

    while min_mtu < max_mtu {
        print!("probe mtu={} icmp_seq={}: ", probe_mtu, icmp_seq);
        std::io::Write::flush(&mut std::io::stdout())?;

        let full_packet = build_icmp_echo_request_packet(probe_mtu, icmp_seq, target);

        match socket.send_to(&full_packet, &socket_addr.into()) {
            Ok(_) => {
                icmp_seq += 1;
            }
            Err(ref err) if err.raw_os_error() == Some(libc::EMSGSIZE) => {
                println!("from=kernel, message too long");
                max_mtu = probe_mtu - 1;
                probe_mtu = min_mtu + (max_mtu - min_mtu + 1) / 2;
                icmp_seq += 1;
                continue;
            }
            Err(ref err) if err.raw_os_error() == Some(libc::EHOSTUNREACH) => {
                println!("from=kernel, no route to host");
                println!("Path MTU discovery to {} failed", target);
                break;
            }
            Err(err) => {
                return Err(err);
            }
        }

        match socket.recv_from(recv_buf.as_mut()) {
            Ok((len, addr)) => {
                let buf =
                    unsafe { std::slice::from_raw_parts(recv_buf.as_ptr() as *const u8, len) };
                let reply_addr = addr.as_socket_ipv4().map(|sock| sock.ip().clone());
                if let Some(reply_addr) = reply_addr {
                    print!("from={}, ", reply_addr); // FIXME
                }

                match handle_response_packet(buf, probe_mtu) {
                    Action::ReplyReceived => {
                        println!("ok");
                        min_mtu = probe_mtu;
                        if min_mtu < max_mtu {
                            probe_mtu = min_mtu + (max_mtu - min_mtu + 1) / 2;
                            sleep(Duration::from_millis(100));
                        }
                    }
                    Action::TryNextHop(size) => {
                        println!("fragmentation needed, next_hop={}", size);
                        if max_mtu > size {
                            max_mtu = size;
                        } else {
                            max_mtu = probe_mtu - 1;
                        }
                        probe_mtu = size;
                    }
                    Action::TryNext => {
                        println!("fragmentation needed");
                        max_mtu = probe_mtu - 1;
                        probe_mtu = min_mtu + (max_mtu - min_mtu + 1) / 2;
                    }
                    Action::Ignore => {}
                }
            }
            Err(_) => {
                // FIXME: not actually all timeout
                println!("timed out");
                max_mtu = probe_mtu - 1;
                probe_mtu = min_mtu + (max_mtu - min_mtu + 1) / 2;
            }
        }
    }

    println!("Path MTU to {}: {} bytes", target, probe_mtu);

    Ok(())
}
