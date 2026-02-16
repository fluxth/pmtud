use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::unix::io::AsRawFd;
use std::thread::sleep;
use std::time::Duration;

use pnet_packet::icmp::destination_unreachable::{DestinationUnreachablePacket, IcmpCodes};
use pnet_packet::icmp::echo_request::MutableEchoRequestPacket;
use pnet_packet::icmp::{IcmpCode, IcmpPacket, IcmpTypes};
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet_packet::{MutablePacket, Packet};
use socket2::{Domain, Protocol, Socket, Type};

const TIMEOUT: Duration = Duration::from_millis(1000);

fn build_icmp_echo_request_packet(size: u16, seq: u16, target: Ipv4Addr) -> Vec<u8> {
    let mut full_packet = vec![0u8; size.into()];

    // Build IPv4 Header
    let mut ip_packet = MutableIpv4Packet::new(&mut full_packet).unwrap();
    ip_packet.set_version(4);
    ip_packet.set_header_length(5);
    ip_packet.set_ttl(64);
    ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
    ip_packet.set_destination(target);

    // Darwin kernel is cursed, when using IP_HDRINCL:
    // it expects these fields to be HOST ENDIAN and NOT NETWORK ENDIAN, wtf?
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        let raw_buf = ip_packet.packet_mut();

        // ip_header.set_total_length(size);
        raw_buf[2..4].copy_from_slice(&size.to_ne_bytes());

        // ip_header.set_fragment_offset(0);
        // ip_header.set_flags(Ipv4Flags::DontFragment);
        let flags_and_frag: u16 = 0x4000; // BE: DF bit, no offset
        raw_buf[6..8].copy_from_slice(&flags_and_frag.to_ne_bytes());
    }

    // Linux and other normal people: Use standard pnet setters
    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    {
        use pnet_packet::ipv4::Ipv4Flags;
        ip_header.set_total_length(size);
        ip_header.set_fragment_offset(0);
        ip_header.set_flags(Ipv4Flags::DontFragment);
    }

    // Build ICMP Echo Request
    let mut icmp_packet = MutableEchoRequestPacket::new(ip_packet.payload_mut()).unwrap();
    icmp_packet.set_icmp_type(IcmpTypes::EchoRequest);
    icmp_packet.set_icmp_code(IcmpCode::new(0));
    icmp_packet.set_identifier(0x1234); // FIXME: change
    icmp_packet.set_sequence_number(seq);
    icmp_packet.payload_mut().fill(0x42);

    let icmp_view = IcmpPacket::new(icmp_packet.packet()).unwrap();
    let icmp_checksum = pnet_packet::icmp::checksum(&icmp_view);
    icmp_packet.set_checksum(icmp_checksum);

    ip_packet.set_checksum(0);
    let ip_checksum = pnet_packet::ipv4::checksum(&ip_packet.to_immutable());
    ip_packet.set_checksum(ip_checksum);

    full_packet
}

enum Action {
    ReportPathMTU(u16),
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
        IcmpTypes::EchoReply => Action::ReportPathMTU(size),
        IcmpTypes::DestinationUnreachable => match icmp_code {
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
        },
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

    let mut probe_mtu = 1500;
    let mut icmp_seq = 0;

    loop {
        let full_packet = build_icmp_echo_request_packet(probe_mtu, icmp_seq, target);

        print!("probe mtu={} icmp_seq={}: ", probe_mtu, icmp_seq);
        std::io::Write::flush(&mut std::io::stdout())?;

        socket.send_to(&full_packet, &socket_addr.into())?;
        icmp_seq += 1;

        let mut recv_buf = [std::mem::MaybeUninit::<u8>::uninit(); 2048];
        match socket.recv_from(&mut recv_buf) {
            Ok((len, addr)) => {
                let buf =
                    unsafe { std::slice::from_raw_parts(recv_buf.as_ptr() as *const u8, len) };
                let reply_addr = addr.as_socket_ipv4().map(|sock| sock.ip().clone());
                if let Some(reply_addr) = reply_addr {
                    print!("{}: ", reply_addr);
                }

                match handle_response_packet(buf, probe_mtu) {
                    Action::ReportPathMTU(path_mtu) => {
                        println!("ok");
                        println!("Path MTU to {}: {} bytes", target, path_mtu);
                        break;
                    }
                    Action::TryNextHop(size) => {
                        println!("fragmentation needed, next_hop={}", size);
                        probe_mtu = size;
                    }
                    Action::TryNext => {
                        println!("fragmentation needed");
                        probe_mtu -= 1;
                        sleep(Duration::from_millis(100));
                    }
                    Action::Ignore => {}
                }
            }
            Err(_) => {
                println!("timed out");
                probe_mtu -= 1;
                sleep(Duration::from_millis(100));
            }
        }
        if probe_mtu < 68 {
            break;
        }
    }

    Ok(())
}
