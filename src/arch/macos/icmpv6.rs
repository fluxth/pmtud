use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::os::unix::io::AsRawFd;
use std::thread::sleep;
use std::time::Duration;

use pnet_packet::icmpv6::echo_request::MutableEchoRequestPacket;
use pnet_packet::icmpv6::{Icmpv6Packet, Icmpv6Types};
use pnet_packet::{MutablePacket, Packet};
use socket2::{Domain, Protocol, Socket, Type};

const TIMEOUT: Duration = Duration::from_millis(1000);
const IPV6_MTU_MAX: u16 = 1500;
const IPV6_MTU_MIN: u16 = 1280;

fn build_icmpv6_echo_request_packet(size: u16, seq: u16) -> Vec<u8> {
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

enum Action {
    ReplyReceived,
    TryNextHop(u32),
    TryNext,
    Ignore,
}

fn handle_response_packet(buf: &[u8], size: u16) -> Action {
    let Some(icmpv6_packet) = Icmpv6Packet::new(buf) else {
        return Action::Ignore;
    };

    let icmpv6_type = icmpv6_packet.get_icmpv6_type();
    //let icmpv6_code = icmpv6_packet.get_icmpv6_code();

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

pub(crate) fn icmpv6_pmtud(target: Ipv6Addr) -> std::io::Result<()> {
    let socket_addr = SocketAddr::new(IpAddr::V6(target), 0);

    let socket = Socket::new(
        Domain::IPV6,
        Type::from(libc::SOCK_RAW),
        Some(Protocol::ICMPV6),
    )?;

    socket.set_read_timeout(Some(TIMEOUT))?;

    // tell the kernel we don't want to fragment our ipv6 packet
    let result = unsafe {
        let opt: libc::c_int = 1; // true - enabled
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_IPV6,
            libc::IPV6_DONTFRAG,
            &opt as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };

    if result != 0 {
        return Err(std::io::Error::last_os_error());
    }

    let mut max_mtu = IPV6_MTU_MAX;
    let mut min_mtu = IPV6_MTU_MIN;
    let mut probe_mtu = 1500;
    let mut icmp_seq = 0;

    while min_mtu < max_mtu {
        print!("probe mtu={} icmp_seq={}: ", probe_mtu, icmp_seq);
        std::io::Write::flush(&mut std::io::stdout())?;

        let raw_packet = build_icmpv6_echo_request_packet(probe_mtu, icmp_seq);

        match socket.send_to(&raw_packet, &socket_addr.into()) {
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

        let mut recv_buf = [std::mem::MaybeUninit::<u8>::uninit(); 2048];
        match socket.recv_from(&mut recv_buf) {
            Ok((len, addr)) => {
                let buf =
                    unsafe { std::slice::from_raw_parts(recv_buf.as_ptr() as *const u8, len) };
                let reply_addr = addr.as_socket_ipv6().map(|sock| sock.ip().clone());
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
                        let size = size.try_into().unwrap();
                        println!("packet too big, next_hop={}", size);
                        if max_mtu > size {
                            max_mtu = size;
                        } else {
                            max_mtu = probe_mtu - 1;
                        }
                        probe_mtu = size;
                    }
                    Action::TryNext => {
                        println!("packet too big");
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
