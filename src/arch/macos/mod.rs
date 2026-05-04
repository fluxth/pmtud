pub(crate) mod icmp;
pub(crate) mod icmpv6;
pub(crate) mod tcp_mss;

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::io::{AsRawFd, RawFd};
use std::thread::sleep;
use std::time::{Duration, Instant};

use pcap::{Capture, Device, Linktype};
use pnet_packet::ipv4::Ipv4Packet;
use pnet_packet::ipv6::Ipv6Packet;
use socket2::{Domain, Protocol, Socket, Type};

const TIMEOUT: Duration = Duration::from_millis(1000);
const PCAP_TICK_MS: i32 = 100;

#[derive(Debug, PartialEq, Eq)]
enum Action<M> {
    ReplyReceived,
    TryNextHop(M),
    TryNext,
    Ignore,
}

trait IcmpPmtud {
    type IpAddrType: std::fmt::Display + Copy + Into<IpAddr> + 'static;
    type MtuSizeType: TryInto<u16> + Copy;

    fn build_echo_request_packet(&self, size: u16, seq: u16, target: Self::IpAddrType) -> Vec<u8>;
    fn handle_response_packet(&self, buf: &[u8], size: u16) -> Action<Self::MtuSizeType>;
    fn get_socket_domain(&self) -> Domain;
    fn get_socket_protocol(&self) -> Protocol;
    fn set_socket_options(&self, socket_fd: RawFd) -> io::Result<()>;
    fn get_max_mtu(&self) -> u16;
    fn get_min_mtu(&self) -> u16;
    fn get_initial_probe_mtu(&self) -> u16 {
        self.get_max_mtu()
    }
    fn get_bpf_filter(&self, target: IpAddr) -> String;
    fn prepare_icmp_payload<'a>(&self, ip_data: &'a [u8]) -> Option<&'a [u8]>;
}

pub(super) fn find_outgoing_device(target: IpAddr, port: u16) -> io::Result<Device> {
    let domain = match target {
        IpAddr::V4(_) => Domain::IPV4,
        IpAddr::V6(_) => Domain::IPV6,
    };
    let probe = Socket::new(domain, Type::DGRAM, None)?;
    let target_addr: SocketAddr = (target, port).into();
    probe.connect(&target_addr.into())?;
    let local_ip = probe
        .local_addr()?
        .as_socket()
        .ok_or_else(|| io::Error::other("no local addr"))?
        .ip();

    Device::list()
        .map_err(|e| io::Error::other(e.to_string()))?
        .into_iter()
        .find(|d| d.addresses.iter().any(|a| a.addr == local_ip))
        .ok_or_else(|| io::Error::other(format!("no interface with address {}", local_ip)))
}

pub(super) fn ip_data_from_link_frame(data: &[u8], linktype: Linktype) -> Option<&[u8]> {
    match linktype.0 {
        1 => {
            // Ethernet: 6 dst + 6 src + 2 ethertype = 14 bytes
            if data.len() < 14 {
                return None;
            }
            let ethertype = u16::from_be_bytes([data[12], data[13]]);
            match ethertype {
                0x0800 /* IPv4 */ | 0x86DD /* IPv6 */ => data.get(14..), // skip 6 dst + 6 src + 2 ethertype
                _ => None,
            }
        }
        0 => {
            // BSD loopback: 4-byte address family in host byte order, then raw IP
            let af = data
                .get(..4)
                .and_then(|b| b.try_into().ok())
                .map(u32::from_ne_bytes)?;
            let ip_data = data.get(4..)?; // skip 4-byte AF prefix
            match af as libc::c_int {
                libc::AF_INET | libc::AF_INET6 => Some(ip_data),
                _ => None,
            }
        }
        _ => None,
    }
}

fn source_ip_from_ip_data(ip_data: &[u8]) -> Option<IpAddr> {
    // IP version is top nibble of first byte
    match ip_data.first().map(|b| b >> 4)? {
        4 => Ipv4Packet::new(ip_data).map(|p| IpAddr::V4(p.get_source())),
        6 => Ipv6Packet::new(ip_data).map(|p| IpAddr::V6(p.get_source())),
        _ => None,
    }
}

fn run_pmtud_by_icmp<T: IcmpPmtud>(pinger: &T, target: T::IpAddrType) -> io::Result<()> {
    let socket_addr = SocketAddr::new(target.into(), 0);

    let socket = Socket::new(
        pinger.get_socket_domain(),
        Type::from(libc::SOCK_RAW),
        Some(pinger.get_socket_protocol()),
    )?;

    pinger.set_socket_options(socket.as_raw_fd())?;

    let device = find_outgoing_device(target.into(), 1)?;
    let filter = pinger.get_bpf_filter(target.into());

    let mut cap = Capture::from_device(device)
        .map_err(|e| io::Error::other(e.to_string()))?
        .immediate_mode(true)
        .timeout(PCAP_TICK_MS)
        .open()
        .map_err(|e| io::Error::other(e.to_string()))?;

    cap.filter(&filter, true)
        .map_err(|e| io::Error::other(e.to_string()))?;

    let linktype = cap.get_datalink();

    let mut max_mtu = pinger.get_max_mtu();
    let mut min_mtu = pinger.get_min_mtu();
    let mut probe_mtu = pinger.get_initial_probe_mtu();
    let mut icmp_seq = 0;

    while min_mtu < max_mtu {
        let probe_seq = icmp_seq;
        print!("  probe[{}] size={}: listening...", probe_seq, probe_mtu);
        std::io::Write::flush(&mut std::io::stdout())?;

        let full_packet = pinger.build_echo_request_packet(probe_mtu, probe_seq, target);
        icmp_seq += 1;

        match socket.send_to(&full_packet, &socket_addr.into()) {
            Ok(_) => {}
            Err(ref err) if err.raw_os_error() == Some(libc::EMSGSIZE) => {
                println!(
                    "\r  probe[{}] size={}: from=kernel, message too long",
                    probe_seq, probe_mtu
                );
                max_mtu = probe_mtu - 1;
                probe_mtu = (max_mtu + min_mtu).div_ceil(2);
                continue;
            }
            Err(ref err) if err.raw_os_error() == Some(libc::EHOSTUNREACH) => {
                println!(
                    "\r  probe[{}] size={}: from=kernel, no route to host",
                    probe_seq, probe_mtu
                );
                println!("  path mtu: discovery failed");
                return Ok(());
            }
            Err(err) => {
                return Err(err);
            }
        }

        let probe_start = Instant::now();

        'receive: loop {
            match cap.next_packet() {
                Ok(packet) => {
                    let Some(ip_data) = ip_data_from_link_frame(packet.data, linktype) else {
                        continue 'receive;
                    };
                    let from_prefix = source_ip_from_ip_data(ip_data)
                        .map(|ip| format!("from={}, ", ip))
                        .unwrap_or_default();
                    let Some(icmp_data) = pinger.prepare_icmp_payload(ip_data) else {
                        continue 'receive;
                    };

                    match pinger.handle_response_packet(icmp_data, probe_mtu) {
                        Action::ReplyReceived => {
                            println!(
                                "\r  probe[{}] size={}: {}ok          ",
                                probe_seq, probe_mtu, from_prefix
                            );
                            min_mtu = probe_mtu;
                            if min_mtu < max_mtu {
                                probe_mtu = (max_mtu + min_mtu).div_ceil(2);
                                sleep(Duration::from_millis(100));
                            }
                            break 'receive;
                        }
                        Action::TryNextHop(size) => {
                            let size: u16 =
                                size.try_into().map_err(|_| ()).unwrap_or(probe_mtu - 1);
                            println!(
                                "\r  probe[{}] size={}: {}fragmentation needed, next_hop={}",
                                probe_seq, probe_mtu, from_prefix, size
                            );
                            if max_mtu > size {
                                max_mtu = size;
                            } else {
                                max_mtu = probe_mtu - 1;
                            }
                            probe_mtu = size;
                            break 'receive;
                        }
                        Action::TryNext => {
                            println!(
                                "\r  probe[{}] size={}: {}fragmentation needed",
                                probe_seq, probe_mtu, from_prefix
                            );
                            max_mtu = probe_mtu - 1;
                            probe_mtu = (max_mtu + min_mtu).div_ceil(2);
                            break 'receive;
                        }
                        Action::Ignore => {
                            if probe_start.elapsed() >= TIMEOUT {
                                println!(
                                    "\r  probe[{}] size={}: timed out   ",
                                    probe_seq, probe_mtu
                                );
                                max_mtu = probe_mtu - 1;
                                probe_mtu = (max_mtu + min_mtu).div_ceil(2);
                                break 'receive;
                            }
                        }
                    }
                }
                Err(pcap::Error::TimeoutExpired) => {
                    if probe_start.elapsed() >= TIMEOUT {
                        println!("\r  probe[{}] size={}: timed out   ", probe_seq, probe_mtu);
                        max_mtu = probe_mtu - 1;
                        probe_mtu = (max_mtu + min_mtu).div_ceil(2);
                        break 'receive;
                    }
                }
                Err(e) => return Err(io::Error::other(e.to_string())),
            }
        }
    }

    println!("  path mtu: {}", probe_mtu);

    Ok(())
}
