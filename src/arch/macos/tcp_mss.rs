use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use pcap::{Capture, Linktype};
use pnet_packet::Packet;
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv4::Ipv4Packet;
use pnet_packet::ipv6::Ipv6Packet;
use pnet_packet::tcp::{TcpOptionNumbers, TcpPacket};
use socket2::{Domain, Protocol, Socket, Type};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

struct SynAckInfo {
    mss: u16,
    has_timestamps: bool,
}

fn parse_tcp_options(data: &[u8]) -> Option<SynAckInfo> {
    let tcp = TcpPacket::new(data)?;
    let mut mss: Option<u16> = None;
    let mut has_timestamps = false;
    for option in tcp.get_options_iter() {
        match option.get_number() {
            TcpOptionNumbers::MSS => {
                if let [high, low] = option.payload() {
                    mss = Some(u16::from_be_bytes([*high, *low]));
                }
            }
            TcpOptionNumbers::TIMESTAMPS => {
                has_timestamps = true;
            }
            _ => {}
        }
    }
    mss.map(|mss| SynAckInfo {
        mss,
        has_timestamps,
    })
}

fn parse_syn_ack_options(data: &[u8], linktype: Linktype) -> Option<SynAckInfo> {
    let ip_data = super::ip_data_from_link_frame(data, linktype)?;
    match ip_data.first().map(|b| b >> 4)? {
        4 => {
            let ip = Ipv4Packet::new(ip_data)?;
            if ip.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
                return None;
            }
            parse_tcp_options(ip.payload())
        }
        6 => {
            let ip = Ipv6Packet::new(ip_data)?;
            if ip.get_next_header() != IpNextHeaderProtocols::Tcp {
                return None;
            }
            parse_tcp_options(ip.payload())
        }
        _ => None,
    }
}

fn capture_syn_ack(target: IpAddr, port: u16) -> io::Result<SynAckInfo> {
    let device = super::find_outgoing_device(target, port)?;

    let domain = match target {
        IpAddr::V4(_) => Domain::IPV4,
        IpAddr::V6(_) => Domain::IPV6,
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    let bind_addr: SocketAddr = match target {
        IpAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0u16).into(),
        IpAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0u16).into(),
    };
    socket.bind(&bind_addr.into())?;
    let local_port = socket
        .local_addr()?
        .as_socket()
        .ok_or_else(|| io::Error::other("no local addr"))?
        .port();

    let filter = match target {
        IpAddr::V4(ip) => format!(
            "src host {} and dst port {} and tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn|tcp-ack",
            ip, local_port
        ),
        IpAddr::V6(ip) => format!(
            "ip6 and src host {} and dst port {} and ip6[53] & 0x12 == 0x12",
            ip, local_port
        ),
    };

    let mut cap = Capture::from_device(device)
        .map_err(|e| io::Error::other(e.to_string()))?
        .immediate_mode(true)
        .timeout(CONNECT_TIMEOUT.as_millis() as i32 + 1000)
        .open()
        .map_err(|e| io::Error::other(e.to_string()))?;

    cap.filter(&filter, true)
        .map_err(|e| io::Error::other(e.to_string()))?;

    let linktype = cap.get_datalink();

    let target_addr: SocketAddr = (target, port).into();
    let connect_handle = std::thread::spawn(move || {
        let _ = socket.connect_timeout(&target_addr.into(), CONNECT_TIMEOUT);
    });

    let result = loop {
        match cap.next_packet() {
            Ok(packet) => {
                if let Some(result) = parse_syn_ack_options(packet.data, linktype) {
                    break Ok(result);
                }
            }
            Err(pcap::Error::TimeoutExpired) => {
                break Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "no SYN-ACK captured within timeout",
                ));
            }
            Err(e) => break Err(io::Error::other(e.to_string())),
        }
    };

    let _ = connect_handle.join();
    result
}

pub(crate) fn tcp_mss_pmtud_v4(target: Ipv4Addr, port: u16) -> io::Result<()> {
    print!("  probe: connecting...");
    std::io::Write::flush(&mut std::io::stdout())?;
    match capture_syn_ack(IpAddr::V4(target), port) {
        Ok(info) => {
            // Raw SYN-ACK MSS follows RFC 6691: MTU - IP(20) - TCP(20), no TS deduction.
            let estimated_mtu = info.mss as u32 + 40;
            println!(
                "\r  probe: from={}, mss={}, timestamps={}",
                target, info.mss, info.has_timestamps
            );
            println!("  estimated path mtu: {}", estimated_mtu);
        }
        Err(ref err) if err.kind() == io::ErrorKind::TimedOut => {
            println!("\r  probe: timed out    ");
        }
        Err(err) => return Err(err),
    }
    Ok(())
}

pub(crate) fn tcp_mss_pmtud_v6(target: Ipv6Addr, port: u16) -> io::Result<()> {
    print!("  probe: connecting...");
    std::io::Write::flush(&mut std::io::stdout())?;
    match capture_syn_ack(IpAddr::V6(target), port) {
        Ok(info) => {
            // Raw SYN-ACK MSS follows RFC 6691: MTU - IPv6(40) - TCP(20), no TS deduction.
            let estimated_mtu = info.mss as u32 + 60;
            println!(
                "\r  probe: from={}, mss={}, timestamps={}",
                target, info.mss, info.has_timestamps
            );
            println!("  estimated path mtu: {}", estimated_mtu);
        }
        Err(ref err) if err.kind() == io::ErrorKind::TimedOut => {
            println!("\r  probe: timed out    ");
        }
        Err(err) => return Err(err),
    }
    Ok(())
}
