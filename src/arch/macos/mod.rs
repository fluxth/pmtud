pub(crate) mod icmp;
pub(crate) mod icmpv6;
pub(crate) mod tcp_mss;

use std::net::{IpAddr, SocketAddr};
use std::os::unix::io::{AsRawFd, RawFd};
use std::thread::sleep;
use std::time::Duration;

use socket2::{Domain, Protocol, Socket, Type};

const TIMEOUT: Duration = Duration::from_millis(1000);
const RECV_BUF_SIZE: usize = 9000;

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
    fn set_socket_options(&self, socket_fd: RawFd) -> std::io::Result<()>;
    fn get_max_mtu(&self) -> u16;
    fn get_min_mtu(&self) -> u16;
    fn get_initial_probe_mtu(&self) -> u16 {
        self.get_max_mtu()
    }
}

fn run_pmtud_by_icmp<T: IcmpPmtud>(pinger: &T, target: T::IpAddrType) -> std::io::Result<()> {
    let socket_addr = SocketAddr::new(target.into(), 0);

    let socket = Socket::new(
        pinger.get_socket_domain(),
        Type::from(libc::SOCK_RAW),
        Some(pinger.get_socket_protocol()),
    )?;

    socket.set_read_timeout(Some(TIMEOUT))?;

    pinger.set_socket_options(socket.as_raw_fd())?;

    let mut max_mtu = pinger.get_max_mtu();
    let mut min_mtu = pinger.get_min_mtu();
    let mut probe_mtu = pinger.get_initial_probe_mtu();
    let mut icmp_seq = 0;
    let mut recv_buf = Box::new([std::mem::MaybeUninit::<u8>::uninit(); RECV_BUF_SIZE]);

    while min_mtu < max_mtu {
        let probe_seq = icmp_seq;
        print!("  probe[{}] mtu={}: listening...", probe_seq, probe_mtu);
        std::io::Write::flush(&mut std::io::stdout())?;

        let full_packet = pinger.build_echo_request_packet(probe_mtu, probe_seq, target);
        icmp_seq += 1;

        match socket.send_to(&full_packet, &socket_addr.into()) {
            Ok(_) => {}
            Err(ref err) if err.raw_os_error() == Some(libc::EMSGSIZE) => {
                println!(
                    "\r  probe[{}] mtu={}: from=kernel, message too long",
                    probe_seq, probe_mtu
                );
                max_mtu = probe_mtu - 1;
                probe_mtu = (max_mtu + min_mtu).div_ceil(2);
                continue;
            }
            Err(ref err) if err.raw_os_error() == Some(libc::EHOSTUNREACH) => {
                println!(
                    "\r  probe[{}] mtu={}: from=kernel, no route to host",
                    probe_seq, probe_mtu
                );
                println!("  path mtu: discovery failed");
                return Ok(());
            }
            Err(err) => {
                return Err(err);
            }
        }

        match socket.recv_from(recv_buf.as_mut()) {
            Ok((len, addr)) => {
                let buf =
                    unsafe { std::slice::from_raw_parts(recv_buf.as_ptr() as *const u8, len) };
                let from_prefix = addr
                    .as_socket()
                    .map(|sock| format!("from={}, ", sock.ip()))
                    .unwrap_or_default();

                match pinger.handle_response_packet(buf, probe_mtu) {
                    Action::ReplyReceived => {
                        println!(
                            "\r  probe[{}] mtu={}: {}ok          ",
                            probe_seq, probe_mtu, from_prefix
                        );
                        min_mtu = probe_mtu;
                        if min_mtu < max_mtu {
                            probe_mtu = (max_mtu + min_mtu).div_ceil(2);
                            sleep(Duration::from_millis(100));
                        }
                    }
                    Action::TryNextHop(size) => {
                        let size: u16 = size.try_into().map_err(|_| ()).unwrap_or(probe_mtu - 1);
                        println!(
                            "\r  probe[{}] mtu={}: {}fragmentation needed, next_hop={}",
                            probe_seq, probe_mtu, from_prefix, size
                        );
                        if max_mtu > size {
                            max_mtu = size;
                        } else {
                            max_mtu = probe_mtu - 1;
                        }
                        probe_mtu = size;
                    }
                    Action::TryNext => {
                        println!(
                            "\r  probe[{}] mtu={}: {}fragmentation needed",
                            probe_seq, probe_mtu, from_prefix
                        );
                        max_mtu = probe_mtu - 1;
                        probe_mtu = (max_mtu + min_mtu).div_ceil(2);
                    }
                    Action::Ignore => {
                        // FIXME: ignored isn't the most descriptive thing to say here
                        println!(
                            "\r  probe[{}] mtu={}: {}ignored     ",
                            probe_seq, probe_mtu, from_prefix
                        );
                    }
                }
            }
            Err(_) => {
                println!("\r  probe[{}] mtu={}: timed out   ", probe_seq, probe_mtu);
                max_mtu = probe_mtu - 1;
                probe_mtu = (max_mtu + min_mtu).div_ceil(2);
            }
        }
    }

    println!("  path mtu: {}", probe_mtu);

    Ok(())
}
