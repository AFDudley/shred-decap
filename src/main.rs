// Decapsulate shreds from nested GRE tunnels and forward as raw UDP.
//
// Reads raw packets from a network interface via AF_PACKET socket,
// walks through nested GRE layers (TEB 0x6558, IPv4 0x0800, ERSPAN
// 0x88be) added by DoubleZero tunnels and Arista ERSPAN mirrors,
// extracts the innermost UDP payload, and forwards it to a destination.
//
// See scripts/shred-decap.py for the Python prototype.

use clap::Parser;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

const ETH_P_ALL: u16 = 0x0003;
const ETH_HEADER_LEN: usize = 14;
const IP_HEADER_MIN: usize = 20;
const GRE_HEADER_MIN: usize = 4;
const UDP_HEADER_LEN: usize = 8;

const GRE_PROTO_TEB: u16 = 0x6558;
const GRE_PROTO_IP4: u16 = 0x0800;
// ERSPAN Type II — Arista 7280CR3A sends raw IPv4 after the GRE key,
// no ERSPAN header. Treat same as GRE_PROTO_IP4.
const GRE_PROTO_ERSPAN_II: u16 = 0x88BE;

// DZ heartbeat port
const HEARTBEAT_PORT: u16 = 44880;

// Minimum payload size to forward (skip tiny control packets)
const MIN_PAYLOAD_SIZE: usize = 100;

// DZ full mesh can nest 30+ GRE layers
const MAX_GRE_DEPTH: usize = 64;

#[derive(Parser)]
#[command(
    about = "Decapsulate shreds from nested GRE tunnels and forward as UDP",
    version = concat!(env!("CARGO_PKG_VERSION"), " (", env!("GIT_HASH"), ")"),
)]
struct Args {
    /// Interface to capture from
    #[arg(long, default_value = "eno1")]
    iface: String,

    /// Host to forward extracted payloads to
    #[arg(long, default_value = "127.0.0.1")]
    forward_host: String,

    /// Port to forward extracted payloads to
    #[arg(long, default_value_t = 7005)]
    forward_port: u16,

    /// Additional host:port destinations (e.g. for shredtop monitoring)
    #[arg(long)]
    also_send: Vec<String>,

    /// Only forward inner UDP packets with this dst port (0 = no filter)
    #[arg(long, default_value_t = 0)]
    filter_dst_port: u16,

    /// Print stats every N seconds
    #[arg(long, default_value_t = 30)]
    stats_interval: u64,

    /// Interface delivers raw IP with no link-layer header (GRE tunnel
    /// interfaces like doublezero0). Starts parsing at the IP layer.
    #[arg(long)]
    raw_ip: bool,

    /// Demux by inner multicast group dst IP. Format: GROUP_IP=RUSSULA_PORT:SHREDTOP_PORT
    /// e.g. --demux 233.84.178.1=7005:9103 --demux 233.84.178.2=7006:9104
    /// When demux is set, --forward-host/port and --also-send are ignored.
    #[arg(long)]
    demux: Vec<String>,
}

/// Result of extracting the inner UDP payload from nested GRE.
struct ExtractedUdp<'a> {
    payload: &'a [u8],
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
}

/// Walk nested GRE layers and return innermost UDP payload.
///
/// `link_hdr_len` is the link-layer header size: 14 for Ethernet,
/// 0 for raw IP (GRE tunnel interfaces deliver IPv4 directly via
/// AF_PACKET with no link-layer header).
fn extract_inner_udp(data: &[u8], link_hdr_len: usize) -> Option<ExtractedUdp<'_>> {
    if data.len() < link_hdr_len + IP_HEADER_MIN {
        return None;
    }

    let mut offset = 0usize;
    let mut eth_type = if link_hdr_len == 0 {
        // Raw IP — no link header, data starts at IPv4
        0x0800u16
    } else {
        // Ethernet — protocol at bytes [12..14]
        u16::from_be_bytes([data[link_hdr_len - 2], data[link_hdr_len - 1]])
    };
    offset += link_hdr_len;
    let mut depth = 0usize;

    while offset < data.len() && depth < MAX_GRE_DEPTH {
        if eth_type != 0x0800 {
            return None;
        }

        // Parse IPv4 header
        if data.len() < offset + IP_HEADER_MIN {
            return None;
        }
        let vhl = data[offset];
        if (vhl >> 4) != 4 {
            return None;
        }
        let ihl = ((vhl & 0x0F) as usize) * 4;
        let proto = data[offset + 9];
        let ip_src: [u8; 4] = [
            data[offset + 12],
            data[offset + 13],
            data[offset + 14],
            data[offset + 15],
        ];
        let ip_dst: [u8; 4] = [
            data[offset + 16],
            data[offset + 17],
            data[offset + 18],
            data[offset + 19],
        ];
        offset += ihl;

        match proto {
            47 => {
                // GRE
                if data.len() < offset + GRE_HEADER_MIN {
                    return None;
                }
                let flags = u16::from_be_bytes([data[offset], data[offset + 1]]);
                let gre_proto = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
                let mut gre_len = 4usize;
                if flags & 0x8000 != 0 {
                    gre_len += 4; // checksum
                }
                if flags & 0x2000 != 0 {
                    gre_len += 4; // key
                }
                if flags & 0x1000 != 0 {
                    gre_len += 4; // sequence
                }
                offset += gre_len;
                depth += 1;

                match gre_proto {
                    GRE_PROTO_TEB => {
                        // Another Ethernet frame inside
                        if data.len() < offset + ETH_HEADER_LEN {
                            return None;
                        }
                        eth_type = u16::from_be_bytes([data[offset + 12], data[offset + 13]]);
                        offset += ETH_HEADER_LEN;
                    }
                    GRE_PROTO_IP4 | GRE_PROTO_ERSPAN_II => {
                        eth_type = 0x0800;
                    }
                    _ => return None,
                }
            }
            17 => {
                // UDP
                if data.len() < offset + UDP_HEADER_LEN {
                    return None;
                }
                let src_port = u16::from_be_bytes([data[offset], data[offset + 1]]);
                let dst_port = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
                let udp_len = u16::from_be_bytes([data[offset + 4], data[offset + 5]]) as usize;
                let payload_len = udp_len.saturating_sub(UDP_HEADER_LEN);
                let payload_start = offset + UDP_HEADER_LEN;
                let payload_end = (payload_start + payload_len).min(data.len());
                if payload_start >= data.len() {
                    return None;
                }
                return Some(ExtractedUdp {
                    payload: &data[payload_start..payload_end],
                    src_ip: ip_src,
                    dst_ip: ip_dst,
                    src_port,
                    dst_port,
                });
            }
            _ => return None,
        }
    }

    None
}

/// Create an AF_PACKET raw socket bound to an interface.
fn raw_socket(iface: &str) -> io::Result<i32> {
    // SAFETY: creating a raw packet socket and binding to interface.
    // The fd is owned by the caller and closed in main().
    unsafe {
        let fd = libc::socket(libc::AF_PACKET, libc::SOCK_RAW, (ETH_P_ALL as i32).to_be());
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        // Get interface index
        let mut ifr: libc::ifreq = std::mem::zeroed();
        let name_bytes = iface.as_bytes();
        if name_bytes.len() >= ifr.ifr_name.len() {
            libc::close(fd);
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "interface name too long",
            ));
        }
        for (i, &b) in name_bytes.iter().enumerate() {
            ifr.ifr_name[i] = b as libc::c_char;
        }

        if libc::ioctl(fd, libc::SIOCGIFINDEX, &ifr) < 0 {
            let err = io::Error::last_os_error();
            libc::close(fd);
            return Err(err);
        }

        let ifindex = ifr.ifr_ifru.ifru_ifindex;

        // Bind to interface
        let mut sll: libc::sockaddr_ll = std::mem::zeroed();
        sll.sll_family = libc::AF_PACKET as u16;
        sll.sll_protocol = ETH_P_ALL.to_be();
        sll.sll_ifindex = ifindex;

        let ret = libc::bind(
            fd,
            &sll as *const libc::sockaddr_ll as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        );
        if ret < 0 {
            let err = io::Error::last_os_error();
            libc::close(fd);
            return Err(err);
        }

        // Set receive buffer to 16MB for high packet rates
        let buf_size: libc::c_int = 16 * 1024 * 1024;
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &buf_size as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );

        Ok(fd)
    }
}

fn recv_packet(fd: i32, buf: &mut [u8]) -> io::Result<usize> {
    // SAFETY: reading from raw socket fd into provided buffer.
    let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
    if n < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}

/// Create an IPPROTO_RAW socket for sending packets with custom IP headers.
/// IP_HDRINCL is implicit with IPPROTO_RAW.
fn raw_ip_socket() -> io::Result<i32> {
    // SAFETY: creating a raw IP socket. Caller owns the fd.
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_RAW);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(fd)
    }
}

/// Send a UDP payload via raw socket with spoofed source IP:port.
/// Builds IP + UDP headers manually. UDP checksum set to 0 (optional in IPv4).
fn send_raw_udp(
    raw_fd: i32,
    src_ip: [u8; 4],
    src_port: u16,
    dst: &SocketAddr,
    payload: &[u8],
    pkt_buf: &mut Vec<u8>,
) {
    let dst_ip = match dst.ip() {
        std::net::IpAddr::V4(ip) => ip.octets(),
        _ => return,
    };
    let dst_port = dst.port();
    let udp_len = (UDP_HEADER_LEN + payload.len()) as u16;
    let total_len = (IP_HEADER_MIN + UDP_HEADER_LEN + payload.len()) as u16;

    pkt_buf.clear();
    // IP header (20 bytes)
    pkt_buf.push(0x45); // version=4, ihl=5
    pkt_buf.push(0x00); // DSCP/ECN
    pkt_buf.extend_from_slice(&total_len.to_be_bytes());
    pkt_buf.extend_from_slice(&[0, 0]); // identification
    pkt_buf.extend_from_slice(&[0x40, 0x00]); // flags=DF, frag=0
    pkt_buf.push(64); // TTL
    pkt_buf.push(17); // protocol=UDP
    pkt_buf.extend_from_slice(&[0, 0]); // checksum (kernel fills)
    pkt_buf.extend_from_slice(&src_ip);
    pkt_buf.extend_from_slice(&dst_ip);
    // UDP header (8 bytes)
    pkt_buf.extend_from_slice(&src_port.to_be_bytes());
    pkt_buf.extend_from_slice(&dst_port.to_be_bytes());
    pkt_buf.extend_from_slice(&udp_len.to_be_bytes());
    pkt_buf.extend_from_slice(&[0, 0]); // checksum=0 (optional for IPv4)
                                        // Payload
    pkt_buf.extend_from_slice(payload);

    // SAFETY: sending raw IP packet via sendto. The sockaddr and buffer are
    // valid for the duration of the call.
    unsafe {
        let mut addr: libc::sockaddr_in = std::mem::zeroed();
        addr.sin_family = libc::AF_INET as libc::sa_family_t;
        addr.sin_port = dst_port.to_be();
        addr.sin_addr.s_addr = u32::from_be_bytes(dst_ip).to_be();
        libc::sendto(
            raw_fd,
            pkt_buf.as_ptr() as *const libc::c_void,
            pkt_buf.len(),
            0,
            &addr as *const libc::sockaddr_in as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        );
    }
}

static mut RUNNING_FLAG: *const AtomicBool = std::ptr::null();

extern "C" fn signal_handler(_sig: libc::c_int) {
    // SAFETY: RUNNING_FLAG is set once before signals can fire (in main),
    // never deallocated (Box::leak). AtomicBool::store is async-signal-safe.
    unsafe {
        if !RUNNING_FLAG.is_null() {
            (*RUNNING_FLAG).store(false, Ordering::Relaxed);
        }
    }
}

/// Demux entry: maps a multicast group IP to output ports.
struct DemuxEntry {
    russula_dest: SocketAddr,
    shredtop_dest: SocketAddr,
}

/// Parse --demux GROUP_IP=RUSSULA_PORT:SHREDTOP_PORT
/// russula_host controls where russula packets go (default 127.0.0.1,
/// set to 172.20.0.2 to send directly to the validator pod).
fn parse_demux(
    specs: &[String],
    russula_host: &str,
) -> io::Result<std::collections::HashMap<[u8; 4], DemuxEntry>> {
    use std::collections::HashMap;
    let mut map = HashMap::new();
    for spec in specs {
        let parts: Vec<&str> = spec.splitn(2, '=').collect();
        if parts.len() != 2 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("bad demux format: {spec} (expected IP=RUSSULA_PORT:SHREDTOP_PORT)"),
            ));
        }
        let ip: std::net::Ipv4Addr = parts[0]
            .parse()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let ports: Vec<&str> = parts[1].splitn(2, ':').collect();
        if ports.len() != 2 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("bad port format: {} (expected RUSSULA:SHREDTOP)", parts[1]),
            ));
        }
        let russula_port: u16 = ports[0]
            .parse()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let shredtop_port: u16 = ports[1]
            .parse()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        map.insert(
            ip.octets(),
            DemuxEntry {
                russula_dest: format!("{russula_host}:{russula_port}")
                    .parse()
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?,
                shredtop_dest: format!("127.0.0.1:{shredtop_port}").parse().unwrap(),
            },
        );
    }
    Ok(map)
}

fn main() -> io::Result<()> {
    let args = Args::parse();

    let fd = raw_socket(&args.iface)?;
    let link_hdr_len = if args.raw_ip { 0 } else { ETH_HEADER_LEN };

    // Parse demux map
    let demux_map = parse_demux(&args.demux, &args.forward_host)?;
    let use_demux = !demux_map.is_empty();

    let dest: SocketAddr = format!("{}:{}", args.forward_host, args.forward_port)
        .parse()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let mut extra_dests: Vec<SocketAddr> = Vec::new();
    if !use_demux {
        for s in &args.also_send {
            extra_dests.push(
                s.parse()
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?,
            );
        }
    }
    let sock_out = UdpSocket::bind("0.0.0.0:0")?;

    // Raw IP socket for also-send / demux shredtop: preserves original source IP:port
    let raw_fd = if extra_dests.is_empty() && !use_demux {
        -1
    } else {
        raw_ip_socket()?
    };

    // Signal handling for graceful shutdown
    let running = &*Box::leak(Box::new(AtomicBool::new(true)));
    // SAFETY: setting global pointer before installing signal handlers.
    // Box::leak ensures the AtomicBool lives for the entire process.
    unsafe {
        RUNNING_FLAG = running as *const AtomicBool;
        libc::signal(libc::SIGTERM, signal_handler as libc::sighandler_t);
        libc::signal(libc::SIGINT, signal_handler as libc::sighandler_t);
    }

    if use_demux {
        eprintln!(
            "Demux {} (skip heartbeat port {}, min payload {}B)",
            args.iface, HEARTBEAT_PORT, MIN_PAYLOAD_SIZE,
        );
        for (ip, entry) in &demux_map {
            eprintln!(
                "  {}.{}.{}.{} → russula {} / shredtop {}",
                ip[0], ip[1], ip[2], ip[3], entry.russula_dest, entry.shredtop_dest,
            );
        }
    } else {
        eprintln!(
            "Forwarding {} → {}:{} (skip heartbeat port {}, min payload {}B{})",
            args.iface,
            args.forward_host,
            args.forward_port,
            HEARTBEAT_PORT,
            MIN_PAYLOAD_SIZE,
            if args.filter_dst_port != 0 {
                format!(", filter dst_port={}", args.filter_dst_port)
            } else {
                String::new()
            },
        );
        for ed in &extra_dests {
            eprintln!("  also → {ed}");
        }
    }

    let mut buf = [0u8; 65535];
    let mut raw_pkt_buf: Vec<u8> = Vec::with_capacity(2048);
    let mut forwarded: u64 = 0;
    let mut dropped_heartbeat: u64 = 0;
    let mut dropped_small: u64 = 0;
    let mut dropped_port: u64 = 0;
    let mut dropped_parse: u64 = 0;
    let mut total: u64 = 0;
    let start = Instant::now();
    let mut last_stats = start;
    let stats_dur = std::time::Duration::from_secs(args.stats_interval);

    while running.load(Ordering::Relaxed) {
        let n = match recv_packet(fd, &mut buf) {
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => {
                eprintln!("recv error: {e}");
                break;
            }
        };

        total += 1;
        let data = &buf[..n];

        let extracted = match extract_inner_udp(data, link_hdr_len) {
            Some(e) => e,
            None => {
                dropped_parse += 1;
                continue;
            }
        };

        if extracted.src_port == HEARTBEAT_PORT || extracted.dst_port == HEARTBEAT_PORT {
            dropped_heartbeat += 1;
            continue;
        }

        if args.filter_dst_port != 0 && extracted.dst_port != args.filter_dst_port {
            dropped_port += 1;
            continue;
        }

        if extracted.payload.len() < MIN_PAYLOAD_SIZE {
            dropped_small += 1;
            continue;
        }

        if use_demux {
            // Demux: look up inner dst IP to find output ports
            if let Some(entry) = demux_map.get(&extracted.dst_ip) {
                // Russula: plain UDP (payload only)
                let _ = sock_out.send_to(extracted.payload, entry.russula_dest);
                // Shredtop: raw socket preserving source IP:port
                send_raw_udp(
                    raw_fd,
                    extracted.src_ip,
                    extracted.src_port,
                    &entry.shredtop_dest,
                    extracted.payload,
                    &mut raw_pkt_buf,
                );
                forwarded += 1;
            }
            // Unknown group: silently drop (not an error — just non-shred multicast)
        } else {
            // Legacy mode: single destination
            let _ = sock_out.send_to(extracted.payload, dest);
            for ed in &extra_dests {
                send_raw_udp(
                    raw_fd,
                    extracted.src_ip,
                    extracted.src_port,
                    ed,
                    extracted.payload,
                    &mut raw_pkt_buf,
                );
            }
            forwarded += 1;
        }

        // Periodic stats
        let now = Instant::now();
        if now.duration_since(last_stats) >= stats_dur {
            let elapsed = now.duration_since(start).as_secs_f64();
            let rate = forwarded as f64 / elapsed;
            let total_rate = total as f64 / elapsed;
            eprintln!(
                "[{elapsed:.0}s] forwarded={forwarded} ({rate:.0}/s) \
                 total={total} ({total_rate:.0}/s) \
                 dropped: heartbeat={dropped_heartbeat} \
                 port={dropped_port} \
                 small={dropped_small} parse={dropped_parse}",
            );
            last_stats = now;
        }
    }

    let elapsed = start.elapsed().as_secs_f64();
    eprintln!(
        "\nShutdown after {elapsed:.0}s. \
         Forwarded {forwarded} packets, \
         dropped {} \
         (heartbeat={dropped_heartbeat} \
         port={dropped_port} \
         small={dropped_small} \
         parse={dropped_parse})",
        dropped_heartbeat + dropped_port + dropped_small + dropped_parse,
    );

    // SAFETY: closing the raw socket fds we opened.
    unsafe {
        libc::close(fd);
        if raw_fd >= 0 {
            libc::close(raw_fd);
        }
    }
    Ok(())
}
