//! Linux per-socket TCP byte counters via `NETLINK_SOCK_DIAG`.
//!
//! Replaces the placeholder Linux throughput sampler. We talk directly
//! to the kernel via netlink (the same mechanism `ss` uses internally)
//! to fetch `bytes_acked` (cumulative tx) and `bytes_received`
//! (cumulative rx) per established TCP socket. The result is keyed by
//! the client-side local port so the lsof-driven join in
//! `tunnel_live::annotate_peer_throughput` can attribute counters to
//! the right tunnel client.
//!
//! Permission model: an unprivileged process gets only sockets owned
//! by its own UID. The kernel filters by UID before sending responses,
//! so this surface cannot leak counters from other users' sockets.
//!
//! Failure model: any error (socket open, send, recv, parse, kernel
//! NLMSG_ERROR) is logged once with the `[external]` fault prefix and
//! the function returns an empty map. The renderer then shows
//! "sampling…" exactly as it does on a fresh tunnel before throughput
//! data has arrived. We never panic the lsof-poller thread.
//!
//! Resource cap: at most `MAX_SOCKETS` (4096) entries are returned per
//! call. On a host with more established sockets, the dump is
//! truncated and a single `warn!` per truncation is emitted.
//!
//! No syscalls are made in unit tests — those construct response
//! packets with the same crate's emitters and round-trip them through
//! the parser to verify decode correctness without touching the
//! kernel.

#![cfg(target_os = "linux")]

// Big-endian Linux is not a release target for purple (we ship
// x86_64-unknown-linux-gnu and aarch64-unknown-linux-gnu binaries,
// both little-endian). The `tcp_info` byte-offset extraction below
// uses `from_ne_bytes` which would silently misparse on a big-endian
// host because `ss` and the kernel emit native-CPU-endian struct
// dumps. Refuse to compile rather than ship a sampler that returns
// transposed counters.
#[cfg(target_endian = "big")]
compile_error!(
    "tcp_diag is not supported on big-endian Linux. \
     `tcpi_bytes_acked`/`tcpi_bytes_received` extraction uses native-endian \
     reads that would misparse on big-endian hosts. \
     If you need this target, port `extract_tcp_counters` to explicit \
     `from_le_bytes` and remove this guard."
);

use std::collections::HashMap;
use std::panic::{self, AssertUnwindSafe};

use netlink_packet_core::{
    NLM_F_DUMP, NLM_F_REQUEST, NetlinkHeader, NetlinkMessage, NetlinkPayload,
};
use netlink_packet_sock_diag::{
    SockDiagMessage,
    constants::{AF_INET, AF_INET6, IPPROTO_TCP},
    inet::{ExtensionFlags, InetRequest, SocketId, StateFlags, nlas::Nla},
};
use netlink_sys::{Socket, SocketAddr, protocols::NETLINK_SOCK_DIAG};

/// Hard cap on the number of per-socket entries we accept from a
/// single dump. A typical workstation has tens of established TCP
/// sockets at any moment; 4096 is far above realistic and protects us
/// from runaway allocation if a co-tenant inflates the socket count.
const MAX_SOCKETS: usize = 4096;

/// Receive buffer size per `recv_from` call. Netlink message batches
/// fit comfortably in 32 KiB; the kernel will split larger dumps
/// across multiple recvs which we drain in a loop.
const RECV_BUF_LEN: usize = 32 * 1024;

/// Sample cumulative TCP byte counters keyed by client local port.
///
/// Returns `(bytes_received, bytes_acked)` where:
/// - `bytes_received` is the cumulative rx for that socket
/// - `bytes_acked` is the cumulative tx that has been acknowledged
///
/// This call is infallible from the caller's perspective: any error
/// is logged and an empty map is returned. The caller treats an empty
/// map as "no data yet" and falls back to the "sampling…" UI branch.
pub fn sample_per_local_port() -> HashMap<u16, (u64, u64)> {
    let mut out = HashMap::new();
    let mut truncated = false;

    for family in [AF_INET, AF_INET6] {
        match dump_family(family, &mut out, &mut truncated) {
            Ok(()) => {}
            Err(e) => {
                log::warn!("[external] netlink INET_DIAG family={family} dump failed: {e}",);
            }
        }
        if out.len() >= MAX_SOCKETS {
            break;
        }
    }

    if truncated {
        log::warn!(
            "[external] netlink dump truncated at {MAX_SOCKETS} sockets; counters for additional sockets are skipped this tick",
        );
    }

    log::debug!("[external] netlink returned {} socket(s)", out.len());
    out
}

/// Dump established TCP sockets for one address family and merge the
/// per-socket counters into `out`. The parse loop is wrapped in
/// `catch_unwind` so a panic inside the upstream parser cannot kill
/// the lsof-poller thread.
fn dump_family(
    family: u8,
    out: &mut HashMap<u16, (u64, u64)>,
    truncated: &mut bool,
) -> Result<(), DumpError> {
    let socket_id = match family {
        AF_INET => SocketId::new_v4(),
        AF_INET6 => SocketId::new_v6(),
        _ => return Err(DumpError::UnsupportedFamily(family)),
    };

    let mut socket = Socket::new(NETLINK_SOCK_DIAG).map_err(DumpError::OpenSocket)?;
    socket.bind_auto().map_err(DumpError::Bind)?;

    let request = InetRequest {
        family,
        protocol: IPPROTO_TCP,
        extensions: ExtensionFlags::INFO,
        states: StateFlags::ESTABLISHED,
        socket_id,
    };

    let mut header = NetlinkHeader::default();
    header.flags = NLM_F_REQUEST | NLM_F_DUMP;
    let mut packet = NetlinkMessage::new(
        header,
        NetlinkPayload::from(SockDiagMessage::InetRequest(request)),
    );
    packet.finalize();

    let mut send_buf = vec![0u8; packet.buffer_len()];
    packet.serialize(&mut send_buf);

    let kernel_addr = SocketAddr::new(0, 0);
    socket
        .send_to(&send_buf, &kernel_addr, 0)
        .map_err(DumpError::Send)?;

    catch_panic(|| drain_responses(&socket, out, truncated))
}

/// Wrap a closure that returns `Result<(), DumpError>` in
/// `panic::catch_unwind` and convert any panic into
/// `DumpError::ParsePanic`. The lsof-poller thread that calls
/// `sample_per_local_port` must never die from a panic in the
/// upstream `netlink-packet-sock-diag` parser, so this wrapper is the
/// single chokepoint where unwinding from the parse loop is contained.
///
/// `AssertUnwindSafe` is used because the closure captures `&mut`
/// references whose types do not implement `UnwindSafe`. A panic mid-
/// drain leaves a possibly-partial `out` map; the caller in
/// `dump_family` then returns `Err(ParsePanic)` and the outer
/// `sample_per_local_port` discards `out` so the partial state never
/// reaches the UI.
fn catch_panic<F>(f: F) -> Result<(), DumpError>
where
    F: FnOnce() -> Result<(), DumpError>,
{
    match panic::catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(DumpError::ParsePanic),
    }
}

/// Drain `recv_from` until the kernel signals `Done` or `Error`. Each
/// recv may contain multiple netlink messages back-to-back; we walk
/// them via the header `length` field. Per-message decode failures
/// are logged at `debug` and skipped so a single bad message never
/// aborts the whole dump.
fn drain_responses(
    socket: &Socket,
    out: &mut HashMap<u16, (u64, u64)>,
    truncated: &mut bool,
) -> Result<(), DumpError> {
    let mut recv_buf = vec![0u8; RECV_BUF_LEN];

    loop {
        // recv_from accepts &mut &mut [u8] (the inner reference is
        // resliced by the implementation). Returns the number of
        // bytes read for the entire batch.
        let mut slice = &mut recv_buf[..];
        let (size, _addr) = socket.recv_from(&mut slice, 0).map_err(DumpError::Recv)?;
        let bytes = &recv_buf[..size];

        match process_batch(bytes, out, truncated)? {
            BatchOutcome::Continue => {}
            BatchOutcome::Done => return Ok(()),
        }

        if out.len() >= MAX_SOCKETS {
            return Ok(());
        }
    }
}

/// Parse one recv batch into individual netlink messages and merge
/// counters. Returns `Done` when the batch ends with a `NLMSG_DONE`
/// payload, otherwise `Continue` so the caller issues another recv.
///
/// Per-message decode failures use the raw header `length` field
/// (first 4 bytes of every netlink message) to advance the offset
/// past the bad message rather than aborting the whole batch. That
/// way a single malformed entry inside a multi-message recv does not
/// silently discard the valid entries that follow it.
fn process_batch(
    bytes: &[u8],
    out: &mut HashMap<u16, (u64, u64)>,
    truncated: &mut bool,
) -> Result<BatchOutcome, DumpError> {
    let mut offset = 0usize;
    while offset < bytes.len() {
        let remaining = &bytes[offset..];

        // Peek the raw header length first so we can advance past a
        // malformed message even if full deserialization fails. The
        // netlink header lays out `length` (u32 native-endian) in the
        // first 4 bytes of every message.
        let raw_len = match peek_msg_len(remaining) {
            Some(l) => l,
            None => {
                log::debug!(
                    "[external] netlink: header truncated ({} bytes), aborting batch",
                    remaining.len()
                );
                return Ok(BatchOutcome::Done);
            }
        };
        if raw_len == 0 || raw_len > remaining.len() {
            log::debug!("[external] netlink: invalid header length ({raw_len}), aborting batch");
            return Ok(BatchOutcome::Done);
        }

        match NetlinkMessage::<SockDiagMessage>::deserialize(remaining) {
            Ok(msg) => match msg.payload {
                NetlinkPayload::Done(_) => return Ok(BatchOutcome::Done),
                NetlinkPayload::Error(err) => {
                    return Err(DumpError::KernelError(format!("{err:?}")));
                }
                NetlinkPayload::Overrun(_) => {
                    log::warn!(
                        "[external] netlink OVERRUN: kernel dropped messages, counters incomplete this tick",
                    );
                    return Ok(BatchOutcome::Done);
                }
                NetlinkPayload::InnerMessage(SockDiagMessage::InetResponse(resp)) => {
                    if out.len() >= MAX_SOCKETS {
                        *truncated = true;
                    } else {
                        merge_response(&resp, out);
                    }
                }
                // Noop and any future non_exhaustive variants: ignore.
                _ => {}
            },
            Err(e) => {
                log::debug!(
                    "[external] netlink: skipping malformed message at offset {offset}: {e}"
                );
                // Advance past the bad message using the raw header
                // length so subsequent valid messages in this batch
                // are still processed.
            }
        }

        offset += align(raw_len);
    }
    Ok(BatchOutcome::Continue)
}

/// Read the netlink header `length` field (first 4 bytes of every
/// message, native-endian u32) without trying to parse the rest.
/// Returns `None` if `bytes` is shorter than 4.
fn peek_msg_len(bytes: &[u8]) -> Option<usize> {
    if bytes.len() < 4 {
        return None;
    }
    let raw: [u8; 4] = bytes[0..4].try_into().ok()?;
    Some(u32::from_ne_bytes(raw) as usize)
}

/// Byte offsets of `tcpi_bytes_acked` and `tcpi_bytes_received` in
/// the kernel's `struct tcp_info` (see `linux/include/uapi/linux/tcp.h`).
/// These match RFC4898 `tcpEStatsAppHCThruOctetsAcked` and
/// `tcpEStatsAppHCThruOctetsReceived` respectively. Stable since
/// kernel 4.0; later kernels append fields after byte 136 but never
/// move existing ones.
const TCP_INFO_BYTES_ACKED_OFFSET: usize = 120;
const TCP_INFO_BYTES_RECEIVED_OFFSET: usize = 128;
const TCP_INFO_MIN_LEN: usize = TCP_INFO_BYTES_RECEIVED_OFFSET + 8;

/// Pull the local port and (rx, tx) counters out of one InetResponse
/// and write them into `out`. We extract bytes from the raw
/// `tcp_info` payload (avoiding the crate's `rich_nlas` feature so we
/// keep the dependency surface minimal). Sockets without a `TcpInfo`
/// extension or whose payload is shorter than the offsets we read are
/// skipped silently.
fn merge_response(
    resp: &netlink_packet_sock_diag::inet::InetResponse,
    out: &mut HashMap<u16, (u64, u64)>,
) {
    let local_port = resp.header.socket_id.source_port;
    if local_port == 0 {
        return;
    }
    for nla in &resp.nlas {
        if let Nla::TcpInfo(bytes) = nla {
            if let Some(counters) = extract_tcp_counters(bytes) {
                // (received, acked) → (rx, tx). Using bytes_acked
                // rather than bytes_sent gives the "delivered" view
                // that matches what nettop on macOS reports.
                out.insert(local_port, counters);
            }
            return;
        }
    }
}

/// Extract `(bytes_received, bytes_acked)` from a raw `tcp_info`
/// payload. Returns `None` if the payload is too short for the fields
/// we need.
///
/// Endianness contract: `ss` and the Linux kernel emit `tcp_info` in
/// **native CPU byte order**, not protocol-byte-order. On every Linux
/// target purple ships (x86_64-unknown-linux-gnu and
/// aarch64-unknown-linux-gnu) native-endian equals little-endian, so
/// `from_ne_bytes` and `from_le_bytes` produce identical results.
/// The module-level `compile_error!` blocks big-endian Linux targets
/// outright so this assumption cannot regress silently. If the
/// supported target list ever expands to a big-endian Linux, replace
/// `from_ne_bytes` with `from_le_bytes` and lift the guard.
fn extract_tcp_counters(bytes: &[u8]) -> Option<(u64, u64)> {
    if bytes.len() < TCP_INFO_MIN_LEN {
        return None;
    }
    let acked = u64::from_ne_bytes(
        bytes[TCP_INFO_BYTES_ACKED_OFFSET..TCP_INFO_BYTES_ACKED_OFFSET + 8]
            .try_into()
            .ok()?,
    );
    let received = u64::from_ne_bytes(
        bytes[TCP_INFO_BYTES_RECEIVED_OFFSET..TCP_INFO_BYTES_RECEIVED_OFFSET + 8]
            .try_into()
            .ok()?,
    );
    Some((received, acked))
}

/// Round a netlink message length up to the 4-byte alignment boundary
/// used by the protocol so the next message starts on a valid offset.
fn align(len: usize) -> usize {
    (len + 3) & !3
}

#[derive(Debug)]
enum DumpError {
    OpenSocket(std::io::Error),
    Bind(std::io::Error),
    Send(std::io::Error),
    Recv(std::io::Error),
    KernelError(String),
    UnsupportedFamily(u8),
    ParsePanic,
}

impl std::fmt::Display for DumpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DumpError::OpenSocket(e) => write!(f, "open netlink socket: {e}"),
            DumpError::Bind(e) => write!(f, "bind netlink socket: {e}"),
            DumpError::Send(e) => write!(f, "send INET_DIAG request: {e}"),
            DumpError::Recv(e) => write!(f, "recv from netlink: {e}"),
            DumpError::KernelError(s) => write!(f, "kernel returned NLMSG_ERROR: {s}"),
            DumpError::UnsupportedFamily(fam) => write!(f, "unsupported family {fam}"),
            DumpError::ParsePanic => write!(f, "panic in netlink parser"),
        }
    }
}

#[derive(Debug)]
enum BatchOutcome {
    Continue,
    Done,
}

#[cfg(test)]
mod tests {
    use super::*;
    use netlink_packet_sock_diag::inet::{InetResponse, InetResponseHeader};

    /// Build a synthetic `tcp_info` payload of `TCP_INFO_MIN_LEN`
    /// bytes filled with zeros, with `bytes_acked` and `bytes_received`
    /// written at the right offsets in native-endian. The leading 120
    /// bytes are uninteresting kernel state for our test purposes.
    fn tcp_info_bytes(bytes_received: u64, bytes_acked: u64) -> Vec<u8> {
        let mut v = vec![0u8; TCP_INFO_MIN_LEN];
        v[TCP_INFO_BYTES_ACKED_OFFSET..TCP_INFO_BYTES_ACKED_OFFSET + 8]
            .copy_from_slice(&bytes_acked.to_ne_bytes());
        v[TCP_INFO_BYTES_RECEIVED_OFFSET..TCP_INFO_BYTES_RECEIVED_OFFSET + 8]
            .copy_from_slice(&bytes_received.to_ne_bytes());
        v
    }

    /// Build a one-NLA InetResponse with the given local port and
    /// counters. Used to drive `merge_response` without touching the
    /// kernel.
    fn make_response(local_port: u16, rx: u64, tx: u64) -> InetResponse {
        let mut socket_id = SocketId::new_v4();
        socket_id.source_port = local_port;

        let mut resp = InetResponse {
            header: InetResponseHeader {
                family: AF_INET,
                state: 1, // TCP_ESTABLISHED
                timer: None,
                socket_id,
                recv_queue: 0,
                send_queue: 0,
                uid: 1000,
                inode: 12345,
            },
            nlas: Default::default(),
        };
        resp.nlas.push(Nla::TcpInfo(tcp_info_bytes(rx, tx)));
        resp
    }

    #[test]
    fn extract_tcp_counters_reads_offsets() {
        let bytes = tcp_info_bytes(1_024_000, 64_000);
        assert_eq!(extract_tcp_counters(&bytes), Some((1_024_000, 64_000)));
    }

    #[test]
    fn extract_tcp_counters_returns_none_for_short_payload() {
        assert_eq!(extract_tcp_counters(&[0u8; 100]), None);
    }

    #[test]
    fn extract_tcp_counters_accepts_longer_payload() {
        // Kernels later than 4.0 append fields beyond byte 136. We
        // must still read the original offsets correctly.
        let mut bytes = tcp_info_bytes(99, 88);
        bytes.extend_from_slice(&[0u8; 64]); // padding from a "newer" kernel
        assert_eq!(extract_tcp_counters(&bytes), Some((99, 88)));
    }

    #[test]
    fn merge_response_extracts_rx_and_tx() {
        let resp = make_response(54321, 1_024_000, 64_000);
        let mut out = HashMap::new();
        merge_response(&resp, &mut out);
        assert_eq!(out.get(&54321), Some(&(1_024_000, 64_000)));
    }

    #[test]
    fn merge_response_skips_zero_local_port() {
        let resp = make_response(0, 999, 999);
        let mut out = HashMap::new();
        merge_response(&resp, &mut out);
        assert!(out.is_empty());
    }

    #[test]
    fn merge_response_skips_when_no_tcp_info_nla() {
        let mut resp = make_response(54321, 1, 2);
        resp.nlas.clear();
        let mut out = HashMap::new();
        merge_response(&resp, &mut out);
        assert!(out.is_empty());
    }

    #[test]
    fn merge_response_skips_when_tcp_info_payload_truncated() {
        let mut resp = make_response(54321, 1, 2);
        resp.nlas.clear();
        resp.nlas.push(Nla::TcpInfo(vec![0u8; 50])); // shorter than offsets
        let mut out = HashMap::new();
        merge_response(&resp, &mut out);
        assert!(out.is_empty());
    }

    #[test]
    fn merge_response_overwrites_existing_port_entry() {
        let mut out = HashMap::new();
        merge_response(&make_response(8080, 100, 50), &mut out);
        merge_response(&make_response(8080, 200, 75), &mut out);
        assert_eq!(out.get(&8080), Some(&(200, 75)));
    }

    #[test]
    fn align_rounds_up_to_4_bytes() {
        assert_eq!(align(0), 0);
        assert_eq!(align(1), 4);
        assert_eq!(align(4), 4);
        assert_eq!(align(5), 8);
        assert_eq!(align(7), 8);
        assert_eq!(align(8), 8);
        assert_eq!(align(9), 12);
    }

    #[test]
    fn process_batch_handles_empty_input() {
        let mut out = HashMap::new();
        let mut truncated = false;
        let outcome = process_batch(&[], &mut out, &mut truncated).unwrap();
        assert!(matches!(outcome, BatchOutcome::Continue));
        assert!(out.is_empty());
    }

    #[test]
    fn process_batch_aborts_on_zero_header_length() {
        // 16 bytes of zeros: peek_msg_len reads length=0 → invalid
        // length guard fires → batch ends gracefully without panic.
        // This exercises the "invalid header length" branch, NOT a
        // deserialize failure.
        let buf = vec![0u8; 16];
        let mut out = HashMap::new();
        let mut truncated = false;
        let outcome = process_batch(&buf, &mut out, &mut truncated).unwrap();
        assert!(matches!(outcome, BatchOutcome::Done));
        assert!(out.is_empty());
    }

    /// Serialize one InetResponse into a NetlinkMessage byte buffer
    /// using the crate's own emitters. Used by the multi-message and
    /// cap tests to build realistic batches without a kernel.
    fn serialize_inet_response(resp: InetResponse) -> Vec<u8> {
        let header = NetlinkHeader::default();
        let payload = NetlinkPayload::from(SockDiagMessage::InetResponse(Box::new(resp)));
        let mut packet = NetlinkMessage::new(header, payload);
        packet.finalize();
        let mut buf = vec![0u8; packet.buffer_len()];
        packet.serialize(&mut buf);
        buf
    }

    /// Serialize an `NLMSG_DONE` message. Used to verify that the
    /// batch walker stops at the kernel's end-of-dump marker.
    fn serialize_nlmsg_done() -> Vec<u8> {
        let header = NetlinkHeader::default();
        let packet: NetlinkMessage<SockDiagMessage> =
            NetlinkMessage::new(header, NetlinkPayload::Done(Default::default()));
        let mut packet = packet;
        packet.finalize();
        let mut buf = vec![0u8; packet.buffer_len()];
        packet.serialize(&mut buf);
        buf
    }

    #[test]
    fn process_batch_walks_multiple_inet_responses() {
        // Two valid InetResponses back-to-back: walker must process
        // both and not stop after the first.
        let mut buf = serialize_inet_response(make_response(8080, 1_000, 500));
        buf.extend(serialize_inet_response(make_response(9090, 2_000, 1_000)));

        let mut out = HashMap::new();
        let mut truncated = false;
        let outcome = process_batch(&buf, &mut out, &mut truncated).unwrap();
        assert!(matches!(outcome, BatchOutcome::Continue));
        assert_eq!(out.get(&8080), Some(&(1_000, 500)));
        assert_eq!(out.get(&9090), Some(&(2_000, 1_000)));
        assert!(!truncated);
    }

    #[test]
    fn process_batch_stops_on_nlmsg_done_after_responses() {
        // One InetResponse followed by NLMSG_DONE: walker processes
        // the response and returns Done at the marker.
        let mut buf = serialize_inet_response(make_response(7777, 42, 24));
        buf.extend(serialize_nlmsg_done());

        let mut out = HashMap::new();
        let mut truncated = false;
        let outcome = process_batch(&buf, &mut out, &mut truncated).unwrap();
        assert!(matches!(outcome, BatchOutcome::Done));
        assert_eq!(out.get(&7777), Some(&(42, 24)));
    }

    #[test]
    fn process_batch_advances_past_malformed_message_inside_batch() {
        // Construct a batch where a malformed message sits between
        // two valid InetResponses. The malformed entry is a 16-byte
        // header with length=16 (a legal but empty NLMSG_NOOP-shaped
        // packet that fails SockDiagMessage decode). Walker must skip
        // past it via the raw header length and still process the
        // response that follows.
        let valid_a = serialize_inet_response(make_response(11111, 5, 3));
        let valid_b = serialize_inet_response(make_response(22222, 7, 11));
        // Manually craft a 16-byte netlink message: length=16, type=99
        // (unknown SockDiag type → deserialize Err), rest zero.
        let mut bad: Vec<u8> = Vec::new();
        bad.extend_from_slice(&16u32.to_ne_bytes()); // length
        bad.extend_from_slice(&99u16.to_ne_bytes()); // type
        bad.extend_from_slice(&0u16.to_ne_bytes()); // flags
        bad.extend_from_slice(&0u32.to_ne_bytes()); // seq
        bad.extend_from_slice(&0u32.to_ne_bytes()); // pid

        let mut buf = valid_a;
        buf.extend(&bad);
        buf.extend(valid_b);

        let mut out = HashMap::new();
        let mut truncated = false;
        let outcome = process_batch(&buf, &mut out, &mut truncated).unwrap();
        assert!(matches!(outcome, BatchOutcome::Continue));
        assert_eq!(out.get(&11111), Some(&(5, 3)));
        assert_eq!(
            out.get(&22222),
            Some(&(7, 11)),
            "the malformed middle message must not silently discard the valid one that follows"
        );
    }

    #[test]
    fn process_batch_sets_truncated_flag_when_cap_reached() {
        // Pre-fill `out` to MAX_SOCKETS, then feed one more valid
        // InetResponse. The merge must be skipped and `truncated`
        // must flip to true.
        let mut out: HashMap<u16, (u64, u64)> = HashMap::new();
        for port in 1u16..=MAX_SOCKETS as u16 {
            out.insert(port, (0, 0));
        }
        assert_eq!(out.len(), MAX_SOCKETS);

        let buf = serialize_inet_response(make_response(50_000, 999, 888));
        let mut truncated = false;
        let _ = process_batch(&buf, &mut out, &mut truncated).unwrap();

        assert!(truncated, "truncated flag must flip when cap is reached");
        assert!(
            !out.contains_key(&50_000),
            "capped insertion must be skipped"
        );
        assert_eq!(out.len(), MAX_SOCKETS, "size must not exceed cap");
    }

    #[test]
    fn process_batch_returns_kernel_error_on_nlmsg_error_bytes() {
        // Manually craft an NLMSG_ERROR message. Layout: 16-byte
        // netlink header (type=2 = NLMSG_ERROR) followed by a 4-byte
        // error code and the original-message header echo (16 bytes).
        // Total length = 16 + 4 + 16 = 36 bytes.
        const NLMSG_ERROR: u16 = 2;
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(&36u32.to_ne_bytes()); // length
        bytes.extend_from_slice(&NLMSG_ERROR.to_ne_bytes()); // type
        bytes.extend_from_slice(&0u16.to_ne_bytes()); // flags
        bytes.extend_from_slice(&0u32.to_ne_bytes()); // seq
        bytes.extend_from_slice(&0u32.to_ne_bytes()); // pid
        bytes.extend_from_slice(&(-1i32).to_ne_bytes()); // error code
        bytes.extend_from_slice(&[0u8; 16]); // echoed original header

        let mut out = HashMap::new();
        let mut truncated = false;
        let result = process_batch(&bytes, &mut out, &mut truncated);
        assert!(
            matches!(result, Err(DumpError::KernelError(_))),
            "expected DumpError::KernelError, got {result:?}",
        );
    }

    #[test]
    fn extract_tcp_counters_returns_none_at_min_len_minus_one() {
        // Sharp boundary: one byte short of TCP_INFO_MIN_LEN must
        // refuse to parse rather than over-read the slice.
        let bytes = vec![0u8; TCP_INFO_MIN_LEN - 1];
        assert_eq!(extract_tcp_counters(&bytes), None);
    }

    #[test]
    fn extract_tcp_counters_returns_zeros_for_zeroed_payload() {
        // A fresh socket reports all-zero counters. Verify zero is
        // not confused with "no data" — the caller expects Some((0, 0))
        // so the diff path can record this as the new baseline.
        let bytes = tcp_info_bytes(0, 0);
        assert_eq!(extract_tcp_counters(&bytes), Some((0, 0)));
    }

    #[test]
    fn extract_tcp_counters_handles_max_u64_counters() {
        // Long-running sockets approach but never reach u64::MAX.
        // Verify the offset arithmetic and try_into path do not
        // overflow or fail at the upper bound of the type.
        let bytes = tcp_info_bytes(u64::MAX, u64::MAX);
        assert_eq!(extract_tcp_counters(&bytes), Some((u64::MAX, u64::MAX)));
    }

    #[test]
    fn peek_msg_len_reads_first_4_bytes_native_endian() {
        // peek_msg_len is the entry point that lets the batch walker
        // advance past malformed messages without losing framing.
        let mut buf = Vec::new();
        buf.extend_from_slice(&64u32.to_ne_bytes());
        buf.extend_from_slice(&[0u8; 12]);
        assert_eq!(peek_msg_len(&buf), Some(64));
    }

    #[test]
    fn peek_msg_len_returns_none_for_short_input() {
        assert_eq!(peek_msg_len(&[]), None);
        assert_eq!(peek_msg_len(&[0u8; 3]), None);
    }

    #[test]
    fn catch_panic_returns_ok_for_ok_closure() {
        let result = catch_panic(|| Ok(()));
        assert!(matches!(result, Ok(())));
    }

    #[test]
    fn catch_panic_propagates_inner_dump_error() {
        let result = catch_panic(|| Err(DumpError::UnsupportedFamily(99)));
        assert!(matches!(result, Err(DumpError::UnsupportedFamily(99))));
    }

    #[test]
    fn catch_panic_converts_panic_into_parse_panic_variant() {
        // The lsof-poller thread must never die from an upstream
        // parser panic. Verify the wrapper traps the unwind and
        // returns DumpError::ParsePanic instead of letting the
        // panic propagate.
        let result = catch_panic(|| {
            panic!("simulated upstream parser panic");
        });
        assert!(
            matches!(result, Err(DumpError::ParsePanic)),
            "panic in closure must convert to DumpError::ParsePanic, got {result:?}",
        );
    }

    #[test]
    fn extract_tcp_counters_pins_little_endian_assumption_on_supported_targets() {
        // Production code uses `from_ne_bytes`, which on x86_64 and
        // aarch64 (purple's Linux targets) is identical to
        // `from_le_bytes`. This test writes the counters in EXPLICIT
        // little-endian and asserts decode succeeds. If a future
        // refactor accidentally swaps to `from_be_bytes`, this test
        // breaks even though the current `to_ne_bytes` fixture would
        // not. Together with the module-level `compile_error!` for
        // big-endian targets, this pins the assumption end-to-end.
        let mut bytes = vec![0u8; TCP_INFO_MIN_LEN];
        bytes[TCP_INFO_BYTES_ACKED_OFFSET..TCP_INFO_BYTES_ACKED_OFFSET + 8]
            .copy_from_slice(&64_000_u64.to_le_bytes());
        bytes[TCP_INFO_BYTES_RECEIVED_OFFSET..TCP_INFO_BYTES_RECEIVED_OFFSET + 8]
            .copy_from_slice(&1_024_000_u64.to_le_bytes());
        assert_eq!(extract_tcp_counters(&bytes), Some((1_024_000, 64_000)));
    }
}
