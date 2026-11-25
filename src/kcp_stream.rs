use hbb_common::{
    anyhow,
    bytes::{Bytes, BytesMut},
    bytes_codec::BytesCodec,
    config, log,
    tcp::{DynTcpStream, FramedStream},
    tokio::{self, net::UdpSocket, sync::mpsc, sync::oneshot},
    tokio_util, ResultType, Stream,
};
use kcp_sys::{
    endpoint::KcpEndpoint,
    packet_def::{KcpPacket, KcpPacketHeader},
    stream,
};
use std::{net::SocketAddr, sync::Arc};

pub struct KcpStream {
    _endpoint: KcpEndpoint,
    stop_sender: Option<oneshot::Sender<()>>,
}

impl KcpStream {
    fn create_framed(stream: stream::KcpStream, local_addr: Option<SocketAddr>) -> Stream {
        Stream::Tcp(FramedStream(
            tokio_util::codec::Framed::new(DynTcpStream(Box::new(stream)), BytesCodec::new()),
            local_addr.unwrap_or(config::Config::get_any_listen_addr(true)),
            None,
            0,
        ))
    }

    pub async fn accept(
        udp_socket: Arc<UdpSocket>,
        timeout: std::time::Duration,
        init_packet: Option<BytesMut>,
    ) -> ResultType<(Self, Stream)> {
        let mut endpoint = KcpEndpoint::new();
        endpoint.run().await;

        let (input, output) = (
            endpoint.input_sender(),
            endpoint
                .output_receiver()
                .ok_or_else(|| anyhow::anyhow!("Failed to get output receiver"))?,
        );
        let (stop_sender, stop_receiver) = oneshot::channel();
        if let Some(packet) = init_packet {
            if packet.len() >= std::mem::size_of::<KcpPacketHeader>() {
                input.send(packet.into()).await?;
            }
        }
        Self::kcp_io(udp_socket.clone(), input, output, stop_receiver).await;

        let conn_id = tokio::time::timeout(timeout, endpoint.accept()).await??;
        if let Some(stream) = stream::KcpStream::new(&endpoint, conn_id) {
            Ok((
                Self {
                    _endpoint: endpoint,
                    stop_sender: Some(stop_sender),
                },
                Self::create_framed(stream, udp_socket.local_addr().ok()),
            ))
        } else {
            Err(anyhow::anyhow!("Failed to create KcpStream"))
        }
    }

    pub async fn connect(
        udp_socket: Arc<UdpSocket>,
        timeout: std::time::Duration,
    ) -> ResultType<(Self, Stream)> {
        let mut endpoint = KcpEndpoint::new();
        endpoint.run().await;

        let (input, output) = (
            endpoint.input_sender(),
            endpoint
                .output_receiver()
                .ok_or_else(|| anyhow::anyhow!("Failed to get output receiver"))?,
        );
        let (stop_sender, stop_receiver) = oneshot::channel();
        Self::kcp_io(udp_socket.clone(), input, output, stop_receiver).await;

        let conn_id = endpoint.connect(timeout, 0, 0, Bytes::new()).await?;
        if let Some(stream) = stream::KcpStream::new(&endpoint, conn_id) {
            Ok((
                Self {
                    _endpoint: endpoint,
                    stop_sender: Some(stop_sender),
                },
                Self::create_framed(stream, udp_socket.local_addr().ok()),
            ))
        } else {
            Err(anyhow::anyhow!("Failed to create KcpStream"))
        }
    }

    async fn kcp_io(
        udp_socket: Arc<UdpSocket>,
        input: mpsc::Sender<KcpPacket>,
        mut output: mpsc::Receiver<KcpPacket>,
        mut stop_receiver: oneshot::Receiver<()>,
    ) {
        let udp = udp_socket.clone();
        tokio::spawn(async move {
            let mut buf = vec![0; 1500];
            loop {
                tokio::select! {
                    _ = &mut stop_receiver => {
                        log::debug!("KCP io loop received stop signal");
                        break;
                    }
                    Some(data) = output.recv() => {
                        if let Err(e) = udp.send(&data.inner()).await {
                            log::debug!("KCP send error: {:?}", e);
                            break;
                        }
                    }
                    result = udp.recv_from(&mut buf) => {
                        match result {
                            Ok((size, _)) => {
                                if size < std::mem::size_of::<KcpPacketHeader>() {
                                    continue;
                                }
                                input
                                    .send(BytesMut::from(&buf[..size]).into())
                                    .await.ok();
                            }
                            Err(e) => {
                                log::debug!("KCP recv_from error: {:?}", e);
                                break;
                            }
                        }
                    }
                    else => {
                        log::debug!("KCP endpoint input closed");
                        break;
                    }
                }
            }
        });
    }
}

// ── fleet direct paths (fgtw_direct.rs) ──
//
// The host keeps ONE fleet UDP socket for every peer — it is the port the router maps and the fleet publishes — so it cannot be `connect`ed to a peer, and its reader is a demux that hands each peer's datagrams to that peer's KCP session. The guest dials from a socket of its own and reads it here directly, dropping anyone else and any late signed probe.
#[cfg(feature = "fgtw")]
impl KcpStream {
    /// Host side: a KCP session with `peer` over the shared fleet socket. `rx` carries this peer's datagrams from the socket's demux, the first SYN included; replies leave with `send_to(peer)`.
    pub async fn accept_via(
        udp_socket: Arc<UdpSocket>,
        peer: SocketAddr,
        mut rx: mpsc::Receiver<BytesMut>,
        timeout: std::time::Duration,
    ) -> ResultType<(Self, Stream)> {
        let mut endpoint = KcpEndpoint::new();
        endpoint.run().await;
        let input = endpoint.input_sender();
        let mut output = endpoint
            .output_receiver()
            .ok_or_else(|| anyhow::anyhow!("Failed to get output receiver"))?;
        let (stop_sender, mut stop_receiver) = oneshot::channel::<()>();
        let udp = udp_socket.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut stop_receiver => break,
                    Some(data) = output.recv() => {
                        if udp.send_to(&data.inner(), peer).await.is_err() {
                            break;
                        }
                    }
                    Some(packet) = rx.recv() => {
                        if packet.len() >= std::mem::size_of::<KcpPacketHeader>() {
                            input.send(packet.into()).await.ok();
                        }
                    }
                    else => break,
                }
            }
        });
        let conn_id = tokio::time::timeout(timeout, endpoint.accept()).await??;
        let stream = stream::KcpStream::new(&endpoint, conn_id)
            .ok_or_else(|| anyhow::anyhow!("Failed to create KcpStream"))?;
        Ok((
            Self {
                _endpoint: endpoint,
                stop_sender: Some(stop_sender),
            },
            Self::create_framed(stream, udp_socket.local_addr().ok()),
        ))
    }

    /// Guest side: a KCP session to `peer` over a socket this stream now reads alone. A datagram from any other source is dropped, and so is a signed probe that arrives after the path was chosen (a VSF file, never a KCP packet).
    pub async fn connect_to(
        udp_socket: Arc<UdpSocket>,
        peer: SocketAddr,
        timeout: std::time::Duration,
    ) -> ResultType<(Self, Stream)> {
        let mut endpoint = KcpEndpoint::new();
        endpoint.run().await;
        let input = endpoint.input_sender();
        let mut output = endpoint
            .output_receiver()
            .ok_or_else(|| anyhow::anyhow!("Failed to get output receiver"))?;
        let (stop_sender, mut stop_receiver) = oneshot::channel::<()>();
        let udp = udp_socket.clone();
        tokio::spawn(async move {
            let mut buf = vec![0; 1500];
            loop {
                tokio::select! {
                    _ = &mut stop_receiver => break,
                    Some(data) = output.recv() => {
                        if udp.send_to(&data.inner(), peer).await.is_err() {
                            break;
                        }
                    }
                    result = udp.recv_from(&mut buf) => {
                        let Ok((size, from)) = result else { break };
                        if from != peer
                            || size < std::mem::size_of::<KcpPacketHeader>()
                            || crate::fgtw_direct::is_signed_datagram(&buf[..size])
                        {
                            continue;
                        }
                        input.send(BytesMut::from(&buf[..size]).into()).await.ok();
                    }
                    else => break,
                }
            }
        });
        let conn_id = endpoint.connect(timeout, 0, 0, Bytes::new()).await?;
        let stream = stream::KcpStream::new(&endpoint, conn_id)
            .ok_or_else(|| anyhow::anyhow!("Failed to create KcpStream"))?;
        Ok((
            Self {
                _endpoint: endpoint,
                stop_sender: Some(stop_sender),
            },
            Self::create_framed(stream, udp_socket.local_addr().ok()),
        ))
    }
}

impl Drop for KcpStream {
    fn drop(&mut self) {
        if let Some(sender) = self.stop_sender.take() {
            let _ = sender.send(());
        }
    }
}

#[cfg(all(test, feature = "fgtw"))]
mod fleet_tests {
    use super::*;

    /// The fleet shims end to end on loopback: the host's shared socket feeds one peer's KCP session through a demux channel, the guest reads its own socket, and framed bytes cross both ways.
    #[tokio::test]
    async fn kcp_over_a_shared_host_socket_carries_bytes_both_ways() {
        let host = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let guest = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (host_addr, guest_addr) = (host.local_addr().unwrap(), guest.local_addr().unwrap());

        // The hub's demux, reduced to one peer: every datagram from the guest goes to its session.
        let (tx, rx) = mpsc::channel::<BytesMut>(1 << 8);
        let demux = host.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 1 << 11];
            while let Ok((n, from)) = demux.recv_from(&mut buf).await {
                if from == guest_addr {
                    let _ = tx.send(BytesMut::from(&buf[..n])).await;
                }
            }
        });

        let timeout = std::time::Duration::from_secs(5);
        let accept = tokio::spawn(KcpStream::accept_via(host.clone(), guest_addr, rx, timeout));
        let (_g, mut g) = KcpStream::connect_to(guest.clone(), host_addr, timeout).await.expect("guest connects");
        let (_h, mut h) = accept.await.unwrap().expect("host accepts");

        g.send_bytes(Bytes::from_static(b"signed id, please")).await.unwrap();
        let got = tokio::time::timeout(timeout, h.next()).await.unwrap().unwrap().unwrap();
        assert_eq!(&got[..], b"signed id, please");
        let big = vec![7u8; 1 << 16];
        h.send_bytes(Bytes::from(big.clone())).await.unwrap();
        let got = tokio::time::timeout(timeout, g.next()).await.unwrap().unwrap().unwrap();
        assert_eq!(got.len(), big.len(), "a frame larger than one datagram reassembles");
    }
}
