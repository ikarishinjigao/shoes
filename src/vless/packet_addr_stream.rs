//! VLESS PacketAddr support for multi-destination UDP over a single VLESS stream.
//!
//! Mihomo calls this mode `packet-encoding: packet`. Each VLESS UDP message starts
//! with a v2fly PacketAddr address (IPv4 or IPv6) followed by the UDP payload.

use std::io::{Error, ErrorKind, Result};
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::ReadBuf;

use crate::address::{Address, NetLocation};
use crate::async_stream::{
    AsyncFlushMessage, AsyncMessageStream, AsyncPing, AsyncReadTargetedMessage,
    AsyncShutdownMessage, AsyncTargetedMessageStream, AsyncWriteSourcedMessage,
};
use crate::util::allocate_vec;

pub const PACKET_ADDR_MAGIC_HOST: &str = "sp.packet-addr.v2fly.arpa";

const IPV4_FAMILY: u8 = 1;
const IPV6_FAMILY: u8 = 2;
const MAX_MESSAGE_SIZE: usize = u16::MAX as usize;

pub fn is_packet_addr_location(location: &NetLocation) -> bool {
    location
        .address()
        .hostname()
        .is_some_and(|host| host.eq_ignore_ascii_case(PACKET_ADDR_MAGIC_HOST))
}

fn parse_packet_addr_message(message: &[u8]) -> Result<(NetLocation, &[u8])> {
    let (address, port_offset) = match message.first().copied() {
        Some(IPV4_FAMILY) => {
            if message.len() < 7 {
                return Err(Error::new(
                    ErrorKind::UnexpectedEof,
                    "truncated IPv4 PacketAddr message",
                ));
            }
            let octets: [u8; 4] = message[1..5].try_into().unwrap();
            (Address::Ipv4(octets.into()), 5)
        }
        Some(IPV6_FAMILY) => {
            if message.len() < 19 {
                return Err(Error::new(
                    ErrorKind::UnexpectedEof,
                    "truncated IPv6 PacketAddr message",
                ));
            }
            let octets: [u8; 16] = message[1..17].try_into().unwrap();
            (Address::Ipv6(octets.into()), 17)
        }
        Some(family) => {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("unsupported PacketAddr address family: {family}"),
            ));
        }
        None => {
            return Err(Error::new(
                ErrorKind::UnexpectedEof,
                "empty PacketAddr message",
            ));
        }
    };

    let port = u16::from_be_bytes([message[port_offset], message[port_offset + 1]]);
    Ok((NetLocation::new(address, port), &message[port_offset + 2..]))
}

fn write_packet_addr_header(output: &mut Vec<u8>, source: &SocketAddr) {
    match source.ip() {
        IpAddr::V4(address) => {
            output.push(IPV4_FAMILY);
            output.extend_from_slice(&address.octets());
        }
        IpAddr::V6(address) => {
            output.push(IPV6_FAMILY);
            output.extend_from_slice(&address.octets());
        }
    }
    output.extend_from_slice(&source.port().to_be_bytes());
}

pub struct VlessPacketAddrStream<S> {
    stream: S,
    read_buffer: Box<[u8]>,
    write_buffer: Vec<u8>,
}

impl<S: AsyncMessageStream> VlessPacketAddrStream<S> {
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            read_buffer: allocate_vec(MAX_MESSAGE_SIZE).into_boxed_slice(),
            write_buffer: Vec::with_capacity(MAX_MESSAGE_SIZE),
        }
    }
}

impl<S: AsyncMessageStream> AsyncReadTargetedMessage for VlessPacketAddrStream<S> {
    fn poll_read_targeted_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<Result<NetLocation>> {
        let this = self.get_mut();
        let mut message = ReadBuf::new(&mut this.read_buffer);
        match Pin::new(&mut this.stream).poll_read_message(cx, &mut message) {
            Poll::Ready(Ok(())) => {
                if message.filled().is_empty() {
                    return Poll::Ready(Ok(NetLocation::UNSPECIFIED));
                }

                let (destination, payload) = parse_packet_addr_message(message.filled())?;
                if output.remaining() < payload.len() {
                    return Poll::Ready(Err(Error::new(
                        ErrorKind::InvalidInput,
                        "output buffer is too small for PacketAddr payload",
                    )));
                }
                output.put_slice(payload);
                Poll::Ready(Ok(destination))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S: AsyncMessageStream> AsyncWriteSourcedMessage for VlessPacketAddrStream<S> {
    fn poll_write_sourced_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        payload: &[u8],
        source: &SocketAddr,
    ) -> Poll<Result<()>> {
        let this = self.get_mut();
        let header_len = if source.is_ipv4() { 7 } else { 19 };
        if payload.len() > MAX_MESSAGE_SIZE - header_len {
            return Poll::Ready(Err(Error::new(
                ErrorKind::InvalidInput,
                "PacketAddr message is too large",
            )));
        }

        this.write_buffer.clear();
        write_packet_addr_header(&mut this.write_buffer, source);
        this.write_buffer.extend_from_slice(payload);
        Pin::new(&mut this.stream).poll_write_message(cx, &this.write_buffer)
    }
}

impl<S: AsyncMessageStream> AsyncFlushMessage for VlessPacketAddrStream<S> {
    fn poll_flush_message(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush_message(cx)
    }
}

impl<S: AsyncMessageStream> AsyncShutdownMessage for VlessPacketAddrStream<S> {
    fn poll_shutdown_message(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown_message(cx)
    }
}

impl<S: AsyncMessageStream> AsyncPing for VlessPacketAddrStream<S> {
    fn supports_ping(&self) -> bool {
        self.stream.supports_ping()
    }

    fn poll_write_ping(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<bool>> {
        Pin::new(&mut self.get_mut().stream).poll_write_ping(cx)
    }
}

impl<S: AsyncMessageStream> AsyncTargetedMessageStream for VlessPacketAddrStream<S> {}

#[cfg(test)]
mod tests {
    use std::future::poll_fn;
    use std::net::{Ipv4Addr, Ipv6Addr};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    use super::*;
    use crate::vless::VlessMessageStream;

    async fn tcp_pair() -> std::io::Result<(TcpStream, TcpStream)> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let accept = listener.accept();
        let connect = TcpStream::connect(address);
        let ((server, _), client) = tokio::try_join!(accept, connect)?;
        Ok((client, server))
    }

    #[test]
    fn identifies_magic_location_case_insensitively() {
        assert!(is_packet_addr_location(&NetLocation::new(
            Address::Hostname("SP.PACKET-ADDR.V2FLY.ARPA".to_string()),
            443,
        )));
        assert!(!is_packet_addr_location(&NetLocation::new(
            Address::Hostname("example.com".to_string()),
            443,
        )));
    }

    #[test]
    fn rejects_invalid_and_truncated_messages() {
        for message in [&[][..], &[IPV4_FAMILY][..], &[IPV6_FAMILY; 18][..]] {
            assert_eq!(
                parse_packet_addr_message(message).unwrap_err().kind(),
                ErrorKind::UnexpectedEof
            );
        }
        assert_eq!(
            parse_packet_addr_message(&[3, 0, 0]).unwrap_err().kind(),
            ErrorKind::InvalidData
        );
    }

    #[tokio::test]
    async fn reads_ipv4_and_writes_ipv6_vless_messages() {
        let (client, mut peer) = tcp_pair().await.unwrap();
        let mut stream = VlessPacketAddrStream::new(VlessMessageStream::new(client));

        let destination = SocketAddr::from((Ipv4Addr::new(203, 0, 113, 7), 5353));
        let inbound_payload = b"request";
        let mut inbound = Vec::new();
        write_packet_addr_header(&mut inbound, &destination);
        inbound.extend_from_slice(inbound_payload);
        peer.write_all(&(inbound.len() as u16).to_be_bytes())
            .await
            .unwrap();
        peer.write_all(&inbound).await.unwrap();

        let mut output_bytes = [0u8; 64];
        let mut output = ReadBuf::new(&mut output_bytes);
        let parsed_destination =
            poll_fn(|cx| Pin::new(&mut stream).poll_read_targeted_message(cx, &mut output))
                .await
                .unwrap();
        assert_eq!(
            parsed_destination.to_socket_addr_nonblocking(),
            Some(destination)
        );
        assert_eq!(output.filled(), inbound_payload);

        let source = SocketAddr::from((Ipv6Addr::LOCALHOST, 443));
        let response_payload = b"response";
        poll_fn(|cx| {
            Pin::new(&mut stream).poll_write_sourced_message(cx, response_payload, &source)
        })
        .await
        .unwrap();
        poll_fn(|cx| Pin::new(&mut stream).poll_flush_message(cx))
            .await
            .unwrap();

        let response_len = peer.read_u16().await.unwrap() as usize;
        let mut response = vec![0u8; response_len];
        peer.read_exact(&mut response).await.unwrap();
        let (parsed_source, parsed_payload) = parse_packet_addr_message(&response).unwrap();
        assert_eq!(parsed_source.to_socket_addr_nonblocking(), Some(source));
        assert_eq!(parsed_payload, response_payload);
    }
}
