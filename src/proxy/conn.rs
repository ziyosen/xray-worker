use crate::config::Config;

use std::pin::Pin;
use std::task::{Context, Poll};
use bytes::{BufMut, BytesMut};
use futures_util::Stream;
use pin_project_lite::pin_project;
use pretty_bytes::converter::convert;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use worker::*;

static MAX_WEBSOCKET_SIZE: usize = 64 * 1024; // 64kb
static MAX_BUFFER_SIZE: usize = 512 * 1024; // 512kb

pin_project! {
    pub struct ProxyStream<'a> {
        pub config: Config,
        pub ws: &'a WebSocket,
        pub buffer: BytesMut,
        #[pin]
        pub events: EventStream<'a>,
    }
}

impl<'a> ProxyStream<'a> {
    pub fn new(config: Config, ws: &'a WebSocket, events: EventStream<'a>) -> Self {
        let buffer = BytesMut::with_capacity(MAX_BUFFER_SIZE);

        Self {
            config,
            ws,
            buffer,
            events,
        }
    }
    
    pub async fn fill_buffer_until(&mut self, n: usize) -> std::io::Result<()> {
        use futures_util::StreamExt;

        while self.buffer.len() < n {
            match self.events.next().await {
                Some(Ok(WebsocketEvent::Message(msg))) => {
                    if let Some(data) = msg.bytes() {
                        self.buffer.put_slice(&data);
                    }
                }
                Some(Ok(WebsocketEvent::Close(_))) => {
                    break;
                }
                Some(Err(e)) => {
                    return Err(std::io::Error::new(std::io::ErrorKind::Other, e.to_string()));
                }
                None => {
                    break;
                }
            }
        }
        Ok(())
    }

    pub fn peek_buffer(&self, n: usize) -> &[u8] {
        let len = self.buffer.len().min(n);
        &self.buffer[..len]
    }

    pub async fn process(&mut self) -> Result<()> {
        let peek_buffer_len = 62;
        self.fill_buffer_until(peek_buffer_len).await?;
        let peeked_buffer = self.peek_buffer(peek_buffer_len);

        // Guard ketat: semua sniffer mengindeks sampai byte 57 — kalau kurang, tolak rapi
        // (bukan panic → mencegah 1101).
        if peeked_buffer.len() < 58 {
            return Err(Error::RustError("not enough buffer".to_string()));
        }

        if self.is_vless(peeked_buffer) {
            console_log!("vless detected!");
            self.process_vless().await
        } else if self.is_shadowsocks(peeked_buffer) {
            console_log!("shadowsocks detected!");
            self.process_shadowsocks().await
        } else if self.is_trojan(peeked_buffer) {
            console_log!("trojan detected!");
            self.process_trojan().await
        } else if self.is_vmess(peeked_buffer) {
            console_log!("vmess detected!");
            self.process_vmess().await
        } else {
            Err(Error::RustError("protocol not implemented".to_string()))
        }
    }

    pub fn is_vless(&self, buffer: &[u8]) -> bool {
        buffer[0] == 0
    }

    fn is_shadowsocks(&self, buffer: &[u8]) -> bool {
        match buffer[0] {
            1 => { // IPv4
                if buffer.len() < 7 {
                    return false;
                }
                let remote_port = u16::from_be_bytes([buffer[5], buffer[6]]);
                remote_port != 0
            }
            3 => { // Domain name
                if buffer.len() < 2 {
                    return false;
                }
                let domain_len = buffer[1] as usize;
                if buffer.len() < 2 + domain_len + 2 {
                    return false;
                }
                let remote_port = u16::from_be_bytes([
                    buffer[2 + domain_len],
                    buffer[2 + domain_len + 1],
                ]);
                remote_port != 0
            }
            4 => { // IPv6
                if buffer.len() < 19 {
                    return false;
                }
                let remote_port = u16::from_be_bytes([buffer[17], buffer[18]]);
                remote_port != 0
            }
            _ => false,
        }
    }

    fn is_trojan(&self, buffer: &[u8]) -> bool {
        buffer.len() > 57 && buffer[56] == 13 && buffer[57] == 10
    }

    // vmess TIDAK bisa di-sniff dari byte pertama dengan andal —
    // fallback "selalu true" bikin garbage masuk parser vmess dan panic (sumber 1101).
    // Sniffer hanya terima vless/trojan/ss; selain itu ditolak rapi.
    fn is_vmess(&self, _buffer: &[u8]) -> bool {
        false
    }

    pub async fn handle_tcp_outbound(&mut self, addr: String, port: u16) -> Result<()> {
        let mut remote_socket = Socket::builder().connect(&addr, port).map_err(|e| {
            Error::RustError(e.to_string())
        })?;

        remote_socket.opened().await.map_err(|e| {
            Error::RustError(e.to_string())
        })?;

        tokio::io::copy_bidirectional(self, &mut remote_socket)
            .await
            .map(|(a_to_b, b_to_a)| {
                console_log!("copied data from {}:{}, up: {} and dl: {}", &addr, &port, convert(a_to_b as f64), convert(b_to_a as f64));
            })
            .map_err(|e| {
                Error::RustError(e.to_string())
            })?;
        Ok(())
    }

    pub async fn handle_udp_outbound(&mut self) -> Result<()> {
        let mut buff = vec![0u8; 65535];

        let n = self.read(&mut buff).await?;
        let data = &buff[..n];
        if crate::dns::doh(data).await.is_ok() {
            self.write(&data).await?;
        };
        Ok(())
    }
}

impl<'a> AsyncRead for ProxyStream<'a> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<tokio::io::Result<()>> {
        let mut this = self.project();

        loop {
            let size = std::cmp::min(this.buffer.len(), buf.remaining());
            if size > 0 {
                buf.put_slice(&this.buffer.split_to(size));
                return Poll::Ready(Ok(()));
            }

            match this.events.as_mut().poll_next(cx) {
                Poll::Ready(Some(Ok(WebsocketEvent::Message(msg)))) => {
                    if let Some(data) = msg.bytes() {
                        if data.len() > MAX_WEBSOCKET_SIZE {
                            return Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::Other, "websocket buffer too long")))
                        }
                        
                        if this.buffer.len() + data.len() > MAX_BUFFER_SIZE {
                            console_log!("buffer full, applying backpressure");
                            return Poll::Pending;
                        }
                        
                        this.buffer.put_slice(&data);
                    }
                }
                Poll::Pending => return Poll::Pending,
                _ => return Poll::Ready(Ok(())),
            }
        }
    }
}

impl<'a> AsyncWrite for ProxyStream<'a> {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<tokio::io::Result<usize>> {
        return Poll::Ready(
            self.ws
                .send_with_bytes(buf)
                .map(|_| buf.len())
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string())),
        );
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<tokio::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<tokio::io::Result<()>> {
        match self.ws.close(Some(1000), Some("shutdown".to_string())) {
            Ok(_) => Poll::Ready(Ok(())),
            Err(e) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            ))),
        }
    }
}
