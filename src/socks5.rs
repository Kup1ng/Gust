//! A minimal SOCKS5 *client* used for `-F` chaining (TCP only).
//!
//! Implements method negotiation, RFC 1929 username/password auth, and the
//! CONNECT command over any byte stream. This is the only SOCKS5 surface we
//! need: Gust never acts as a SOCKS5 server.

use std::io::{self, ErrorKind};
use std::net::{Ipv4Addr, Ipv6Addr};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const VER: u8 = 0x05;
const METHOD_NO_AUTH: u8 = 0x00;
const METHOD_USER_PASS: u8 = 0x02;
const METHOD_NONE: u8 = 0xFF;
const CMD_CONNECT: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;
const AUTH_VER: u8 = 0x01;

/// Negotiate auth and issue a CONNECT to `host:port` over `stream`. On success
/// the stream is positioned to relay application bytes to the destination.
pub async fn connect<S>(
    stream: &mut S,
    host: &str,
    port: u16,
    user: Option<&str>,
    pass: Option<&str>,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    negotiate_method(stream, user, pass).await?;
    send_connect(stream, host, port).await?;
    Ok(())
}

async fn negotiate_method<S>(
    stream: &mut S,
    user: Option<&str>,
    pass: Option<&str>,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let methods: &[u8] = if user.is_some() {
        &[METHOD_NO_AUTH, METHOD_USER_PASS]
    } else {
        &[METHOD_NO_AUTH]
    };
    let mut req = Vec::with_capacity(2 + methods.len());
    req.push(VER);
    req.push(methods.len() as u8);
    req.extend_from_slice(methods);
    stream.write_all(&req).await?;

    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await?;
    if resp[0] != VER {
        return Err(proto_err(format!(
            "bad SOCKS version in method reply: {}",
            resp[0]
        )));
    }
    match resp[1] {
        METHOD_NO_AUTH => Ok(()),
        METHOD_USER_PASS => {
            if user.is_none() {
                return Err(proto_err(
                    "server requires username/password auth but none was configured",
                ));
            }
            user_pass_auth(stream, user.unwrap_or(""), pass.unwrap_or("")).await
        }
        METHOD_NONE => Err(proto_err("server rejected all offered auth methods")),
        other => Err(proto_err(format!(
            "server selected unsupported method {other}"
        ))),
    }
}

async fn user_pass_auth<S>(stream: &mut S, user: &str, pass: &str) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if user.len() > 255 || pass.len() > 255 {
        return Err(proto_err("username or password exceeds 255 bytes"));
    }
    let mut req = Vec::with_capacity(3 + user.len() + pass.len());
    req.push(AUTH_VER);
    req.push(user.len() as u8);
    req.extend_from_slice(user.as_bytes());
    req.push(pass.len() as u8);
    req.extend_from_slice(pass.as_bytes());
    stream.write_all(&req).await?;

    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await?;
    if resp[1] != 0x00 {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            format!("SOCKS5 username/password auth failed (status {})", resp[1]),
        ));
    }
    Ok(())
}

async fn send_connect<S>(stream: &mut S, host: &str, port: u16) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut req = Vec::with_capacity(22 + host.len());
    req.push(VER);
    req.push(CMD_CONNECT);
    req.push(0x00); // RSV
    encode_addr(&mut req, host)?;
    req.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&req).await?;

    // Reply: VER REP RSV ATYP BND.ADDR BND.PORT
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    if head[0] != VER {
        return Err(proto_err(format!(
            "bad SOCKS version in reply: {}",
            head[0]
        )));
    }
    if head[1] != 0x00 {
        return Err(reply_err(head[1]));
    }
    let addr_len = match head[3] {
        ATYP_IPV4 => 4,
        ATYP_IPV6 => 16,
        ATYP_DOMAIN => {
            let mut l = [0u8; 1];
            stream.read_exact(&mut l).await?;
            l[0] as usize
        }
        other => return Err(proto_err(format!("unknown ATYP in reply: {other}"))),
    };
    // Consume BND.ADDR + BND.PORT (2 bytes) which we don't use.
    let mut scratch = vec![0u8; addr_len + 2];
    stream.read_exact(&mut scratch).await?;
    Ok(())
}

/// Append ATYP + address bytes for `host` (no port). IPv4/IPv6 literals use the
/// numeric ATYPs; everything else is sent as a domain for the proxy to resolve.
fn encode_addr(buf: &mut Vec<u8>, host: &str) -> io::Result<()> {
    if let Ok(v4) = host.parse::<Ipv4Addr>() {
        buf.push(ATYP_IPV4);
        buf.extend_from_slice(&v4.octets());
    } else if let Ok(v6) = host.parse::<Ipv6Addr>() {
        buf.push(ATYP_IPV6);
        buf.extend_from_slice(&v6.octets());
    } else {
        let b = host.as_bytes();
        if b.len() > 255 {
            return Err(proto_err("destination hostname exceeds 255 bytes"));
        }
        buf.push(ATYP_DOMAIN);
        buf.push(b.len() as u8);
        buf.extend_from_slice(b);
    }
    Ok(())
}

fn proto_err(msg: impl Into<String>) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, msg.into())
}

fn reply_err(rep: u8) -> io::Error {
    let reason = match rep {
        0x01 => "general SOCKS server failure",
        0x02 => "connection not allowed by ruleset",
        0x03 => "network unreachable",
        0x04 => "host unreachable",
        0x05 => "connection refused",
        0x06 => "TTL expired",
        0x07 => "command not supported",
        0x08 => "address type not supported",
        _ => "unknown SOCKS5 error",
    };
    io::Error::other(format!("SOCKS5 CONNECT failed: {reason} ({rep})"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use tokio::io::duplex;

    fn enc(host: &str) -> Vec<u8> {
        let mut b = Vec::new();
        encode_addr(&mut b, host).unwrap();
        b
    }

    #[test]
    fn encode_ipv4() {
        assert_eq!(enc("1.2.3.4"), vec![ATYP_IPV4, 1, 2, 3, 4]);
    }

    #[test]
    fn encode_domain() {
        let mut want = vec![ATYP_DOMAIN, 11];
        want.extend_from_slice(b"example.com");
        assert_eq!(enc("example.com"), want);
    }

    #[test]
    fn encode_ipv6() {
        let b = enc("::1");
        assert_eq!(b[0], ATYP_IPV6);
        assert_eq!(b.len(), 17);
        assert_eq!(b[16], 1);
    }

    // Full client handshake against a scripted in-memory "server".
    #[tokio::test]
    async fn connect_no_auth_roundtrip() {
        let (mut client, mut server) = duplex(1024);

        let server_task = tokio::spawn(async move {
            // method negotiation: expect VER, NMETHODS=1, [NO_AUTH]
            let mut m = [0u8; 3];
            server.read_exact(&mut m).await.unwrap();
            assert_eq!(m, [VER, 1, METHOD_NO_AUTH]);
            server.write_all(&[VER, METHOD_NO_AUTH]).await.unwrap();

            // connect request: VER CMD RSV ATYP(domain) len "host" port
            let mut head = [0u8; 4];
            server.read_exact(&mut head).await.unwrap();
            assert_eq!(head, [VER, CMD_CONNECT, 0x00, ATYP_DOMAIN]);
            let mut len = [0u8; 1];
            server.read_exact(&mut len).await.unwrap();
            let mut host = vec![0u8; len[0] as usize + 2];
            server.read_exact(&mut host).await.unwrap();
            // reply success with IPv4 BND
            server
                .write_all(&[VER, 0x00, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
        });

        connect(&mut client, "host.example", 443, None, None)
            .await
            .unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn connect_with_auth_roundtrip() {
        let (mut client, mut server) = duplex(1024);
        let server_task = tokio::spawn(async move {
            let mut m = [0u8; 4];
            server.read_exact(&mut m).await.unwrap();
            assert_eq!(m, [VER, 2, METHOD_NO_AUTH, METHOD_USER_PASS]);
            server.write_all(&[VER, METHOD_USER_PASS]).await.unwrap();

            // auth: VER ULEN user PLEN pass
            let mut h = [0u8; 2];
            server.read_exact(&mut h).await.unwrap();
            assert_eq!(h[0], AUTH_VER);
            let mut user = vec![0u8; h[1] as usize];
            server.read_exact(&mut user).await.unwrap();
            assert_eq!(&user, b"u");
            let mut pl = [0u8; 1];
            server.read_exact(&mut pl).await.unwrap();
            let mut pass = vec![0u8; pl[0] as usize];
            server.read_exact(&mut pass).await.unwrap();
            assert_eq!(&pass, b"p");
            server.write_all(&[AUTH_VER, 0x00]).await.unwrap();

            let mut head = [0u8; 4];
            server.read_exact(&mut head).await.unwrap();
            let mut rest = vec![0u8; 4 + 2 + 2]; // domain handling: read len then addr+port
                                                 // For 1.2.3.4 IPv4 target, ATYP=IPv4 -> 4 addr + 2 port already after head
                                                 // head already consumed VER CMD RSV ATYP. Read 4 (ipv4) + 2 (port).
            let _ = &mut rest;
            let mut ap = vec![0u8; 4 + 2];
            server.read_exact(&mut ap).await.unwrap();
            server
                .write_all(&[VER, 0x00, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
        });

        connect(&mut client, "1.2.3.4", 9090, Some("u"), Some("p"))
            .await
            .unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn connect_refused_maps_error() {
        let (mut client, mut server) = duplex(1024);
        let server_task = tokio::spawn(async move {
            let mut m = [0u8; 3];
            server.read_exact(&mut m).await.unwrap();
            server.write_all(&[VER, METHOD_NO_AUTH]).await.unwrap();
            let mut head = [0u8; 4];
            server.read_exact(&mut head).await.unwrap();
            let mut len = [0u8; 1];
            server.read_exact(&mut len).await.unwrap();
            let mut host = vec![0u8; len[0] as usize + 2];
            server.read_exact(&mut host).await.unwrap();
            // REP=0x05 connection refused
            server
                .write_all(&[VER, 0x05, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
        });
        let err = connect(&mut client, "host", 80, None, None)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("refused"), "{err}");
        server_task.await.unwrap();
        let _ = Cursor::new(Vec::<u8>::new());
    }
}
