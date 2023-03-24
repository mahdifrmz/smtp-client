use std::{
    io::{Read, Write},
    net::TcpStream,
    sync::Arc,
};

use base64::{engine::general_purpose, Engine};
use rustls::{OwnedTrustAnchor, RootCertStore};

type TlsCon = rustls::ClientConnection;

fn create_tls_conn(server_address: &str) -> TlsCon {
    let mut root_store = RootCertStore::empty();
    root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
        OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    }));
    let config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    return TlsCon::new(Arc::new(config), server_address.try_into().unwrap()).unwrap();
}

struct Parser<'a, T>
where
    T: Read,
{
    stream: &'a mut T,
    next_char: char,
}

#[derive(Debug)]
enum SmtpErr {
    Syntax,
    Network,
}

type SmtpResult<T> = Result<T, SmtpErr>;

impl<'a, T> Parser<'a, T>
where
    T: Read,
{
    fn recv_char(&mut self) -> SmtpResult<char> {
        let mut buf = [0u8; 1];
        self.stream.read(&mut buf).map_err(|_| SmtpErr::Network)?;
        let c = self.next_char;
        self.next_char = buf[0] as char;
        Ok(c)
    }
    fn peek_char(&mut self) -> char {
        self.next_char
    }
    fn recv_digit(&mut self) -> SmtpResult<u8> {
        let c = self.recv_char()?;
        if c > '9' || c < '0' {
            Err(SmtpErr::Syntax)
        } else {
            Ok((c as u8) - ('0' as u8))
        }
    }
    fn expect_char(&mut self, exp: char) -> SmtpResult<()> {
        let c = self.recv_char()?;
        if c == exp {
            Ok(())
        } else {
            Err(SmtpErr::Syntax)
        }
    }
    fn expect_end(&mut self) -> SmtpResult<()> {
        self.expect_char('\r')?;
        if self.peek_char() == '\n' {
            Ok(())
        } else {
            Err(SmtpErr::Syntax)
        }
    }
    fn recv_text(&mut self) -> SmtpResult<String> {
        let mut text = String::new();
        loop {
            let c = self.recv_char()?;
            if c == '\r' && self.peek_char() == '\n' {
                return Ok(text);
            } else {
                text.push(c);
            }
        }
    }
    fn recv_line(&mut self) -> SmtpResult<Line> {
        self.recv_char()?;
        let d1 = self.recv_digit()? as u32;
        let d2 = self.recv_digit()? as u32;
        let d3 = self.recv_digit()? as u32;
        let code = d1 * 100 + d2 * 10 + d3;
        let next = self.peek_char();
        let text = if next == ' ' || next == '-' {
            self.recv_char()?;
            self.recv_text()?
        } else {
            self.expect_end()?;
            String::new()
        };
        Ok(Line {
            text,
            code,
            last: next == ' ',
        })
    }
    fn recv_reply(&mut self) -> SmtpResult<Vec<Line>> {
        let mut lines = vec![self.recv_line()?];
        while !lines[lines.len() - 1].last {
            lines.push(self.recv_line()?);
        }
        Ok(lines)
    }

    fn new(stream: &'a mut T) -> Parser<'a, T> {
        let parser = Parser {
            stream,
            next_char: '\0',
        };
        parser
    }
}

struct Line {
    code: u32,
    text: String,
    last: bool,
}

fn get_auth_plain(username: &str, password: &str) -> String {
    let mut s = vec![];
    s.push(0u8);
    s.append(&mut username.chars().map(|c| c as u8).collect());
    s.push(0u8);
    s.append(&mut password.chars().map(|c| c as u8).collect());
    general_purpose::STANDARD.encode(s)
}

fn _recv_reply<T>(stream: &mut T) -> SmtpResult<Vec<Line>>
where
    T: Read,
{
    let mut parser = Parser::new(stream);
    parser.recv_reply()
}
fn recv_reply<T>(stream: &mut T)
where
    T: Read,
{
    let rep = _recv_reply(stream).unwrap();
    for l in rep {
        println!(
            "SERVER -> {}{}{}",
            l.code,
            if l.last { ' ' } else { '-' },
            l.text,
        );
    }
}

struct Mail {
    subject: String,
    from: String,
    to: String,
    text: String,
}

struct Credentials {
    username: String,
    password: String,
}

struct Server {
    address: String,
    port: u16,
    meta: ServerMeta,
}

enum Support {
    Supported,
    NotSupported,
    Unknown,
}

struct ServerMeta {
    utf8: Support,
    auth_plain: Support,
    tls: Support,
    pipelining: Support,
}

struct Mailer {}

impl Mailer {
    fn connect(server: Server, credentials: Credentials) {}
    fn disconnect() {}
    fn send(mail: Mail) {}
}

fn main() {
    /*
        todo:
            PIPELINING
            MORE AUTH METHODS
            UTF8
            MIME
        Done:
            TLS
            AUTH PLAIN
    */

    /*
       - read .toml email file
       - for each server
            - create thread
            - open connection
            - read extensions (switch to TLS if supported)
            - for every email
                - MAIL commands
            - QUIT
        - join All threads
    */
    let server_address = "smtp.gmail.com";
    let port = 25;
    let username = "faramarzpour98@gmail.com";
    let password = "mqtepoybaongfyic";

    let mut client = TcpStream::connect(format!("{}:{}", server_address, port)).unwrap();
    recv_reply(&mut client);
    client.write("EHLO me\n".as_bytes()).unwrap();
    recv_reply(&mut client);
    client.write("starttls\n".as_bytes()).unwrap();
    recv_reply(&mut client);

    let mut con = create_tls_conn(server_address);
    let mut tls = rustls::Stream::new(&mut con, &mut client);

    tls.write("ehlo mee\n".as_bytes()).unwrap();
    recv_reply(&mut tls);
    let userpass = get_auth_plain(username, password);
    tls.write(format!("AUTH PLAIN {}\n", userpass).as_bytes())
        .unwrap();
    recv_reply(&mut tls);
    tls.write("MAIL FROM:<faramarzpour98@gmail.com>\n".as_bytes())
        .unwrap();
    recv_reply(&mut tls);
    tls.write("RCPT TO:<faramarzpour98@gmail.com>\n".as_bytes())
        .unwrap();
    recv_reply(&mut tls);
    tls.write("DATA\n".as_bytes()).unwrap();
    recv_reply(&mut tls);
    tls.write("salam!\r\n.\r\n".as_bytes()).unwrap();
    recv_reply(&mut tls);
}
