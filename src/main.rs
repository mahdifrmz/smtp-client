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

#[derive(Clone)]
struct Server {
    address: String,
    port: u16,
    meta: ServerMeta,
}

#[derive(Clone, Copy)]
enum Support {
    Supported,
    NotSupported,
    Unknown,
}

#[derive(Clone, Copy)]
struct ServerMeta {
    utf8: Support,
    auth_plain: Support,
    tls: Support,
    pipelining: Support,
}

struct Mailer {
    server: Server,
    tlscon: Option<TlsCon>,
    stream: Option<TcpStream>,
}

impl Server {
    fn new(address: &str, port: u16) -> Server {
        Server {
            address: address.to_owned(),
            port,
            meta: ServerMeta::new(),
        }
    }
}

impl ServerMeta {
    fn new() -> ServerMeta {
        ServerMeta {
            utf8: Support::Unknown,
            auth_plain: Support::Unknown,
            tls: Support::Unknown,
            pipelining: Support::Unknown,
        }
    }
}

enum Command {
    Ehlo(String),
    Quit,
    StartTls,
    MailFrom(String),
    RcptTo(String),
    Data,
    AuthPlain(String, String),
}

impl ToString for Command {
    fn to_string(&self) -> String {
        let mut cmd = match self {
            Command::Data => "DATA".to_string(),
            Command::Ehlo(me) => format!("EHLO {}", me),
            Command::StartTls => "STARTTLS".to_string(),
            Command::Quit => "QUIT".to_string(),
            Command::MailFrom(from) => format!("MAIL FROM:<{}>", from),
            Command::RcptTo(to) => format!("RCPT TO:<{}>", to),
            Command::AuthPlain(un, pw) => format!("AUTH PLAIN {}", get_auth_plain(un, pw)),
        };
        cmd.push_str("\r\n");
        cmd
    }
}

impl Mailer {
    fn new(server: Server) -> Mailer {
        Mailer {
            server,
            tlscon: None,
            stream: None,
        }
    }
    fn connect(&mut self, credentials: Credentials) -> SmtpResult<()> {
        let client_name = "me".to_string();
        let server = &self.server;
        let mut client = TcpStream::connect(format!("{}:{}", server.address, server.port))
            .map_err(|_| SmtpErr::Network)?;

        recv_reply(&mut client);
        client
            .write(Command::Ehlo(client_name.clone()).to_string().as_bytes())
            .unwrap();
        recv_reply(&mut client);
        client
            .write(Command::StartTls.to_string().as_bytes())
            .unwrap();
        recv_reply(&mut client);

        let mut con = create_tls_conn(server.address.as_str());
        let mut tls = rustls::Stream::new(&mut con, &mut client);

        tls.write(Command::Ehlo(client_name).to_string().as_bytes())
            .unwrap();
        recv_reply(&mut tls);
        tls.write(
            Command::AuthPlain(credentials.username.clone(), credentials.password.clone())
                .to_string()
                .as_bytes(),
        )
        .unwrap();
        recv_reply(&mut tls);
        self.stream = Some(client);
        self.tlscon = Some(con);
        Ok(())
    }
    fn disconnect(&mut self) -> SmtpResult<()> {
        let mut tls =
            rustls::Stream::new(self.tlscon.as_mut().unwrap(), self.stream.as_mut().unwrap());
        tls.write(Command::Quit.to_string().as_bytes()).unwrap();
        recv_reply(&mut tls);
        self.stream
            .as_mut()
            .unwrap()
            .shutdown(std::net::Shutdown::Both)
            .map_err(|_| SmtpErr::Network)?;
        Ok(())
    }
    fn send(&mut self, mail: Mail) -> SmtpResult<()> {
        let mut tls =
            rustls::Stream::new(self.tlscon.as_mut().unwrap(), self.stream.as_mut().unwrap());
        tls.write(Command::MailFrom(mail.from.clone()).to_string().as_bytes())
            .unwrap();
        recv_reply(&mut tls);
        tls.write(Command::RcptTo(mail.to.clone()).to_string().as_bytes())
            .unwrap();
        recv_reply(&mut tls);
        tls.write(Command::Data.to_string().as_bytes()).unwrap();
        recv_reply(&mut tls);
        tls.write(format!("{}\r\n.\r\n", mail.text).as_bytes())
            .unwrap();
        recv_reply(&mut tls);
        Ok(())
    }
}

fn main() {
    /*
        todo:
            PIPELINING
            MORE AUTH METHODS
            UTF8
            MIME
            ! address validation
            ! dot stuffing
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
    let username = "faramarzpour98@gmail.com".to_string();
    let password = "mqtepoybaongfyic".to_string();

    let mut mailer = Mailer::new(Server::new("smtp.gmail.com", 25));
    mailer
        .connect(Credentials {
            username: username.clone(),
            password,
        })
        .unwrap();
    mailer
        .send(Mail {
            subject: "".to_string(),
            from: username.clone(),
            to: username.clone(),
            text: "salam!".to_string(),
        })
        .unwrap();
    mailer.disconnect().unwrap();
}
