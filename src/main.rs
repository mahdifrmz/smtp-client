use std::{
    io::{Read, Write},
    net::TcpStream,
    sync::Arc,
    time::Duration,
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
    Protocol,
    ServerUnreachable,
    InvalidServer,
    Network,
    Unavailable,
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
            Err(SmtpErr::Protocol)
        } else {
            Ok((c as u8) - ('0' as u8))
        }
    }
    fn expect_char(&mut self, exp: char) -> SmtpResult<()> {
        let c = self.recv_char()?;
        if c == exp {
            Ok(())
        } else {
            Err(SmtpErr::Protocol)
        }
    }
    fn expect_end(&mut self) -> SmtpResult<()> {
        self.expect_char('\r')?;
        if self.peek_char() == '\n' {
            Ok(())
        } else {
            Err(SmtpErr::Protocol)
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
            code: status_code(code).ok_or_else(|| SmtpErr::Protocol)?,
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
    code: StatusCode,
    text: String,
    last: bool,
}

impl Line {
    fn syn(&self) -> SmtpResult<()> {
        let code = self.code;
        if code == StatusCode::SyntaxError
            || code == StatusCode::CommandNotImplemented
            || code == StatusCode::BadSequence
            || code == StatusCode::ParamNotImplemented
        {
            Err(SmtpErr::Protocol)
        } else {
            Ok(())
        }
    }
    fn expect(&self, code: StatusCode) -> SmtpResult<()> {
        if self.code != code {
            Err(SmtpErr::Protocol)
        } else {
            Ok(())
        }
    }
}

fn get_auth_plain(username: &str, password: &str) -> String {
    let mut s = vec![];
    s.push(0u8);
    s.append(&mut username.chars().map(|c| c as u8).collect());
    s.push(0u8);
    s.append(&mut password.chars().map(|c| c as u8).collect());
    general_purpose::STANDARD.encode(s)
}

fn recv_reply<T>(stream: &mut T) -> SmtpResult<Vec<Line>>
where
    T: Read,
{
    let mut parser = Parser::new(stream);
    parser.recv_reply()
}
fn recv_line<T>(stream: &mut T) -> SmtpResult<Line>
where
    T: Read,
{
    let mut parser = Parser::new(stream);
    let line = parser.recv_line()?;
    if !line.last {
        Err(SmtpErr::Protocol)
    } else {
        Ok(line)
    }
}
fn log_reply<T>(stream: &mut T)
where
    T: Read,
{
    let rep = recv_reply(stream).unwrap();
    for l in rep {
        println!(
            "SERVER -> {}{}{}",
            l.code as u32,
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

#[derive(Clone, Copy, PartialEq, Eq)]
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
    name: String,
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

#[derive(PartialEq, Eq, Clone, Copy)]
enum StatusCode {
    SystemStatus = 211,
    HelpMessage = 214,
    ServiceReady = 220,
    ServiceClosingChannel = 221,
    Okay = 250,
    UserNotLocal = 251,
    CanNotVrfyButWillAttemp = 252,
    StartMailInput = 354,
    ServiceNotAvailable = 421,
    MailboxUnavailable = 450,
    LocalError = 451,
    InsufficientStorage = 452,
    AccomodateParams = 455,
    SyntaxError = 501,
    CommandNotImplemented = 502,
    BadSequence = 503,
    ParamNotImplemented = 504,
    NoAccess = 550,
    UserNotLocalError = 551,
    ExeededAllocation = 552,
    MailBoxNameNotAllowed = 553,
    TransactionFailed = 554,
    ParamsNotRecognized = 555,
}

fn status_code(code: u32) -> Option<StatusCode> {
    match code {
        211 => Some(StatusCode::SystemStatus),
        214 => Some(StatusCode::HelpMessage),
        220 => Some(StatusCode::ServiceReady),
        221 => Some(StatusCode::ServiceClosingChannel),
        250 => Some(StatusCode::Okay),
        251 => Some(StatusCode::UserNotLocal),
        252 => Some(StatusCode::CanNotVrfyButWillAttemp),
        354 => Some(StatusCode::StartMailInput),
        421 => Some(StatusCode::ServiceNotAvailable),
        450 => Some(StatusCode::MailboxUnavailable),
        451 => Some(StatusCode::LocalError),
        452 => Some(StatusCode::InsufficientStorage),
        455 => Some(StatusCode::AccomodateParams),
        501 => Some(StatusCode::SyntaxError),
        502 => Some(StatusCode::CommandNotImplemented),
        503 => Some(StatusCode::BadSequence),
        504 => Some(StatusCode::ParamNotImplemented),
        550 => Some(StatusCode::NoAccess),
        551 => Some(StatusCode::UserNotLocalError),
        552 => Some(StatusCode::ExeededAllocation),
        553 => Some(StatusCode::MailBoxNameNotAllowed),
        554 => Some(StatusCode::TransactionFailed),
        555 => Some(StatusCode::ParamsNotRecognized),
        _ => None,
    }
}

impl Mailer {
    fn new(server: Server) -> Mailer {
        Mailer {
            name: "me".to_string(),
            server,
            tlscon: None,
            stream: None,
        }
    }
    fn send(&mut self, data: Command) -> SmtpResult<()> {
        if self.is_tls() {
            let mut tlscon = self.tlscon.take().unwrap();
            rustls::Stream::new(&mut tlscon, self.stream())
                .write(data.to_string().as_bytes())
                .map_err(|_| SmtpErr::Network)?;
            self.tlscon = Some(tlscon);
        } else {
            self.stream()
                .write(data.to_string().as_bytes())
                .map_err(|_| SmtpErr::Network)?;
        }
        Ok(())
    }
    fn stream(&mut self) -> &mut TcpStream {
        self.stream.as_mut().unwrap()
    }
    fn set_time_out(&mut self, seconds: u64) -> SmtpResult<()> {
        self.stream()
            .set_read_timeout(Some(Duration::new(seconds, 0)))
            .map_err(|_| SmtpErr::Network)?;
        self.stream()
            .set_write_timeout(Some(Duration::new(seconds, 0)))
            .map_err(|_| SmtpErr::Network)?;
        Ok(())
    }
    fn init_connection(&mut self) -> SmtpResult<()> {
        let client = TcpStream::connect(format!("{}:{}", self.server.address, self.server.port))
            .map_err(|_| SmtpErr::ServerUnreachable)?;

        self.stream = Some(client);
        self.set_time_out(5)?;

        let rep = recv_line(self.stream()).map_err(|_| SmtpErr::InvalidServer)?;
        if rep.code == StatusCode::ServiceNotAvailable {
            Err(SmtpErr::Unavailable)
        } else if rep.code != StatusCode::ServiceReady {
            Err(SmtpErr::Protocol)
        } else {
            Ok(())
        }
    }
    fn is_tls(&self) -> bool {
        self.tlscon.is_some()
    }
    fn recv_reply(&mut self) -> SmtpResult<Vec<Line>> {
        if self.is_tls() {
            let mut tlscon = self.tlscon.take().unwrap();
            let mut tls = rustls::Stream::new(&mut tlscon, self.stream());
            recv_reply(&mut tls)
        } else {
            recv_reply(self.stream())
        }
    }
    fn recv_line(&mut self) -> SmtpResult<Line> {
        if self.is_tls() {
            let mut tlscon = self.tlscon.take().unwrap();
            let mut tls = rustls::Stream::new(&mut tlscon, self.stream());
            recv_line(&mut tls)
        } else {
            recv_line(self.stream())
        }
    }
    fn handshake(&mut self) -> SmtpResult<()> {
        let name = self.name.clone();

        self.send(Command::Ehlo(name.clone()))?;
        let rep = recv_reply(self.stream())?;
        self.server.meta.tls = Support::NotSupported;
        if self.is_tls() {
            self.server.meta.auth_plain = Support::NotSupported;
        }

        for l in rep.iter() {
            l.expect(StatusCode::Okay)?;
            if l.text == "STARTTLS" {
                self.server.meta.tls = Support::Supported;
            } else if l.text == "8BITMIME" {
                self.server.meta.utf8 = Support::Supported
            } else if l.text == "PIPELINING" {
                self.server.meta.pipelining = Support::Supported;
            } else {
                let words: Vec<&str> = l.text.split(' ').collect();
                if words.len() == 1 {
                    if words[0] == "AUTH" {
                        for i in 1..words.len() {
                            if words[i] == "PLAIN" {
                                self.server.meta.auth_plain = Support::Supported;
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }
    fn start_tls(&mut self) -> SmtpResult<()> {
        self.send(Command::StartTls)?;
        recv_line(self.stream())?.expect(StatusCode::ServiceReady)?;
        let mut con = create_tls_conn(self.server.address.as_str());
        let mut tls = rustls::Stream::new(&mut con, self.stream());
        self.tlscon = Some(con);
        Ok(())
    }
    fn auth_plain(&mut self, credentials: Credentials) -> SmtpResult<()> {
        self.send(Command::AuthPlain(
            credentials.username.clone(),
            credentials.password.clone(),
        ))?;
        // TODO
        Ok(())
    }
    fn connect(&mut self, credentials: Credentials) -> SmtpResult<()> {
        self.init_connection()?;
        self.handshake()?;
        if self.server.meta.tls == Support::Supported {
            self.start_tls()?;
            self.handshake()?;
        }
        if self.server.meta.auth_plain == Support::Supported {
            self.auth_plain(credentials)?;
        }
        Ok(())
    }
    fn disconnect(&mut self) -> SmtpResult<()> {
        self.send(Command::Quit).unwrap();
        self.stream
            .as_mut()
            .unwrap()
            .shutdown(std::net::Shutdown::Both)
            .map_err(|_| SmtpErr::Network)?;
        Ok(())
    }
    fn send_mail(&mut self, mail: Mail) -> SmtpResult<()> {
        let mut tls =
            rustls::Stream::new(self.tlscon.as_mut().unwrap(), self.stream.as_mut().unwrap());
        tls.write(Command::MailFrom(mail.from.clone()).to_string().as_bytes())
            .unwrap();
        log_reply(&mut tls);
        tls.write(Command::RcptTo(mail.to.clone()).to_string().as_bytes())
            .unwrap();
        log_reply(&mut tls);
        tls.write(Command::Data.to_string().as_bytes()).unwrap();
        log_reply(&mut tls);
        tls.write(format!("{}\r\n.\r\n", mail.text).as_bytes())
            .unwrap();
        log_reply(&mut tls);
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
        .send_mail(Mail {
            subject: "".to_string(),
            from: username.clone(),
            to: username.clone(),
            text: "salam!".to_string(),
        })
        .unwrap();
    mailer.disconnect().unwrap();
}
