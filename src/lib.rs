use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream, ToSocketAddrs},
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

pub trait Logger: Clone {
    fn client(&mut self, data: &[u8]);
    fn server(&mut self, data: &[u8]);
    fn disable(&mut self);
    fn enable(&mut self);
}

struct Parser<'a, T, L>
where
    T: Read,
    L: Logger,
{
    stream: &'a mut T,
    logger: &'a mut L,
    next_char: char,
}

#[derive(Debug, Clone)]
pub enum SmtpErr {
    Protocol,
    ServerUnreachable,
    ServerUnavailable,
    InvalidServer,
    Network,
    InvalidCred,
    Policy,
    DNS,
    MailBoxName(String),
    Forward(String),
    File(String),
}

impl SmtpErr {
    pub fn retriable(&self) -> bool {
        match self {
            SmtpErr::Network
            | SmtpErr::DNS
            | SmtpErr::ServerUnavailable
            | SmtpErr::ServerUnreachable => true,
            _ => false,
        }
    }
}

type SmtpResult<T> = Result<T, SmtpErr>;

impl<'a, T, L> Parser<'a, T, L>
where
    T: Read,
    L: Logger,
{
    fn recv_char(&mut self) -> SmtpResult<char> {
        let mut buf = [0u8; 1];
        self.stream.read(&mut buf).map_err(|_| SmtpErr::Network)?;
        let c = self.next_char;
        self.next_char = buf[0] as char;
        self.logger.server(&buf);
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

    fn new(stream: &'a mut T, logger: &'a mut L) -> Parser<'a, T, L> {
        let parser = Parser {
            logger,
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

fn get_auth_login(token: &str) -> String {
    general_purpose::STANDARD.encode(token)
}

fn stream_recv_reply<T>(stream: &mut T, logger: &mut impl Logger) -> SmtpResult<Vec<Line>>
where
    T: Read,
{
    let mut parser = Parser::new(stream, logger);
    parser.recv_reply()
}
fn stream_recv_line<T>(stream: &mut T, logger: &mut impl Logger) -> SmtpResult<Line>
where
    T: Read,
{
    let mut parser = Parser::new(stream, logger);
    let line = parser.recv_line()?;
    if !line.last {
        parser.recv_reply()?;
    }
    Ok(line)
}

pub struct Mail {
    pub subject: String,
    pub from: String,
    pub from_name: Option<String>,
    pub to: String,
    pub to_name: Option<String>,
    pub text: String,
    pub attachments: Vec<String>,
}

#[derive(Clone)]
pub struct Credentials {
    username: String,
    password: String,
}

impl Credentials {
    pub fn new(username: String, password: String) -> Credentials {
        Credentials { username, password }
    }
}

#[derive(Clone)]
pub struct Server {
    address: String,
    port: u16,
    meta: ServerMeta,
}

#[derive(Clone)]
pub struct Config {
    pub retries: u32,
    pub timeout: u64,
    pub parallel: bool,
    pub max_channels: u32,
}

impl Config {
    pub fn new() -> Config {
        Config {
            retries: 0,
            timeout: 5,
            parallel: false,
            max_channels: 8,
        }
    }
    pub fn retires<'a>(&'a mut self, value: u32) -> &'a mut Config {
        self.retries = value;
        self
    }
    pub fn timeout<'a>(&'a mut self, value: u64) -> &'a mut Config {
        self.timeout = value;
        self
    }
    pub fn parallel<'a>(&'a mut self, value: bool) -> &'a mut Config {
        self.parallel = value;
        self
    }
    pub fn max_channels<'a>(&'a mut self, value: u32) -> &'a mut Config {
        self.max_channels = value;
        self
    }
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
    auth_login: Support,
    tls: Support,
    pipelining: Support,
}

pub struct MailerConnection<L>
where
    L: Logger,
{
    name: String,
    config: Config,
    server: Server,
    tlscon: Option<TlsCon>,
    stream: TcpStream,
    logger: L,
}

impl Server {
    pub fn new(address: String, port: u16) -> Server {
        Server {
            address: address,
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
            auth_login: Support::Unknown,
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
    AuthLogin,
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
            Command::AuthLogin => "AUTH LOGIN".to_string(),
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
    AuthSuccess = 235,
    Okay = 250,
    UserNotLocal = 251,
    CanNotVrfyButWillAttemp = 252,
    StartMailInput = 354,
    ServerChallenge = 334,
    ServiceNotAvailable = 421,
    PasswordTransition = 432,
    MailboxUnavailable = 450,
    LocalError = 451,
    InsufficientStorage = 452,
    TempAuthFailure = 454,
    AccomodateParams = 455,
    AuthLineTooLong = 500,
    SyntaxError = 501,
    CommandNotImplemented = 502,
    BadSequence = 503,
    ParamNotImplemented = 504,
    AuthRequired = 530,
    AuthMechWeak = 534,
    AuthInvalidCred = 535,
    AuthEncryptRequired = 538,
    NoAccess = 550,
    UserNotLocalError = 551,
    ExeededAllocation = 552,
    MailBoxNameNotAllowed = 553,
    TransactionFailed = 554,
    ParamsNotRecognized = 555,
}

enum EhloLine {
    Pipelining,
    StartTls,
    EightBitMIME,
    Auth,
}

enum AuthMech {
    Plain,
    Login,
}

impl ToString for AuthMech {
    fn to_string(&self) -> String {
        (match self {
            AuthMech::Plain => "PLAIN",
            AuthMech::Login => "LOGIN",
        })
        .to_string()
    }
}

impl ToString for EhloLine {
    fn to_string(&self) -> String {
        (match self {
            EhloLine::Pipelining => "PIPELINING",
            EhloLine::StartTls => "STARTTLS",
            EhloLine::EightBitMIME => "8BITMIME",
            EhloLine::Auth => "AUTH",
        })
        .to_string()
    }
}

fn status_code(code: u32) -> Option<StatusCode> {
    match code {
        211 => Some(StatusCode::SystemStatus),
        214 => Some(StatusCode::HelpMessage),
        220 => Some(StatusCode::ServiceReady),
        221 => Some(StatusCode::ServiceClosingChannel),
        235 => Some(StatusCode::AuthSuccess),
        250 => Some(StatusCode::Okay),
        251 => Some(StatusCode::UserNotLocal),
        252 => Some(StatusCode::CanNotVrfyButWillAttemp),
        334 => Some(StatusCode::ServerChallenge),
        354 => Some(StatusCode::StartMailInput),
        421 => Some(StatusCode::ServiceNotAvailable),
        432 => Some(StatusCode::PasswordTransition),
        450 => Some(StatusCode::MailboxUnavailable),
        451 => Some(StatusCode::LocalError),
        452 => Some(StatusCode::InsufficientStorage),
        454 => Some(StatusCode::TempAuthFailure),
        455 => Some(StatusCode::AccomodateParams),
        500 => Some(StatusCode::AuthLineTooLong),
        501 => Some(StatusCode::SyntaxError),
        502 => Some(StatusCode::CommandNotImplemented),
        503 => Some(StatusCode::BadSequence),
        504 => Some(StatusCode::ParamNotImplemented),
        530 => Some(StatusCode::AuthRequired),
        534 => Some(StatusCode::AuthMechWeak),
        535 => Some(StatusCode::AuthInvalidCred),
        538 => Some(StatusCode::AuthEncryptRequired),
        550 => Some(StatusCode::NoAccess),
        551 => Some(StatusCode::UserNotLocalError),
        552 => Some(StatusCode::ExeededAllocation),
        553 => Some(StatusCode::MailBoxNameNotAllowed),
        554 => Some(StatusCode::TransactionFailed),
        555 => Some(StatusCode::ParamsNotRecognized),
        _ => None,
    }
}

pub fn check_address(address: &str) -> SmtpResult<()> {
    regex::Regex::new(
        r"^([a-z0-9_+]([a-z0-9_+.]*[a-z0-9_+])?)@([a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,6})",
    )
    .unwrap()
    .captures(address)
    .map(|_| ())
    .ok_or(SmtpErr::MailBoxName(address.to_string()))
}

impl<L> MailerConnection<L>
where
    L: Logger,
{
    fn new(server: Server, config: Config, stream: TcpStream, logger: L) -> MailerConnection<L> {
        MailerConnection {
            name: "me".to_string(),
            server,
            config,
            tlscon: None,
            stream,
            logger,
        }
    }
    fn recv_reply(&mut self) -> SmtpResult<Vec<Line>> {
        let lines = if self.is_tls() {
            let mut tlscon = self.tlscon.take().unwrap();
            let mut tls = rustls::Stream::new(&mut tlscon, &mut self.stream);
            let lines = stream_recv_reply(&mut tls, &mut self.logger)?;
            self.tlscon = Some(tlscon);
            lines
        } else {
            stream_recv_reply(&mut self.stream, &mut self.logger)?
        };
        for l in lines.iter() {
            if l.code == StatusCode::ServiceNotAvailable || l.code == StatusCode::TransactionFailed
            {
                self.terminate();
                return Err(SmtpErr::ServerUnavailable);
            }
        }
        Ok(lines)
    }
    fn recv_line(&mut self) -> SmtpResult<Line> {
        let line = if self.is_tls() {
            let mut tlscon = self.tlscon.take().unwrap();
            let mut tls = rustls::Stream::new(&mut tlscon, &mut self.stream);
            let line = stream_recv_line(&mut tls, &mut self.logger)?;
            self.tlscon = Some(tlscon);
            line
        } else {
            stream_recv_line(&mut self.stream, &mut self.logger)?
        };
        if line.code == StatusCode::ServiceNotAvailable
            || line.code == StatusCode::TransactionFailed
        {
            self.terminate();
            Err(SmtpErr::ServerUnavailable)
        } else {
            Ok(line)
        }
    }
    fn write(&mut self, data: &[u8]) -> SmtpResult<()> {
        self.logger.client(data);
        if self.is_tls() {
            let mut tlscon = self.tlscon.take().unwrap();
            rustls::Stream::new(&mut tlscon, &mut self.stream)
                .write(data)
                .map_err(|_| SmtpErr::Network)?;
            self.tlscon = Some(tlscon);
        } else {
            self.stream.write(data).map_err(|_| SmtpErr::Network)?;
        }
        Ok(())
    }
    fn send(&mut self, cmd: Command) -> SmtpResult<()> {
        self.write(cmd.to_string().as_bytes())
    }
    fn set_time_out(&mut self, seconds: u64) -> SmtpResult<()> {
        self.stream
            .set_read_timeout(Some(Duration::new(seconds, 0)))
            .map_err(|_| SmtpErr::Network)?;
        self.stream
            .set_write_timeout(Some(Duration::new(seconds, 0)))
            .map_err(|_| SmtpErr::Network)?;
        Ok(())
    }

    fn address_resolve(&mut self) -> SmtpResult<SocketAddr> {
        format!("{}:{}", self.server.address, self.server.port)
            .to_socket_addrs()
            .map_err(|_| SmtpErr::DNS)?
            .next()
            .ok_or(SmtpErr::DNS)
    }

    fn init_connection(&mut self) -> SmtpResult<()> {
        let address = self.address_resolve()?;

        let client = TcpStream::connect_timeout(&address, Duration::new(self.config.timeout, 0))
            .map_err(|_| SmtpErr::ServerUnreachable)?;

        self.stream = client;
        self.set_time_out(self.config.timeout)?;

        let rep = self.recv_line().map_err(|_| SmtpErr::InvalidServer)?;
        if rep.code != StatusCode::ServiceReady {
            Err(SmtpErr::Protocol)
        } else {
            Ok(())
        }
    }
    fn is_tls(&self) -> bool {
        self.tlscon.is_some()
    }
    fn handshake(&mut self) -> SmtpResult<()> {
        let name = self.name.clone();

        self.send(Command::Ehlo(name.clone()))?;
        let rep = self.recv_reply()?;
        self.server.meta.tls = Support::NotSupported;
        if self.is_tls() {
            self.server.meta.auth_plain = Support::NotSupported;
        }

        for l in rep.iter() {
            l.expect(StatusCode::Okay)?;
            let text = l.text.to_uppercase();
            if text == EhloLine::StartTls.to_string() {
                self.server.meta.tls = Support::Supported;
            } else if text == EhloLine::EightBitMIME.to_string() {
                self.server.meta.utf8 = Support::Supported
            } else if text == EhloLine::Pipelining.to_string() {
                self.server.meta.pipelining = Support::Supported;
            } else {
                let words: Vec<&str> = text.split(' ').collect();
                if words.len() >= 1 {
                    if words[0] == EhloLine::Auth.to_string() {
                        for i in 1..words.len() {
                            if words[i] == AuthMech::Plain.to_string() {
                                self.server.meta.auth_plain = Support::Supported;
                            } else if words[i] == AuthMech::Login.to_string() {
                                self.server.meta.auth_login = Support::Supported;
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
        self.recv_line()?.expect(StatusCode::ServiceReady)?;
        let mut con = create_tls_conn(self.server.address.as_str());
        rustls::Stream::new(&mut con, &mut self.stream);
        self.tlscon = Some(con);
        Ok(())
    }
    fn reply_auth_result(&mut self) -> SmtpResult<()> {
        let cc = self.recv_line()?.code;
        match cc {
            StatusCode::AuthSuccess => Ok(()),
            StatusCode::AuthInvalidCred | StatusCode::NoAccess => Err(SmtpErr::InvalidCred),
            _ => Err(SmtpErr::Protocol),
        }
    }
    fn auth_plain(&mut self, credentials: Credentials) -> SmtpResult<()> {
        self.send(Command::AuthPlain(
            credentials.username.clone(),
            credentials.password.clone(),
        ))?;
        self.reply_auth_result()
    }
    fn end(&mut self) -> SmtpResult<()> {
        self.write("\r\n".as_bytes())
    }
    fn auth_login(&mut self, credentials: Credentials) -> SmtpResult<()> {
        self.send(Command::AuthLogin)?;
        self.recv_line()?.expect(StatusCode::ServerChallenge)?;
        self.write(get_auth_login(credentials.username.as_str()).as_bytes())?;
        self.end()?;
        self.recv_line()?.expect(StatusCode::ServerChallenge)?;
        self.write(get_auth_login(credentials.password.as_str()).as_bytes())?;
        self.end()?;
        self.reply_auth_result()
    }
    fn try_connect(&mut self, credentials: Credentials) -> SmtpResult<()> {
        self.init_connection()?;
        self.handshake()?;
        if self.server.meta.tls == Support::Supported {
            self.start_tls()?;
            self.handshake()?;
        }
        if self.server.meta.auth_plain == Support::Supported {
            self.auth_plain(credentials)?;
        } else if self.server.meta.auth_login == Support::Supported {
            self.auth_login(credentials)?;
        }
        Ok(())
    }
    fn terminate(&mut self) {
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
        self.tlscon.take();
        self.server.meta = ServerMeta::new();
    }
    fn try_close(&mut self) -> SmtpResult<()> {
        self.send(Command::Quit)?;
        self.recv_line()?
            .expect(StatusCode::ServiceClosingChannel)?;
        self.terminate();
        Ok(())
    }
    fn command_mail_from(&mut self, from: &String) -> SmtpResult<()> {
        self.send(Command::MailFrom(from.clone()))
    }
    fn reply_mail_from(&mut self, from: &String) -> SmtpResult<()> {
        match self.recv_line()?.code {
            StatusCode::Okay => Ok(()),
            StatusCode::NoAccess => Err(SmtpErr::Policy),
            StatusCode::MailBoxNameNotAllowed => Err(SmtpErr::MailBoxName(from.to_string())),
            _ => Err(SmtpErr::Protocol),
        }
    }
    fn command_mail_to(&mut self, to: &String) -> SmtpResult<()> {
        self.send(Command::RcptTo(to.clone()))
    }
    fn reply_mail_to(&mut self, to: &String) -> SmtpResult<()> {
        let line = self.recv_line()?;
        match line.code {
            StatusCode::Okay | StatusCode::UserNotLocal => Ok(()),
            StatusCode::NoAccess | StatusCode::MailboxUnavailable => Err(SmtpErr::Policy),
            StatusCode::MailBoxNameNotAllowed => Err(SmtpErr::MailBoxName(to.to_string())),
            StatusCode::UserNotLocalError => Err(SmtpErr::Forward(line.text.clone())),
            _ => Err(SmtpErr::Protocol),
        }
    }
    fn command_mail_data(&mut self) -> SmtpResult<()> {
        self.send(Command::Data)
    }
    fn reply_mail_data(&mut self) -> SmtpResult<()> {
        self.recv_line()?.expect(StatusCode::StartMailInput)
    }
    fn command_mail_payload(&mut self, mail: &Mail) -> SmtpResult<()> {
        self.write(
            format!(
                "From: {}<{}>\r\n",
                mail.from_name.as_ref().unwrap_or(&"".to_string()),
                mail.from
            )
            .as_bytes(),
        )?;
        self.write(
            format!(
                "To: {}<{}>\r\n",
                mail.to_name.as_ref().unwrap_or(&"".to_string()),
                mail.to
            )
            .as_bytes(),
        )?;
        self.write(format!("Subject: {}\r\n", mail.subject).as_bytes())?;
        self.write("\r\n".as_bytes())?;
        self.write(mail.text.as_bytes())?;
        self.write("\r\n.\r\n".as_bytes())
    }
    fn reply_mail_payload(&mut self) -> SmtpResult<()> {
        match self.recv_line()?.code {
            StatusCode::Okay => Ok(()),
            StatusCode::NoAccess | StatusCode::MailboxUnavailable => Err(SmtpErr::Policy),
            _ => Err(SmtpErr::Protocol),
        }
    }

    fn try_send_mail(&mut self, mail: &Mail) -> SmtpResult<()> {
        check_address(mail.from.as_str())?;
        check_address(mail.to.as_str())?;
        if self.server.meta.pipelining == Support::Supported {
            self.command_mail_from(&mail.from)?;
            self.command_mail_to(&mail.to)?;
            self.command_mail_data()?;
            self.reply_mail_from(&mail.from)?;
            self.reply_mail_to(&mail.to)?;
            self.reply_mail_data()?;
            self.command_mail_payload(&mail)?;
            self.reply_mail_payload()
        } else {
            self.command_mail_from(&mail.from)?;
            self.reply_mail_from(&mail.from)?;
            self.command_mail_to(&mail.to)?;
            self.reply_mail_to(&mail.to)?;
            self.command_mail_data()?;
            self.reply_mail_data()?;
            self.command_mail_payload(&mail)?;
            self.reply_mail_payload()
        }
    }

    pub fn connect(&mut self, credentials: Credentials) -> SmtpResult<()> {
        let mut retries = self.config.retries;
        loop {
            match self.try_connect(credentials.clone()) {
                Ok(_) => {
                    return Ok(());
                }
                Err(e) => {
                    if e.retriable() && retries > 0 {
                        retries = retries - 1;
                    } else {
                        return Err(e);
                    }
                }
            }
        }
    }

    pub fn close(&mut self) -> SmtpResult<()> {
        let mut retries = self.config.retries;
        loop {
            match self.try_close() {
                Ok(_) => {
                    return Ok(());
                }
                Err(e) => {
                    if e.retriable() && retries > 0 {
                        retries = retries - 1;
                    } else {
                        return Err(e);
                    }
                }
            }
        }
    }

    pub fn send_mail(&mut self, mail: &Mail) -> SmtpResult<()> {
        let mut retries = self.config.retries;
        loop {
            match self.try_send_mail(&mail) {
                Ok(_) => {
                    return Ok(());
                }
                Err(e) => {
                    if e.retriable() && retries > 0 {
                        retries = retries - 1;
                    } else {
                        return Err(e);
                    }
                }
            }
        }
    }
}

pub struct Mailer<L>
where
    L: Logger,
{
    config: Config,
    server: Server,
    logger: L,
}

impl<L> Mailer<L>
where
    L: Logger,
{
    pub fn new(server: Server, config: Config, logger: L) -> Mailer<L> {
        Mailer {
            server,
            config,
            logger,
        }
    }

    fn address_resolve(&mut self) -> SmtpResult<SocketAddr> {
        format!("{}:{}", self.server.address, self.server.port)
            .to_socket_addrs()
            .map_err(|_| SmtpErr::DNS)?
            .next()
            .ok_or(SmtpErr::DNS)
    }

    pub fn connect(&mut self, credentials: Credentials) -> SmtpResult<MailerConnection<L>> {
        let address = self.address_resolve()?;
        let client = TcpStream::connect_timeout(&address, Duration::new(self.config.timeout, 0))
            .map_err(|_| SmtpErr::ServerUnreachable)?;

        let mut mailer = MailerConnection::new(
            self.server.clone(),
            self.config.clone(),
            client,
            self.logger.clone(),
        );

        mailer.connect(credentials)?;
        Ok(mailer)
    }
}

/*
    todo:
        MIME-UTF8
        ! dot stuffing
*/
