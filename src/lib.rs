mod input;

use std::{
    io::{Read, Write},
    net::TcpStream,
    sync::Arc,
    time::Duration,
};

pub use input::MailFile;

use base64::{engine::general_purpose, Engine};
use input::MailConfig;
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

pub trait Logger {
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

#[derive(Debug)]
pub enum SmtpErr {
    Protocol,
    ServerUnreachable,
    ServerUnavailable,
    InvalidServer,
    Network,
    InvalidCred,
    Policy,
    MailBoxName(String),
    Forward(String),
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
}

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

pub struct Config {
    retries: u32,
    timeout: u64,
    parallel: bool,
    max_channels: u32,
}

impl From<&MailConfig> for Config {
    fn from(value: &MailConfig) -> Self {
        let def = Config::new();
        Config {
            retries: value.retries.unwrap_or(def.retries),
            timeout: value.timeout.unwrap_or(def.timeout),
            parallel: value.parallel.unwrap_or(def.parallel),
            max_channels: value.max_channels.unwrap_or(def.max_channels),
        }
    }
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

pub struct Mailer<L>
where
    L: Logger,
{
    name: String,
    config: Config,
    server: Server,
    tlscon: Option<TlsCon>,
    stream: Option<TcpStream>,
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
    AuthSuccess = 235,
    Okay = 250,
    UserNotLocal = 251,
    CanNotVrfyButWillAttemp = 252,
    StartMailInput = 354,
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
}

impl ToString for AuthMech {
    fn to_string(&self) -> String {
        (match self {
            AuthMech::Plain => "PLAIN",
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

impl<L> Mailer<L>
where
    L: Logger,
{
    pub fn new(server: Server, config: Config, logger: L) -> Mailer<L> {
        Mailer {
            name: "me".to_string(),
            server,
            config,
            tlscon: None,
            stream: None,
            logger,
        }
    }
    fn stream(&mut self) -> &mut TcpStream {
        self.stream.as_mut().unwrap()
    }
    fn recv_reply(&mut self) -> SmtpResult<Vec<Line>> {
        let lines = if self.is_tls() {
            let mut tlscon = self.tlscon.take().unwrap();
            let mut tls = rustls::Stream::new(&mut tlscon, self.stream.as_mut().unwrap());
            let lines = stream_recv_reply(&mut tls, &mut self.logger)?;
            self.tlscon = Some(tlscon);
            lines
        } else {
            stream_recv_reply(self.stream.as_mut().unwrap(), &mut self.logger)?
        };
        for l in lines.iter() {
            if l.code == StatusCode::ServiceNotAvailable {
                self.close();
                return Err(SmtpErr::ServerUnavailable);
            }
        }
        Ok(lines)
    }
    fn recv_line(&mut self) -> SmtpResult<Line> {
        let line = if self.is_tls() {
            let mut tlscon = self.tlscon.take().unwrap();
            let mut tls = rustls::Stream::new(&mut tlscon, self.stream.as_mut().unwrap());
            let line = stream_recv_line(&mut tls, &mut self.logger)?;
            self.tlscon = Some(tlscon);
            line
        } else {
            stream_recv_line(self.stream.as_mut().unwrap(), &mut self.logger)?
        };
        if line.code == StatusCode::ServiceNotAvailable {
            self.close();
            Err(SmtpErr::ServerUnavailable)
        } else {
            Ok(line)
        }
    }
    fn write(&mut self, data: &[u8]) -> SmtpResult<()> {
        self.logger.client(data);
        if self.is_tls() {
            let mut tlscon = self.tlscon.take().unwrap();
            rustls::Stream::new(&mut tlscon, self.stream())
                .write(data)
                .map_err(|_| SmtpErr::Network)?;
            self.tlscon = Some(tlscon);
        } else {
            self.stream().write(data).map_err(|_| SmtpErr::Network)?;
        }
        Ok(())
    }
    fn send(&mut self, cmd: Command) -> SmtpResult<()> {
        self.write(cmd.to_string().as_bytes())
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
        rustls::Stream::new(&mut con, self.stream());
        self.tlscon = Some(con);
        Ok(())
    }
    fn auth_plain(&mut self, credentials: Credentials) -> SmtpResult<()> {
        self.send(Command::AuthPlain(
            credentials.username.clone(),
            credentials.password.clone(),
        ))?;
        let cc = self.recv_line()?.code;
        match cc {
            StatusCode::AuthSuccess => Ok(()),
            StatusCode::AuthInvalidCred => Err(SmtpErr::InvalidCred),
            _ => Err(SmtpErr::Protocol),
        }
    }
    pub fn connect(&mut self, credentials: Credentials) -> SmtpResult<()> {
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
    fn close(&mut self) {
        if let Some(stream) = self.stream.as_mut() {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
        self.stream.take();
        self.tlscon.take();
        self.server.meta = ServerMeta::new();
    }
    pub fn disconnect(&mut self) -> SmtpResult<()> {
        if self.stream.is_some() {
            self.send(Command::Quit)?;
        }
        self.recv_line()?
            .expect(StatusCode::ServiceClosingChannel)?;
        self.close();
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
    pub fn command_mail_payload(&mut self, mail: &Mail) -> SmtpResult<()> {
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
    pub fn reply_mail_payload(&mut self, mail: &Mail) -> SmtpResult<()> {
        match self.recv_line()?.code {
            StatusCode::Okay => Ok(()),
            StatusCode::NoAccess | StatusCode::MailboxUnavailable => Err(SmtpErr::Policy),
            _ => Err(SmtpErr::Protocol),
        }
    }

    pub fn send_mail(&mut self, mail: Mail) -> SmtpResult<()> {
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
            self.reply_mail_payload(&mail)
        } else {
            self.command_mail_from(&mail.from)?;
            self.reply_mail_from(&mail.from)?;
            self.command_mail_to(&mail.to)?;
            self.reply_mail_to(&mail.to)?;
            self.command_mail_data()?;
            self.reply_mail_data()?;
            self.command_mail_payload(&mail)?;
            self.reply_mail_payload(&mail)
        }
    }
}

/*
    todo:
        MORE AUTH METHODS
        UTF8
        MIME
        ! buffering
        ! dot stuffing
        ! transaction-failed
        ! connect-timeout
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
