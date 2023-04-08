use base64::{engine::general_purpose, Engine};

use crate::{Error, Result};

#[derive(PartialEq, Eq, Clone, Copy)]
pub enum StatusCode {
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

pub fn status_code(code: u32) -> Option<StatusCode> {
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

pub struct Line {
    code: StatusCode,
    text: String,
    last: bool,
}

impl Line {
    pub fn new(code: StatusCode, text: String, last: bool) -> Line {
        Line { code, text, last }
    }

    pub fn expect(&self, code: StatusCode) -> Result<()> {
        if self.code != code {
            Err(Error::Protocol)
        } else {
            Ok(())
        }
    }
    pub fn code(&self) -> StatusCode {
        return self.code;
    }
    pub fn text(&self) -> String {
        return self.text.clone();
    }
    pub fn last(&self) -> bool {
        self.last
    }
}

pub enum EhloLine {
    Pipelining,
    StartTls,
    EightBitMIME,
    Auth,
}

pub enum AuthMech {
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

pub enum Command {
    Ehlo(String),
    Quit,
    StartTls,
    MailFrom(String),
    RcptTo(String),
    Data,
    AuthPlain(String, String),
    AuthLogin,
}

pub fn get_auth_plain(username: &str, password: &str) -> String {
    let mut s = vec![];
    s.push(0u8);
    s.append(&mut username.chars().map(|c| c as u8).collect());
    s.push(0u8);
    s.append(&mut password.chars().map(|c| c as u8).collect());
    general_purpose::STANDARD.encode(s)
}

pub fn get_auth_login(token: &str) -> String {
    general_purpose::STANDARD.encode(token)
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
