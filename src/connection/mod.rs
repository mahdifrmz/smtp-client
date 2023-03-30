mod parser;
mod protocol;

use super::{
    check_address, Config, Credentials, Logger, Mail, Server, ServerMeta, SmtpErr, SmtpResult,
    Support,
};
use protocol::{get_auth_login, AuthMech, Command, EhloLine, Line, StatusCode};
use rustls;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

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

fn stream_recv_reply<T>(stream: &mut T, logger: &mut impl Logger) -> SmtpResult<Vec<Line>>
where
    T: Read,
{
    let mut parser = parser::Parser::new(stream, logger);
    parser.recv_reply()
}
fn stream_recv_line<T>(stream: &mut T, logger: &mut impl Logger) -> SmtpResult<Line>
where
    T: Read,
{
    let mut parser = parser::Parser::new(stream, logger);
    let line = parser.recv_line()?;
    if !line.last() {
        parser.recv_reply()?;
    }
    Ok(line)
}

pub struct MailerConnection<L>
where
    L: Logger,
{
    pub(crate) name: String,
    pub(crate) config: Config,
    pub(crate) server: Server,
    pub(crate) tlscon: Option<TlsCon>,
    pub(crate) stream: TcpStream,
    pub(crate) logger: L,
}

impl<L> MailerConnection<L>
where
    L: Logger,
{
    pub(crate) fn new(
        server: Server,
        config: Config,
        stream: TcpStream,
        logger: L,
    ) -> MailerConnection<L> {
        MailerConnection {
            name: "me".to_string(),
            server,
            config,
            tlscon: None,
            stream,
            logger,
        }
    }
    pub(crate) fn recv_reply(&mut self) -> SmtpResult<Vec<Line>> {
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
            if l.code() == StatusCode::ServiceNotAvailable
                || l.code() == StatusCode::TransactionFailed
            {
                self.terminate();
                return Err(SmtpErr::ServerUnavailable);
            }
        }
        Ok(lines)
    }
    pub(crate) fn recv_line(&mut self) -> SmtpResult<Line> {
        let line = if self.is_tls() {
            let mut tlscon = self.tlscon.take().unwrap();
            let mut tls = rustls::Stream::new(&mut tlscon, &mut self.stream);
            let line = stream_recv_line(&mut tls, &mut self.logger)?;
            self.tlscon = Some(tlscon);
            line
        } else {
            stream_recv_line(&mut self.stream, &mut self.logger)?
        };
        if line.code() == StatusCode::ServiceNotAvailable
            || line.code() == StatusCode::TransactionFailed
        {
            self.terminate();
            Err(SmtpErr::ServerUnavailable)
        } else {
            Ok(line)
        }
    }
    pub(crate) fn write(&mut self, data: &[u8]) -> SmtpResult<()> {
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
    pub(crate) fn send(&mut self, cmd: Command) -> SmtpResult<()> {
        self.write(cmd.to_string().as_bytes())
    }
    pub(crate) fn set_time_out(&mut self, seconds: u64) -> SmtpResult<()> {
        self.stream
            .set_read_timeout(Some(Duration::new(seconds, 0)))
            .map_err(|_| SmtpErr::Network)?;
        self.stream
            .set_write_timeout(Some(Duration::new(seconds, 0)))
            .map_err(|_| SmtpErr::Network)?;
        Ok(())
    }

    pub(crate) fn address_resolve(&mut self) -> SmtpResult<SocketAddr> {
        format!("{}:{}", self.server.address, self.server.port)
            .to_socket_addrs()
            .map_err(|_| SmtpErr::DNS)?
            .next()
            .ok_or(SmtpErr::DNS)
    }

    pub(crate) fn init_connection(&mut self) -> SmtpResult<()> {
        let address = self.address_resolve()?;

        let client = TcpStream::connect_timeout(&address, Duration::new(self.config.timeout, 0))
            .map_err(|_| SmtpErr::ServerUnreachable)?;

        self.stream = client;
        self.set_time_out(self.config.timeout)?;

        let rep = self.recv_line().map_err(|_| SmtpErr::InvalidServer)?;
        if rep.code() != StatusCode::ServiceReady {
            Err(SmtpErr::Protocol)
        } else {
            Ok(())
        }
    }
    pub(crate) fn is_tls(&self) -> bool {
        self.tlscon.is_some()
    }
    pub(crate) fn handshake(&mut self) -> SmtpResult<()> {
        let name = self.name.clone();

        self.send(Command::Ehlo(name.clone()))?;
        let rep = self.recv_reply()?;
        self.server.meta.tls = Support::NotSupported;
        if self.is_tls() {
            self.server.meta.auth_plain = Support::NotSupported;
        }

        for l in rep.iter() {
            l.expect(StatusCode::Okay)?;
            let text = l.text().to_uppercase();
            if text == EhloLine::StartTls.to_string() {
                self.server.meta.tls = Support::Supported;
            } else if text == EhloLine::EightBitMIME.to_string() {
                self.server.meta.eight_bit_mime = Support::Supported
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
    pub(crate) fn start_tls(&mut self) -> SmtpResult<()> {
        self.send(Command::StartTls)?;
        self.recv_line()?.expect(StatusCode::ServiceReady)?;
        let mut con = create_tls_conn(self.server.address.as_str());
        rustls::Stream::new(&mut con, &mut self.stream);
        self.tlscon = Some(con);
        Ok(())
    }
    pub(crate) fn reply_auth_result(&mut self) -> SmtpResult<()> {
        let cc = self.recv_line()?.code();
        match cc {
            StatusCode::AuthSuccess => Ok(()),
            StatusCode::AuthInvalidCred | StatusCode::NoAccess => Err(SmtpErr::InvalidCred),
            _ => Err(SmtpErr::Protocol),
        }
    }
    pub(crate) fn auth_plain(&mut self, credentials: Credentials) -> SmtpResult<()> {
        self.send(Command::AuthPlain(
            credentials.username.clone(),
            credentials.password.clone(),
        ))?;
        self.reply_auth_result()
    }
    pub(crate) fn end(&mut self) -> SmtpResult<()> {
        self.write("\r\n".as_bytes())
    }
    pub(crate) fn auth_login(&mut self, credentials: Credentials) -> SmtpResult<()> {
        self.send(Command::AuthLogin)?;
        self.recv_line()?.expect(StatusCode::ServerChallenge)?;
        self.write(get_auth_login(credentials.username.as_str()).as_bytes())?;
        self.end()?;
        self.recv_line()?.expect(StatusCode::ServerChallenge)?;
        self.write(get_auth_login(credentials.password.as_str()).as_bytes())?;
        self.end()?;
        self.reply_auth_result()
    }
    pub(crate) fn try_connect(&mut self, credentials: Credentials) -> SmtpResult<()> {
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
    pub(crate) fn terminate(&mut self) {
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
        self.tlscon.take();
        self.server.meta = ServerMeta::new();
    }
    pub(crate) fn try_close(&mut self) -> SmtpResult<()> {
        self.send(Command::Quit)?;
        self.recv_line()?
            .expect(StatusCode::ServiceClosingChannel)?;
        self.terminate();
        Ok(())
    }
    pub(crate) fn command_mail_from(&mut self, from: &String) -> SmtpResult<()> {
        self.send(Command::MailFrom(from.clone()))
    }
    pub(crate) fn reply_mail_from(&mut self, from: &String) -> SmtpResult<()> {
        match self.recv_line()?.code() {
            StatusCode::Okay => Ok(()),
            StatusCode::NoAccess => Err(SmtpErr::Policy),
            StatusCode::MailBoxNameNotAllowed => Err(SmtpErr::MailBoxName(from.to_string())),
            _ => Err(SmtpErr::Protocol),
        }
    }
    pub(crate) fn command_mail_to(&mut self, to: &String) -> SmtpResult<()> {
        self.send(Command::RcptTo(to.clone()))
    }
    pub(crate) fn reply_mail_to(&mut self, to: &String) -> SmtpResult<()> {
        let line = self.recv_line()?;
        match line.code() {
            StatusCode::Okay | StatusCode::UserNotLocal => Ok(()),
            StatusCode::NoAccess | StatusCode::MailboxUnavailable => Err(SmtpErr::Policy),
            StatusCode::MailBoxNameNotAllowed => Err(SmtpErr::MailBoxName(to.to_string())),
            StatusCode::UserNotLocalError => Err(SmtpErr::Forward(line.text().clone())),
            _ => Err(SmtpErr::Protocol),
        }
    }
    pub(crate) fn command_mail_data(&mut self) -> SmtpResult<()> {
        self.send(Command::Data)
    }
    pub(crate) fn reply_mail_data(&mut self) -> SmtpResult<()> {
        self.recv_line()?.expect(StatusCode::StartMailInput)
    }
    pub(crate) fn command_mail_payload(&mut self, mail: &Mail) -> SmtpResult<()> {
        if self.server.meta.eight_bit_mime == Support::Supported {
            self.write(mail.to_bytes()?.as_slice())?;
        } else {
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
            self.write(mail.final_text().as_bytes())?;
        }
        self.write("\r\n.\r\n".as_bytes())
    }
    pub(crate) fn reply_mail_payload(&mut self) -> SmtpResult<()> {
        match self.recv_line()?.code() {
            StatusCode::Okay => Ok(()),
            StatusCode::NoAccess | StatusCode::MailboxUnavailable => Err(SmtpErr::Policy),
            _ => Err(SmtpErr::Protocol),
        }
    }

    pub(crate) fn try_send_mail(&mut self, mail: &Mail) -> SmtpResult<()> {
        check_address(mail.from.as_str())?;
        check_address(mail.to.as_str())?;
        if mail.attachments.len() > 0 && self.server.meta.eight_bit_mime != Support::Supported {
            return Err(SmtpErr::MIMENotSupported);
        }
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

impl<L: Logger> Drop for MailerConnection<L> {
    fn drop(&mut self) {
        if self.config.auto_quit {
            let _ = self.close();
        }
    }
}
