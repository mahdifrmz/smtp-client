mod connection;

use std::{
    cmp::min,
    net::{SocketAddr, TcpStream, ToSocketAddrs},
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

use connection::MailerConnection;

pub enum SmtpEvent {
    Connected,
    FailedToConnect(SmtpErr),
    Disconnencted,
    FailToDisconnect(SmtpErr),
    Retry,
    MailSent {
        subject: String,
        to: String,
    },
    FailedToSendMail {
        subject: String,
        to: String,
        error: SmtpErr,
    },
}

pub trait Logger: Clone + Send + Sync {
    fn client(&mut self, data: &[u8]);
    fn server(&mut self, data: &[u8]);
    fn disable(&mut self);
    fn enable(&mut self);
    fn event(&self, event: SmtpEvent);
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
    pub auto_quit: bool,
}

impl Config {
    pub fn new() -> Config {
        Config {
            retries: 0,
            timeout: 5,
            parallel: false,
            max_channels: 8,
            auto_quit: false,
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
    pub fn auto_quit<'a>(&'a mut self, value: bool) -> &'a mut Config {
        self.auto_quit = value;
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

pub fn check_address(address: &str) -> SmtpResult<()> {
    regex::Regex::new(
        r"^([a-z0-9_+]([a-z0-9_+.]*[a-z0-9_+])?)@([a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,6})",
    )
    .unwrap()
    .captures(address)
    .map(|_| ())
    .ok_or(SmtpErr::MailBoxName(address.to_string()))
}

#[derive(Clone)]
pub struct Mailer<L>
where
    L: Logger + 'static,
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

    fn address_resolve(&self) -> SmtpResult<SocketAddr> {
        format!("{}:{}", self.server.address, self.server.port)
            .to_socket_addrs()
            .map_err(|_| SmtpErr::DNS)?
            .next()
            .ok_or(SmtpErr::DNS)
    }

    pub fn connect(&self, credentials: Credentials) -> SmtpResult<MailerConnection<L>> {
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

    fn post_serial(
        &self,
        credentials: Credentials,
        mails: Vec<Mail>,
    ) -> SmtpResult<Vec<SmtpResult<()>>> {
        let mut con = match self.connect(credentials) {
            Ok(con) => con,
            Err(e) => {
                self.logger.event(SmtpEvent::FailedToConnect(e.clone()));
                return Err(e);
            }
        };
        self.logger.event(SmtpEvent::Connected);
        let mut mails = mails;
        let results = mails
            .drain(..)
            .map(|mail| {
                if let Err(e) = con.send_mail(&mail) {
                    self.logger.event(SmtpEvent::FailedToSendMail {
                        subject: mail.subject.clone(),
                        to: mail.to.clone(),
                        error: e.clone(),
                    });
                    Err(e)
                } else {
                    self.logger.event(SmtpEvent::MailSent {
                        subject: mail.subject.clone(),
                        to: mail.to.clone(),
                    });
                    Ok(())
                }
            })
            .collect::<Vec<_>>();
        match con.close() {
            Ok(_) => {
                self.logger.event(SmtpEvent::Disconnencted);
                Ok(results)
            }
            Err(e) => {
                self.logger.event(SmtpEvent::FailToDisconnect(e));
                Ok(results)
            }
        }
    }

    fn post_channel(
        &mut self,
        credentials: Credentials,
        mails: Arc<Mutex<Vec<Mail>>>,
        results: Arc<Mutex<Vec<SmtpResult<()>>>>,
    ) -> bool {
        let mut con = match self.connect(credentials) {
            Ok(con) => con,
            Err(e) => {
                self.logger.event(SmtpEvent::FailedToConnect(e));
                return false;
            }
        };
        self.logger.event(SmtpEvent::Connected);
        loop {
            let mut guard = mails.lock().unwrap();
            let m = guard.pop();
            let idx = guard.len();
            drop(guard);
            match m {
                Some(mail) => {
                    if let Err(e) = con.send_mail(&mail) {
                        self.logger.event(SmtpEvent::FailedToSendMail {
                            subject: mail.subject.clone(),
                            to: mail.to.clone(),
                            error: e.clone(),
                        });
                        results.lock().unwrap()[idx] = Err(e);
                    } else {
                        self.logger.event(SmtpEvent::MailSent {
                            subject: mail.subject.clone(),
                            to: mail.to.clone(),
                        });
                    }
                }
                None => break,
            }
        }
        match con.close() {
            Ok(_) => {
                self.logger.event(SmtpEvent::Disconnencted);
            }
            Err(e) => {
                self.logger.event(SmtpEvent::FailToDisconnect(e));
            }
        }
        return true;
    }

    fn post_parallel(
        &self,
        credentials: Credentials,
        mails: Vec<Mail>,
    ) -> SmtpResult<Vec<SmtpResult<()>>> {
        let mail_count = mails.len();
        let thread_count = min(self.config.max_channels, mail_count as u32);
        let mails = Arc::new(Mutex::new(mails));
        let results = Arc::new(Mutex::new(
            (0..mail_count).map(|_| Ok(())).collect::<Vec<_>>(),
        ));
        let mut handlers = (0..thread_count)
            .map(|_| {
                let mut mailer = self.clone();
                let credentials = credentials.clone();
                let mails = mails.clone();
                let results = results.clone();
                thread::spawn(move || mailer.post_channel(credentials, mails, results))
            })
            .collect::<Vec<_>>();

        let success = handlers.drain(..).fold(false, |success, handle| {
            let s = handle.join().unwrap();
            success || s
        });

        if success {
            let results = Arc::try_unwrap(results).unwrap();
            let results = std::mem::take(results.lock().unwrap().as_mut());
            Ok(results)
        } else {
            Err(SmtpErr::ServerUnreachable)
        }
    }

    pub fn post(
        &self,
        credentials: Credentials,
        mails: Vec<Mail>,
    ) -> SmtpResult<Vec<SmtpResult<()>>> {
        if self.config.parallel {
            self.post_parallel(credentials, mails)
        } else {
            self.post_serial(credentials, mails)
        }
    }
}
