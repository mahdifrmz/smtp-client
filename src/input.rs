use serde_derive::Deserialize;

use crate::{Config, Credentials, Mail, Server};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailConfig {
    pub retries: Option<u32>,
    pub timeout: Option<u64>,
    pub parallel: Option<bool>,
    pub logfile: Option<String>,
    #[serde(rename = "max-channels")]
    pub max_channels: Option<u32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailEntry {
    address: String,
    name: Option<String>,
    subject: String,
    text: String,
    attach: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailUser {
    pub address: String,
    name: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailServer {
    address: String,
    port: u16,
}

impl From<&MailServer> for Server {
    fn from(mail_server: &MailServer) -> Self {
        Server::new(mail_server.address.clone(), mail_server.port)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailFile {
    pub user: MailUser,
    pub server: MailServer,
    pub config: Option<MailConfig>,
    #[serde(rename = "mail")]
    pub mails: Option<Vec<MailEntry>>,
}

fn prompt_password(username: &String) -> String {
    println!("Enter password for {}:", username);
    rpassword::read_password().unwrap()
}

impl MailConfig {
    pub fn destruct(self) -> (Config, Option<String>) {
        let mut config = Config::new();
        let mut logfile = None;

        if let Some(value) = self.timeout {
            config.timeout(value);
        }
        if let Some(value) = self.retries {
            config.retires(value);
        }
        if let Some(value) = self.logfile {
            logfile = Some(value);
        }

        (config, logfile)
    }
}

impl MailServer {
    pub fn destruct(self) -> Server {
        Server::new(self.address, self.port)
    }
}

impl MailFile {
    pub fn destruct(mut self) -> (Server, Vec<Mail>, Config, Option<String>, Credentials) {
        let mut mails = vec![];

        let (config, logfile) = if let Some(cfg) = self.config.take() {
            cfg.destruct()
        } else {
            (Config::new(), None)
        };

        let username = self
            .user
            .username
            .clone()
            .unwrap_or(self.user.address.clone());

        let password = self
            .user
            .password
            .clone()
            .unwrap_or_else(|| prompt_password(&username));

        let server = self.server.destruct();

        if let Some(mut file_mails) = self.mails.take() {
            for m in file_mails.drain(..) {
                let mail = Mail {
                    from: self.user.address.clone(),
                    from_name: self.user.name.clone(),
                    to: m.address,
                    to_name: m.name,
                    subject: m.subject,
                    text: m.text,
                    attachments: m.attach.unwrap_or(vec![]),
                };
                mails.push(mail);
            }
        }
        (
            server,
            mails,
            config,
            logfile,
            Credentials::new(username, password),
        )
    }
}
