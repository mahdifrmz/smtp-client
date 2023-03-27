use serde_derive::Deserialize;

use crate::{Mail, Server};

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

impl MailFile {
    pub fn mails(&self) -> Vec<Mail> {
        let mut mails = vec![];

        if let Some(file_mails) = self.mails.as_ref() {
            for m in file_mails.iter() {
                let mail = Mail {
                    from: self.user.address.clone(),
                    from_name: self.user.name.clone(),
                    to: m.address.clone(),
                    to_name: m.name.clone(),
                    subject: m.subject.clone(),
                    text: m.text.clone(),
                };
                mails.push(mail);
            }
        }
        mails
    }
}
