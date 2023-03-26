use serde_derive::Deserialize;
use smtp::{Credentials, Mail, Mailer, Server};
use std::{env::args, fs, io, process::exit};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MailConfig {
    retries: Option<u32>,
    timeout: Option<u32>,
    parallel: Option<bool>,
    #[serde(rename = "max-channels")]
    max_channels: Option<u32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MailEntry {
    address: String,
    name: Option<String>,
    subject: String,
    text: String,
    attach: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MailUser {
    address: String,
    name: Option<String>,
    username: Option<String>,
    password: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MailServer {
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
struct MailFile {
    user: MailUser,
    server: MailServer,
    config: Option<MailConfig>,
    #[serde(rename = "mail")]
    mails: Option<Vec<MailEntry>>,
}

impl MailFile {
    fn mails(&self) -> Vec<Mail> {
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

fn prompt_password(username: &String) -> String {
    let mut buffer = String::new();
    println!("Enter password for {}:", username);
    io::stdin().read_line(&mut buffer).unwrap();
    buffer
}

fn main() {
    let args: Vec<String> = args().collect();
    if args.len() < 2 {
        exit(1);
    }
    let mail_file = args[1].clone();
    let mail_file = fs::read_to_string(mail_file.clone())
        .expect(format!("failed to open file: {}", mail_file).as_str());

    let mail_file: MailFile = toml::from_str(mail_file.as_str()).unwrap();
    let username = mail_file
        .user
        .username
        .clone()
        .unwrap_or(mail_file.user.address.clone());

    let password = mail_file
        .user
        .password
        .clone()
        .unwrap_or_else(|| prompt_password(&username));

    let mut mailer = Mailer::new(Server::from(&mail_file.server));
    mailer
        .connect(Credentials::new(username, password))
        .unwrap();
    for mail in mail_file.mails() {
        mailer.send_mail(mail).unwrap();
    }
    mailer.disconnect().unwrap();
}
