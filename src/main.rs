mod input;
mod logger;

use input::MailFile;
use smtp::{Config, Credentials, Mail, Mailer, Server};
use std::{env::args, fs, process::exit};

use crate::logger::FileLogger;

fn main() {
    println!("Smtp Client v0.1.0");
    let args: Vec<String> = args().collect();
    if args.len() < 2 {
        exit(1);
    }
    let mail_file = args[1].clone();
    let mail_file = fs::read_to_string(mail_file.clone())
        .expect(format!("failed to open file: {}", mail_file).as_str());

    let mail_file: MailFile = toml::from_str(mail_file.as_str()).unwrap_or_else(|e| {
        eprintln!("mail file error: {}", e.message());
        exit(1)
    });

    let (server, mails, config, logfile, credentials) = mail_file.destruct();
    let _ = Mailer::new(server, config, FileLogger::new(logfile)).post(credentials, mails);
}
