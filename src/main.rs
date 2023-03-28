mod input;
mod logger;

use input::MailFile;
use smtp::{Config, Credentials, Mail, Mailer, Server, SmtpErr};
use std::{
    cmp::min,
    env::args,
    fs,
    process::exit,
    sync::{Arc, Mutex},
    thread,
};

use crate::logger::FileLogger;

fn get_error_message(error: SmtpErr) -> String {
    match error {
        SmtpErr::File(path) => format!("Failed to open file: {}", path),
        SmtpErr::Protocol => "There was an error on the mail server side.".to_string(),
        SmtpErr::MailBoxName(mailbox) => format!("Invalid email address <{}>", mailbox),
        SmtpErr::ServerUnreachable => "Can't reach the server, try again later.".to_string(),
        SmtpErr::ServerUnavailable => "Server abruptly ended the connection.".to_string(),
        SmtpErr::InvalidServer => {
            "The server address you entered probably is not an SMTP one.".to_string()
        }
        SmtpErr::Network => "Disconnected due to a network issues.".to_string(),
        SmtpErr::DNS => "Failed to resolve hostname.".to_string(),
        SmtpErr::InvalidCred => "The credentials you entered were invalidated by the server. \
Make sure about the entered username and password."
            .to_string(),
        SmtpErr::Policy => "The Mail request was rejected by the server due to some policy. \
Can't send the mail."
            .to_string(),
        SmtpErr::Forward(mes) => format!(
            "The entered address was an old one. \
Here's the message from the server: {}",
            mes
        )
        .to_string(),
    }
}

mod message {

    use crate::get_error_message;
    use smtp::{Mail, SmtpErr};

    pub fn connected() {
        println!("connected to server.");
    }
    pub fn disconnect() {
        println!("connection closed.");
    }
    pub fn connection_failed(error: SmtpErr) {
        eprintln!("connecting failed:\n{}", get_error_message(error.clone()));
    }
    pub fn mail_sent(mail: &Mail) {
        println!("--> sent [{}] to <{}>.", &mail.subject, &mail.to);
    }
    pub fn mail_failed(mail: &Mail, error: &SmtpErr) {
        eprintln!(
            "--> sending [{}] to <{}> failed:\n{}",
            &mail.subject,
            &mail.to,
            get_error_message(error.clone())
        );
    }
}

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

    let parallel = config.parallel;
    let thread_count = min(config.max_channels, mails.len() as u32);

    if !parallel {
        let mut mailer = Mailer::new(server, config, logger::FileLogger::new(logfile));
        let mut success = true;
        let mut con = match mailer.connect(credentials) {
            Ok(con) => con,
            Err(e) => {
                message::connection_failed(e);
                exit(1);
            }
        };
        message::connected();
        for mail in mails {
            if let Err(e) = con.send_mail(&mail) {
                success = false;
                message::mail_failed(&mail, &e);
            } else {
                message::mail_sent(&mail);
            }
        }
        if con.close().is_ok() {
            message::disconnect();
        }
        if !success {
            exit(1);
        }
    } else {
        let mails = Arc::new(Mutex::new(mails));
        let mut handles = (0..thread_count)
            .map(|_| {
                let server = server.clone();
                let config = config.clone();
                let credentials = credentials.clone();
                let mails = mails.clone();
                let handle = thread::spawn(move || {
                    let mut mailer = Mailer::new(server, config, FileLogger::none());
                    let mut con = match mailer.connect(credentials) {
                        Ok(con) => con,
                        Err(e) => {
                            message::connection_failed(e);
                            return false;
                        }
                    };
                    message::connected();
                    let mut success = true;
                    loop {
                        let m = mails.lock().unwrap().pop();
                        match m {
                            Some(mail) => {
                                match con.send_mail(&mail) {
                                    Ok(_) => message::mail_sent(&mail),
                                    Err(e) => {
                                        success = false;
                                        message::mail_failed(&mail, &e)
                                    }
                                };
                            }
                            None => break,
                        }
                    }
                    if con.close().is_ok() {
                        message::disconnect();
                    }
                    success
                });
                handle
            })
            .collect::<Vec<_>>();

        let success = handles
            .drain(..)
            .map(|h| h.join().unwrap())
            .fold(true, |a, b| a && b);
        if !success {
            exit(1);
        }
    }
}
