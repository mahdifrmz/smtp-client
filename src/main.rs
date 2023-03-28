mod input;
mod logger;

use input::MailFile;
use smtp::{Config, Credentials, Mail, Mailer, Server, SmtpErr};
use std::{env::args, fs, process::exit, sync::mpsc::channel};

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

fn try_send_mail(mailer: &mut Mailer<logger::FileLogger>, mail: &Mail, retries: u32) -> bool {
    let mut retries = retries;
    loop {
        match mailer.send_mail(&mail) {
            Ok(_) => {
                println!("--> sent [{}] to <{}>.", &mail.subject, &mail.to);
                return true;
            }
            Err(e) => {
                eprintln!(
                    "--> sending [{}] to <{}> failed:\n{}",
                    &mail.subject,
                    &mail.to,
                    get_error_message(e.clone())
                );
                if e.retriable() && retries > 0 {
                    eprintln!("--> retrying...");
                    retries = retries - 1;
                } else {
                    return false;
                }
            }
        }
    }
}

fn try_connect(
    mailer: &mut Mailer<logger::FileLogger>,
    credentials: Credentials,
    retries: u32,
) -> bool {
    let mut retries = retries;
    loop {
        match mailer.connect(credentials.clone()) {
            Ok(_) => {
                println!("connected to server.");
                return true;
            }
            Err(e) => {
                eprintln!("connecting failed:\n{}", get_error_message(e.clone()));
                if e.retriable() && retries > 0 {
                    eprintln!("retrying...");
                    retries = retries - 1;
                } else {
                    return false;
                }
            }
        }
    }
}

fn try_disconnect(mailer: &mut Mailer<logger::FileLogger>) {
    if let Ok(()) = mailer.disconnect() {
        println!("connection closed.");
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

    let retries = config.retries;
    let parallel = config.parallel;
    let thread_count = config.max_channels;

    if !parallel {
        let mut mailer = Mailer::new(server, config, logger::FileLogger::new(logfile));
        let mut success = true;
        if !try_connect(&mut mailer, credentials, retries) {
            exit(1);
        }
        for mail in mails {
            success = success && try_send_mail(&mut mailer, &mail, retries);
        }
        try_disconnect(&mut mailer);
        if !success {
            exit(1);
        }
    } else {
        let threadpool = threadpool::ThreadPool::new(thread_count as usize);
        let (tx, rx) = channel();
        let mut mail_count = 0;
        for mail in mails {
            mail_count = mail_count + 1;
            let logger = logger::FileLogger::new(logfile.clone());
            let credentials = credentials.clone();
            let config = config.clone();
            let server = server.clone();
            let tx = tx.clone();
            threadpool.execute(move || {
                let mut mailer = Mailer::new(server, config, logger);
                if !try_connect(&mut mailer, credentials, retries) {
                    let _ = tx.send(false);
                    return;
                }
                let success = try_send_mail(&mut mailer, &mail, retries);
                try_disconnect(&mut mailer);
                let _ = tx.send(success);
            });
        }
        let mut success = true;
        for _ in 0..mail_count {
            success = success && rx.recv().unwrap();
        }
        if !success {
            exit(1);
        }
    }
}
