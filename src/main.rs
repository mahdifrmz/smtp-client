use smtp::{Config, Credentials, Logger, Mail, MailFile, Mailer, Server, SmtpErr};
use std::{env::args, fs, io::Write, process::exit, sync::mpsc::channel};

fn prompt_password(username: &String) -> String {
    println!("Enter password for {}:", username);
    rpassword::read_password().unwrap()
}

struct FileLogger {
    enabled: bool,
    file: Option<fs::File>,
    is_client: bool,
    is_server: bool,
}

impl FileLogger {
    fn new(path: &String) -> FileLogger {
        let file = fs::OpenOptions::new()
            .truncate(true)
            .write(true)
            .create(true)
            .open(path)
            .expect(format!("failed to open file: {}", path).as_str());
        FileLogger {
            enabled: true,
            file: Some(file),
            is_client: false,
            is_server: false,
        }
    }
    fn none() -> FileLogger {
        FileLogger {
            enabled: false,
            file: None,
            is_client: false,
            is_server: false,
        }
    }
}

impl Logger for FileLogger {
    fn client(&mut self, data: &[u8]) {
        let file = if let Some(f) = self.file.as_mut() {
            f
        } else {
            return;
        };

        if self.enabled {
            if !self.is_client {
                self.is_client = true;
                self.is_server = false;
                let _ = file.write("C: ".as_bytes());
            }
            let _ = file.write(data);
        }
    }

    fn server(&mut self, data: &[u8]) {
        let file = if let Some(f) = self.file.as_mut() {
            f
        } else {
            return;
        };

        if self.enabled {
            if !self.is_server {
                self.is_server = true;
                self.is_client = false;
                let _ = file.write("S: ".as_bytes());
            }
            let _ = file.write(data);
        }
    }

    fn disable(&mut self) {
        self.enabled = false;
    }

    fn enable(&mut self) {
        self.enabled = true;
    }
}

impl Drop for FileLogger {
    fn drop(&mut self) {
        if let Some(file) = self.file.as_mut() {
            let _ = file.flush();
        }
    }
}

fn get_error_message(error: SmtpErr) -> String {
    match error {
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

fn try_send_mail(mailer: &mut Mailer<FileLogger>, mail: &Mail, retries: u32) -> bool {
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

fn try_connect(mailer: &mut Mailer<FileLogger>, credentials: Credentials, retries: u32) -> bool {
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

fn try_disconnect(mailer: &mut Mailer<FileLogger>) {
    if let Ok(()) = mailer.disconnect() {
        println!("connection closed.");
    }
}

fn create_logger(mail_file: &MailFile) -> FileLogger {
    if let Some(logfile) = mail_file
        .config
        .as_ref()
        .map(|c| c.logfile.clone())
        .flatten()
    {
        FileLogger::new(&logfile)
    } else {
        FileLogger::none()
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

    let server = Server::from(&mail_file.server);
    let config = if let Some(cfg) = mail_file.config.as_ref() {
        Config::from(cfg)
    } else {
        Config::new()
    };
    let retries = config.retries;
    let parallel = config.parallel;
    let thread_count = config.max_channels;

    if !parallel {
        let mut mailer = Mailer::new(server, config, create_logger(&mail_file));
        let mut success = true;
        if !try_connect(&mut mailer, Credentials::new(username, password), retries) {
            exit(1);
        }
        for mail in mail_file.mails() {
            if !try_send_mail(&mut mailer, &mail, retries) {
                success = false;
            }
        }
        try_disconnect(&mut mailer);
        if !success {
            exit(1);
        }
    } else {
        let threadpool = threadpool::ThreadPool::new(thread_count as usize);
        let (tx, rx) = channel();
        let mut mail_count = 0;
        for mail in mail_file.mails() {
            mail_count = mail_count + 1;
            let logger = create_logger(&mail_file);
            let config = config.clone();
            let server = server.clone();
            let username = username.clone();
            let password = password.clone();
            let tx = tx.clone();
            threadpool.execute(move || {
                let mut mailer = Mailer::new(server, config, logger);
                if !try_connect(&mut mailer, Credentials::new(username, password), retries) {
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
            if !rx.recv().unwrap() {
                success = false;
            }
        }
        if !success {
            exit(1);
        }
    }
}
