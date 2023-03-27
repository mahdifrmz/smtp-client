use smtp::{Config, Credentials, Logger, MailFile, Mailer, Server, SmtpErr};
use std::{
    env::args,
    fs,
    io::{self, Write},
    process::exit,
};

fn prompt_password(username: &String) -> String {
    let mut buffer = String::new();
    println!("Enter password for {}:", username);
    let _ = io::stdin().read_line(&mut buffer);
    buffer
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

fn main() {
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

    let logger = if let Some(logfile) = mail_file
        .config
        .as_ref()
        .map(|c| c.logfile.clone())
        .flatten()
    {
        FileLogger::new(&logfile)
    } else {
        FileLogger::none()
    };

    let server = Server::from(&mail_file.server);
    let config = if let Some(cfg) = mail_file.config.as_ref() {
        Config::from(cfg)
    } else {
        Config::new()
    };

    if let Err(e) = (|| -> Result<(), SmtpErr> {
        let mut mailer = Mailer::new(server, config, logger);
        mailer.connect(Credentials::new(username, password))?;

        for mail in mail_file.mails() {
            mailer.send_mail(mail)?;
        }
        mailer.disconnect()?;

        Ok(())
    })() {
        let mes = match e {
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
        };

        eprintln!("Error: {}", mes);
        exit(1);
    }
}
