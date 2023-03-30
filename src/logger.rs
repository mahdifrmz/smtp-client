use smtp::{Logger, SmtpErr, SmtpEvent};
use std::io::Write;

use std::fs;

pub(crate) struct FileLogger {
    pub(crate) enabled: bool,
    pub(crate) path: Option<String>,
    pub(crate) file: Option<fs::File>,
    pub(crate) is_client: bool,
    pub(crate) is_server: bool,
}

impl FileLogger {
    fn open(path: String) -> fs::File {
        fs::OpenOptions::new()
            .truncate(true)
            .write(true)
            .create(true)
            .open(path.clone())
            .expect(format!("failed to open file: {}", path).as_str())
    }
    pub(crate) fn file(path: String) -> FileLogger {
        FileLogger {
            enabled: true,
            file: Some(FileLogger::open(path.clone())),
            is_client: false,
            is_server: false,
            path: Some(path),
        }
    }
    pub(crate) fn none() -> FileLogger {
        FileLogger {
            enabled: false,
            file: None,
            is_client: false,
            is_server: false,
            path: None,
        }
    }
    pub(crate) fn new(path: Option<String>) -> FileLogger {
        if let Some(logfile) = path {
            FileLogger::file(logfile)
        } else {
            FileLogger::none()
        }
    }
}

impl Clone for FileLogger {
    fn clone(&self) -> Self {
        let file = if let Some(path) = self.path.clone() {
            Some(FileLogger::open(path))
        } else {
            None
        };
        Self {
            enabled: self.enabled,
            path: self.path.clone(),
            file,
            is_client: self.is_client,
            is_server: self.is_server,
        }
    }
}

impl FileLogger {
    fn get_error_message(&self, error: SmtpErr) -> String {
        match error {
            SmtpErr::File(path) => format!("Failed to open file: {}", path),
            SmtpErr::Protocol => "There was an error on the mail server side.".to_string(),
            SmtpErr::MailBoxName(mailbox) => format!("Invalid email address <{}>", mailbox),
            SmtpErr::ServerUnreachable => "Can't reach the server, try again later.".to_string(),
            SmtpErr::ServerUnavailable => "Server abruptly ended the connection.".to_string(),
            SmtpErr::MIMENotSupported => {
                "MIME not supported by server. Can't send attachments.".to_string()
            }
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

    fn event_connected(&self) {
        println!("connected to server.");
    }
    fn event_disconnect(&self) {
        println!("connection closed.");
    }
    fn event_connection_failed(&self, error: SmtpErr) {
        eprintln!(
            "connecting failed:\n{}",
            self.get_error_message(error.clone())
        );
    }
    fn event_mail_sent(&self, subject: String, to: String) {
        println!("--> sent [{}] to <{}>.", subject, to);
    }
    fn event_mail_failed(&self, subject: String, to: String, error: SmtpErr) {
        eprintln!(
            "--> sending [{}] to <{}> failed:\n{}",
            subject,
            to,
            self.get_error_message(error.clone())
        );
    }
    fn event_retrying(&self) {
        eprintln!("--> retrying...");
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

    fn event(&self, event: SmtpEvent) {
        if self.enabled {
            match event {
                SmtpEvent::Connected => self.event_connected(),
                SmtpEvent::FailedToConnect(e) => self.event_connection_failed(e),
                SmtpEvent::Disconnencted => self.event_disconnect(),
                SmtpEvent::FailToDisconnect(_) => (),
                SmtpEvent::Retry => self.event_retrying(),
                SmtpEvent::MailSent { subject, to } => self.event_mail_sent(subject, to),
                SmtpEvent::FailedToSendMail { subject, to, error } => {
                    self.event_mail_failed(subject, to, error)
                }
            }
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
