use smtp::{Credentials, Mail, Mailer, Server};

fn main() {
    let username = "faramarzpour98@gmail.com".to_string();
    let password = "mqtepoybaongfyic".to_string();

    let mut mailer = Mailer::new(Server::new("smtp.gmail.com", 25));
    mailer
        .connect(Credentials::new(username.clone(), password))
        .unwrap();
    mailer
        .send_mail(Mail {
            subject: "warning".to_string(),
            from: username.clone(),
            to: username.clone(),
            text: "salam!".to_string(),
            from_name: Some("mahdi".to_string()),
            to_name: Some("mahdi".to_string()),
        })
        .unwrap();
    mailer.disconnect().unwrap();
}
