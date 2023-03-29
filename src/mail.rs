use crate::{SmtpErr, SmtpResult};
use mail_builder::MessageBuilder;
use std::fs;

pub struct Mail {
    pub subject: String,
    pub from: String,
    pub from_name: Option<String>,
    pub to: String,
    pub to_name: Option<String>,
    pub text: String,
    pub attachments: Vec<String>,
}

impl Mail {
    pub fn to_bytes(&self) -> SmtpResult<Vec<u8>> {
        let mut builder = MessageBuilder::new()
            .from((
                self.from_name.clone().unwrap_or("".to_owned()),
                self.from.clone(),
            ))
            .to((
                self.to_name.clone().unwrap_or("".to_owned()),
                self.to.clone(),
            ))
            .subject(self.subject.as_str())
            .text_body(self.text.as_str());
        for att in self.attachments.iter() {
            let content = fs::read(att).map_err(|_| SmtpErr::File(att.clone()))?;
            builder = builder.binary_attachment("image/png", att, content);
        }
        Ok(builder.write_to_vec().unwrap())
    }
}
