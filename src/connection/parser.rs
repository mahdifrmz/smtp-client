use super::{
    protocol::{status_code, Line},
    Logger, SmtpErr, SmtpResult,
};
use std::io::Read;

pub(crate) struct Parser<'a, T, L>
where
    T: Read,
    L: Logger,
{
    pub(crate) stream: &'a mut T,
    pub(crate) logger: &'a mut L,
    pub(crate) next_char: char,
}

impl<'a, T, L> Parser<'a, T, L>
where
    T: Read,
    L: Logger,
{
    pub(crate) fn recv_char(&mut self) -> SmtpResult<char> {
        let mut buf = [0u8; 1];
        self.stream.read(&mut buf).map_err(|_| SmtpErr::Network)?;
        let c = self.next_char;
        self.next_char = buf[0] as char;
        self.logger.server(&buf);
        Ok(c)
    }
    pub(crate) fn peek_char(&mut self) -> char {
        self.next_char
    }
    pub(crate) fn recv_digit(&mut self) -> SmtpResult<u8> {
        let c = self.recv_char()?;
        if c > '9' || c < '0' {
            Err(SmtpErr::Protocol)
        } else {
            Ok((c as u8) - ('0' as u8))
        }
    }
    pub(crate) fn expect_char(&mut self, exp: char) -> SmtpResult<()> {
        let c = self.recv_char()?;
        if c == exp {
            Ok(())
        } else {
            Err(SmtpErr::Protocol)
        }
    }
    pub(crate) fn expect_end(&mut self) -> SmtpResult<()> {
        self.expect_char('\r')?;
        if self.peek_char() == '\n' {
            Ok(())
        } else {
            Err(SmtpErr::Protocol)
        }
    }
    pub(crate) fn recv_text(&mut self) -> SmtpResult<String> {
        let mut text = String::new();
        loop {
            let c = self.recv_char()?;
            if c == '\r' && self.peek_char() == '\n' {
                return Ok(text);
            } else {
                text.push(c);
            }
        }
    }
    pub(crate) fn recv_line(&mut self) -> SmtpResult<Line> {
        self.recv_char()?;
        let d1 = self.recv_digit()? as u32;
        let d2 = self.recv_digit()? as u32;
        let d3 = self.recv_digit()? as u32;
        let code = d1 * 100 + d2 * 10 + d3;
        let next = self.peek_char();
        let text = if next == ' ' || next == '-' {
            self.recv_char()?;
            self.recv_text()?
        } else {
            self.expect_end()?;
            String::new()
        };
        Ok(Line::new(
            status_code(code).ok_or_else(|| SmtpErr::Protocol)?,
            text,
            next == ' ',
        ))
    }
    pub(crate) fn recv_reply(&mut self) -> SmtpResult<Vec<Line>> {
        let mut lines = vec![self.recv_line()?];
        while !lines[lines.len() - 1].last() {
            lines.push(self.recv_line()?);
        }
        Ok(lines)
    }

    pub(crate) fn new(stream: &'a mut T, logger: &'a mut L) -> Parser<'a, T, L> {
        let parser = Parser {
            logger,
            stream,
            next_char: '\0',
        };
        parser
    }
}
