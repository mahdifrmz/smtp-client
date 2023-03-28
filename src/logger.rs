use smtp::Logger;
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
