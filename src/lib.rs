//! Library for invoking [`pinentry`](https://www.gnupg.org/related_software/pinentry/index.en.html) to get password
//! input
//!
//! # Example
//!
//! ```
//! # extern crate pinentry_rs;
//! # extern crate secstr;
//! use pinentry_rs::pinentry;
//! use secstr::SecStr;
//!
//! # use pinentry_rs::Result;
//! # fn read_pw() -> Result<SecStr> {
//! // Read a password into a `SecStr`
//! let pw = pinentry().pin("Please enter password:".to_string())?;
//! # Ok(pw)
//! # }
//!
//! ```

#![deny(warnings)]
#[warn(unused_must_use)]
extern crate secstr;

/// Assuan protocol used by pinentry
///
/// _Note_ the module is deliberately left private currently
mod assuan;

use std::ffi::OsStr;
use std::io;
use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::result;

use secstr::SecStr;

use assuan::{AssuanCommand, AssuanResponse, Button};

pub type Result<T> = result::Result<T, Error>;

/// Errors that can occur while interacting with pinentry
#[derive(Debug)]
pub enum Error {
    /// IO error (command not found, broken pipe, etc.)
    IoError(io::Error),
    /// Protocol error (unable to parse protocol, broken pinentry output, etc.)
    ProtocolError(String),
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::IoError(e)
    }
}

/// Create a builder for invoking `pinentry`
pub fn pinentry() -> PinentryBuilder {
    PinentryBuilder::default()
}

/// Builder for pinentry execution
pub struct PinentryBuilder {
    description: Option<String>,
    error_text: Option<String>,
    exe: String,
    label_cancel: Option<String>,
    label_notok: Option<String>,
    label_ok: Option<String>,
    timeout: Option<u32>,
    window_title: Option<String>,
}

impl PinentryBuilder {
    /// Set the descriptive text of the prompt
    pub fn description(mut self, desc: String) -> Self {
        self.description = Some(desc);
        self
    }

    /// Set the text that gets the displayed in case of error
    pub fn error_text(mut self, error_text: String) -> Self {
        self.error_text = Some(error_text);
        self
    }

    /// Override the path to the `pinentry` executable (by default just `pinentry`, looked up using `PATH` environment
    /// variable)
    pub fn exe(mut self, exe: String) -> Self {
        self.exe = exe;
        self
    }

    /// Set the label of the 'Cancel' button
    pub fn label_cancel(mut self, label: String) -> Self {
        self.label_cancel = Some(label);
        self
    }

    /// Set the label of the 'Not OK' button
    pub fn label_notok(mut self, label: String) -> Self {
        self.label_notok = Some(label);
        self
    }

    /// Set the label of the 'OK' button
    pub fn label_ok(mut self, label: String) -> Self {
        self.label_ok = Some(label);
        self
    }

    /// Set timeout for prompt (in seconds)
    pub fn timeout(mut self, secs: u32) -> Self {
        self.timeout = Some(secs);
        self
    }

    /// Set the window title of the prompt
    pub fn window_title(mut self, title: String) -> Self {
        self.window_title = Some(title);
        self
    }

    /// Prompt for confirmation
    ///
    /// The text for the confirmation should be set using `.description()`
    pub fn confirm_yes_no(mut self) -> Result<bool> {
        let mut commands = self.build_commands();
        commands.push(AssuanCommand::Confirm);

        let pinentry = start_pinentry(&self.exe)?;

        let res = process_commands(pinentry, &commands)?;
        match res {
            AssuanResponse::OK => Ok(true),
            AssuanResponse::NOTOK(_) => Ok(false),
            x => panic!("BUG: unexpected response {:?}", x),
        }
    }

    /// Prompt for a PIN
    pub fn pin(mut self, prompt: String) -> Result<SecStr> {
        let mut commands = self.build_commands();
        commands.push(AssuanCommand::SetPrompt(prompt));
        commands.push(AssuanCommand::GetPin);

        let pinentry = start_pinentry(&self.exe)?;

        let res = process_commands(pinentry, &commands)?;
        match res {
            AssuanResponse::PIN(pin) => Ok(pin),
            AssuanResponse::NOTOK(error) => Err(Error::ProtocolError(error)),
            AssuanResponse::OK => panic!("BUG: got OK result but asked for PIN"),
        }
    }

    /// Show a message
    ///
    /// The text for the message should be set using `.description()`
    pub fn show_message(mut self) -> Result<()> {
        let mut commands = self.build_commands();
        commands.push(AssuanCommand::ShowMessage);

        let pinentry = start_pinentry(&self.exe)?;

        let res = process_commands(pinentry, &commands)?;
        match res {
            AssuanResponse::OK => Ok(()),
            x => panic!("BUG: unexpected response {:?}", x),
        }
    }

    fn build_commands(&mut self) -> Vec<AssuanCommand> {
        let mut cmds = Vec::new();

        if let Some(desc) = self.description.take() {
            cmds.push(AssuanCommand::SetDescriptiveText(desc));
        }
        if let Some(text) = self.error_text.take() {
            cmds.push(AssuanCommand::SetErrorText(text));
        }
        if let Some(cancel_label) = self.label_cancel.take() {
            cmds.push(AssuanCommand::SetButtonLabel(Button::CANCEL, cancel_label));
        }
        if let Some(notok_label) = self.label_notok.take() {
            cmds.push(AssuanCommand::SetButtonLabel(Button::NOTOK, notok_label));
        }
        if let Some(ok_label) = self.label_ok.take() {
            cmds.push(AssuanCommand::SetButtonLabel(Button::OK, ok_label));
        }
        if let Some(timeout) = self.timeout {
            cmds.push(AssuanCommand::SetTimeout(timeout));
        }
        if let Some(title) = self.window_title.take() {
            cmds.push(AssuanCommand::SetWindowTitle(title));
        }

        cmds
    }
}

impl Default for PinentryBuilder {
    fn default() -> Self {
        PinentryBuilder {
            description: None,
            error_text: None,
            exe: "pinentry".to_string(),
            label_cancel: None,
            label_notok: None,
            label_ok: None,
            timeout: None,
            window_title: None,
        }
    }
}

fn start_pinentry<S: AsRef<OsStr>>(exe: S) -> Result<Child> {
    let mut pinentry = Command::new(exe)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("failed to execute pinentry");

    {
        // Check whether next line starts with OK
        let stdout = pinentry.stdout.as_mut().expect("failed to get stdout");
        let mut reader = BufReader::new(stdout);

        let mut line = String::with_capacity(32);
        let _ = reader.read_line(&mut line)?;
        if !line.starts_with("OK") {
            return Err(Error::ProtocolError(line));
        }
    }

    Ok(pinentry)
}

fn process_commands(mut pinentry: Child, cmds: &[AssuanCommand]) -> Result<AssuanResponse> {
    let res = {
        let mut stdout = BufReader::new(pinentry.stdout.as_mut().expect("failed to get stdout"));
        let stdin = pinentry.stdin.as_mut().expect("failed to get stdin");

        assuan::process_commands(cmds.iter(), stdin, &mut stdout)?
    };
    pinentry.kill()?;
    Ok(res)
}
