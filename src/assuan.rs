use std::io::{BufRead, Write};

use secstr::SecStr;

use super::Result;

/// Button type in the pinentry (usually there are two buttons, OK and CANCEL, but there is an option
/// to use a third 'not ok' button)
#[derive(Debug)]
pub enum Button {
    OK,
    CANCEL,
    NOTOK,
}

/// Commands in the Assuan protocol (used for communicating with pinentry)
///
/// _Note_ this is not a complete formulation of the protocol - notably passphrase quality, output device
/// and default strings are missing.
#[derive(Debug)]
pub enum AssuanCommand {
    /// Set the timeout before returning an error
    SetTimeout(u32),
    /// Set the descriptive text to display
    SetDescriptiveText(String),
    /// Set the prompt to show
    SetPrompt(String),
    /// Set the window title
    SetWindowTitle(String),
    /// Set a button label (text)
    SetButtonLabel(Button, String),
    /// Set the error text
    SetErrorText(String),
    /// Ask for a PIN
    GetPin,
    /// Ask for confirmation
    Confirm,
    /// Show a message
    ShowMessage,
}

/// Responses in the Assuan protocol
#[derive(Debug)]
pub enum AssuanResponse {
    /// A PIN held in a _secure_ string
    PIN(SecStr),
    /// OK (can mean successful confirmation or just that the last command was successful)
    OK,
    /// Not OK (can either mean non-confirmation or just that the last command was unsuccessful)
    ///
    /// _Note_ that currently no attempt is made to handle protocol errors differently to client errors
    NOTOK(String),
}

// strictly speaking a trait is not necessary
trait CommandWrite {
    fn write_to<W: Write>(&self, writer: &mut W) -> Result<()>;
}

impl CommandWrite for AssuanCommand {
    fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        match self {
            AssuanCommand::SetTimeout(timeout_secs) => write_line(writer, format!("SETTIMEOUT {}", timeout_secs)),
            AssuanCommand::SetDescriptiveText(text) => write_line(writer, format!("SETDESC {}", text)),
            AssuanCommand::SetPrompt(text) => write_line(writer, format!("SETPROMPT {}", text)),
            AssuanCommand::SetWindowTitle(text) => write_line(writer, format!("SETTITLE {}", text)),
            AssuanCommand::SetButtonLabel(button, text) => {
                let command = match button {
                    Button::OK => "SETOK",
                    Button::CANCEL => "SETCANCEL",
                    Button::NOTOK => "SETNOTOK",
                };
                write_line(writer, format!("{} {}", command, text))
            }
            AssuanCommand::SetErrorText(text) => write_line(writer, format!("SETERROR {}", text)),
            AssuanCommand::GetPin => write_line(writer, "GETPIN".to_string()),
            AssuanCommand::Confirm => write_line(writer, "CONFIRM".to_string()),
            AssuanCommand::ShowMessage => write_line(writer, "MESSAGE".to_string()),
        }
    }
}

/// Main processing function - take in an iterator of commands, and process the commands while interacting with an
/// Assuan-protocol speaking backend (pinentry) using the read/write pipes until the first terminal command.
///
/// Terminal commands are:
///
///   * `GetPin`
///   * `Confirm`
///   * `Message`
///
/// For a `GetPin` command, a `PIN` is expected to be returned. For the other two commands, an `OK` should be returned.
/// If something goes wrong (not at the I/O level) then a `NOTOK` will be returned with the error message from pinentry.
pub fn process_commands<'a, W: Write, R: BufRead, I: Iterator<Item = &'a AssuanCommand>>(
    cmds: I,
    writer: &mut W,
    reader: &mut R,
) -> Result<AssuanResponse> {
    let mut line = String::with_capacity(256);

    for cmd in cmds {
        cmd.write_to(writer)?;
        match cmd {
            AssuanCommand::GetPin => {
                // Expect to read 'D ', so read 2 chars
                let mut ok_or = [0u8; 2];
                let read = reader.read(&mut ok_or)?;
                match &ok_or {
                    b"D " => (),
                    _ => {
                        line.clear();
                        // 2 chars may have already been read - they need to be added to the response
                        for i in 0..read {
                            line.push(ok_or[i] as char);
                        }
                        reader.read_line(&mut line)?;
                        return Ok(AssuanResponse::NOTOK(trim_newl(line)));
                    }
                }
                // Now next chars until end of line are password
                let mut pw = String::with_capacity(2048); // TODO - maybe instead allocate a SecStr and read to that?
                reader.read_line(&mut pw)?;
                let res = AssuanResponse::PIN(SecStr::new(trim_newl(pw).into_bytes()));

                // Next line should be 'OK' - fail if not
                if read_line_is_ok(reader, &mut line)? {
                    return Ok(res);
                } else {
                    return Ok(AssuanResponse::NOTOK(trim_newl(line)));
                }
            }
            AssuanCommand::Confirm | AssuanCommand::ShowMessage => {
                // same as the fallthrough case but return immediately with OK
                if read_line_is_ok(reader, &mut line)? {
                    return Ok(AssuanResponse::OK);
                } else {
                    return Ok(AssuanResponse::NOTOK(trim_newl(line)));
                }
            }
            _ => {
                if !read_line_is_ok(reader, &mut line)? {
                    return Ok(AssuanResponse::NOTOK(trim_newl(line)));
                }
            }
        }
    }

    Ok(AssuanResponse::OK)
}

fn write_line<W: Write>(writer: &mut W, mut s: String) -> Result<()> {
    s.push('\n');
    let _ = writer.write(s.as_ref())?;
    Ok(())
}

fn read_line_is_ok<R: BufRead>(reader: &mut R, l: &mut String) -> Result<bool> {
    l.clear();
    let _ = reader.read_line(l)?;
    match l.as_ref() {
        "OK" | "OK\n" => Ok(true),
        _ => Ok(false),
    }
}

fn trim_newl(mut s: String) -> String {
    if s.ends_with('\n') {
        let _ = s.pop();
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Cursor;
    use std::str;

    fn write_to_string<C: CommandWrite>(cmd: &C) -> String {
        let mut c = Cursor::new(Vec::new());
        cmd.write_to(&mut c).expect("can write to in-memory buffer");
        String::from_utf8(c.into_inner()).expect("utf8-encoded command")
    }

    fn process(cmds: &[AssuanCommand], expected: &[&str]) -> Result<(Vec<String>, AssuanResponse)> {
        let mut w = Cursor::new(Vec::new());
        let mut r = Cursor::new(expected.join("\n"));
        let res = process_commands(cmds.iter(), &mut w, &mut r)?;

        let written = String::from_utf8(w.into_inner())
            .expect("utf8-encoded commands")
            .split('\n')
            .map(|s| s.to_string())
            .collect();
        Ok((written, res))
    }

    #[test]
    fn test_assuan_command_write() {
        assert_eq!("SETTIMEOUT 30\n", write_to_string(&AssuanCommand::SetTimeout(30)));
        assert_eq!(
            "SETDESC Enter PIN for Donald Trump <trump@tower.gov>\n",
            write_to_string(&AssuanCommand::SetDescriptiveText(
                "Enter PIN for Donald Trump <trump@tower.gov>".to_string()
            ))
        );
        assert_eq!(
            "SETPROMPT PIN:\n",
            write_to_string(&AssuanCommand::SetPrompt("PIN:".to_string()))
        );
        assert_eq!(
            "SETTITLE ATM\n",
            write_to_string(&AssuanCommand::SetWindowTitle("ATM".to_string()))
        );
        assert_eq!(
            "SETOK Yes\n",
            write_to_string(&AssuanCommand::SetButtonLabel(Button::OK, "Yes".to_string()))
        );
        assert_eq!(
            "SETCANCEL No\n",
            write_to_string(&AssuanCommand::SetButtonLabel(Button::CANCEL, "No".to_string()))
        );
        assert_eq!(
            "SETNOTOK Don't push this button\n",
            write_to_string(&AssuanCommand::SetButtonLabel(
                Button::NOTOK,
                "Don't push this button".to_string()
            ))
        );
        assert_eq!(
            "SETERROR Invalid PIN entered - please try again\n",
            write_to_string(&AssuanCommand::SetErrorText(
                "Invalid PIN entered - please try again".to_string()
            ))
        );
        assert_eq!("GETPIN\n", write_to_string(&AssuanCommand::GetPin));
        assert_eq!("CONFIRM\n", write_to_string(&AssuanCommand::Confirm));
        assert_eq!("MESSAGE\n", write_to_string(&AssuanCommand::ShowMessage));
    }

    #[test]
    fn test_process_commands_getpin() {
        // command sequence to execute
        let cmds = vec![
            AssuanCommand::SetTimeout(60),
            AssuanCommand::SetWindowTitle("Enter passphrase".to_string()),
            AssuanCommand::GetPin,
        ];

        // simulated responses from pinentry
        let responses = vec!["OK", "OK", "D heremailserver", "OK"];

        // run the test
        let (written, res) = process(&cmds, &responses).expect("commands should be processed successfully");

        // verify commands are written out
        let expected_written = vec!["SETTIMEOUT 60", "SETTITLE Enter passphrase", "GETPIN", ""];
        assert_eq!(expected_written, written);

        // verify that PIN is obtained
        match res {
            AssuanResponse::PIN(pw) => assert_eq!("heremailserver", str::from_utf8(pw.unsecure()).unwrap()),
            x => panic!("unexpected result {:?}", x),
        }
    }

    #[test]
    fn test_process_commands_confirm() {
        // command sequence to execute
        let cmds = vec![
            AssuanCommand::SetDescriptiveText("Please confirm your identity".to_string()),
            AssuanCommand::Confirm,
        ];

        // simulated responses from pinentry
        let responses = vec!["OK", "OK"];

        // run the test
        let (written, res) = process(&cmds, &responses).expect("command should be processed successfully");

        // verify the commands written out
        let expected_written = vec!["SETDESC Please confirm your identity", "CONFIRM", ""];
        assert_eq!(expected_written, written);

        // verify that OK is obtained
        match res {
            AssuanResponse::OK => (),
            x => panic!("unexpected result {:?}", x),
        }
    }
}
