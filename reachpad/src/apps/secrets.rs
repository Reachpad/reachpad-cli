//! The two local halves of `reachpad secrets set`: which names are allowed,
//! and where the value is read from.
//!
//! Both run before the request, and the second one is the reason this file
//! exists at all. Argv is readable by every other process on the machine, so
//! a value never travels there: it arrives on stdin, from a file, from an
//! environment variable, or from a prompt this module turns terminal echo off
//! for. It is never an argument, it is never logged, and nothing here ever
//! prints it back.
//!
//! Nothing here trims a value either. Exactly one trailing newline comes off,
//! the one a shell or an editor adds, and everything else survives, because a
//! PEM private key is leading whitespace, interior newlines and a final one.

use crate::errors::CliError;

use super::failure;

/// The longest name the front door will store.
pub const MAX_NAME: usize = 64;
/// The largest value, in bytes. Cloudflare's per-script secret limit is well
/// above this; the point of the ceiling is that a file pasted in by mistake
/// (a whole key ring, a tarball) is refused here instead of on the wire.
pub const MAX_VALUE_BYTES: usize = 64 * 1024;
/// Reserved for the bindings Reachpad puts in `env` itself.
const RESERVED_PREFIX: &str = "RP_";
/// The binding every function already has.
const RESERVED_NAME: &str = "reachpad";

/// Why this name is not one an app can bind, or `None` if it is.
///
/// The rule is the front door's, checked here so a typo costs no round trip:
/// `^[A-Z][A-Z0-9_]*$`, at most [`MAX_NAME`], and neither of the two reserved
/// spellings. Each sentence names the one thing that is wrong with it, and it
/// begins with the offending name, because [`crate::apps::manifest::parse`]
/// prints it about an entry in a list where the reader cannot see which.
pub fn name_reason(name: &str) -> Option<String> {
    if name.eq_ignore_ascii_case(RESERVED_NAME) {
        return Some(format!(
            "{name} is the binding every function already has. Pick another name."
        ));
    }
    if name.is_empty() {
        return Some("a secret needs a name, like STRIPE_KEY.".to_owned());
    }
    let shaped = name.starts_with(|c: char| c.is_ascii_uppercase())
        && name
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_');
    if !shaped {
        return Some(format!(
            "{name} is not a name an app can bind. Names are uppercase letters, digits and \
             underscores, starting with a letter, like STRIPE_KEY."
        ));
    }
    if name.len() > MAX_NAME {
        return Some(format!(
            "{name} is {} characters and the limit is {MAX_NAME}.",
            name.len()
        ));
    }
    if name.starts_with(RESERVED_PREFIX) {
        return Some(format!(
            "{name} starts with {RESERVED_PREFIX}, which is reserved for Reachpad. Pick another \
             name."
        ));
    }
    None
}

/// [`name_reason`] as the refusal a verb returns.
pub fn check_name(name: &str) -> Result<(), CliError> {
    match name_reason(name) {
        Some(reason) => Err(failure(reason)),
        None => Ok(()),
    }
}

/// The value, from wherever it was named: `-` (stdin), `@<path>`, `env:<VAR>`,
/// or, with no argument at all, stdin when something is piped in and the
/// hidden [`prompt`] when it is not.
///
/// The three spellings are `--api-key`'s, deliberately: a person who has typed
/// one of this CLI's secret-carrying flags already knows this grammar. The
/// reader is this module's own rather than [`crate::conf::read_secret_arg`]
/// because that one trims the value, which would quietly corrupt a key that
/// ends in whitespace, and because the sentence a refusal prints here names
/// this verb.
pub async fn read_value(name: &str, arg: Option<&str>) -> Result<String, CliError> {
    let value = match arg {
        Some("-") => {
            if stdin_is_a_terminal() {
                return Err(would_echo(name));
            }
            from_stdin(name)?
        }
        Some(arg) if arg.starts_with('@') => {
            let path = &arg[1..];
            let text = std::fs::read_to_string(path)
                .map_err(|e| failure(format!("reading the value for {name} from {path}: {e}")))?;
            chomp(&text)
        }
        Some(arg) if arg.starts_with("env:") => {
            let var = &arg[4..];
            let text = std::env::var(var).map_err(|_| {
                failure(format!(
                    "the environment variable {var} is not set, so there is no value for {name}."
                ))
            })?;
            chomp(&text)
        }
        Some(_) => return Err(value_on_argv(name)),
        None => {
            if stdin_is_a_terminal() {
                prompt(name).await?
            } else {
                from_stdin(name)?
            }
        }
    };
    if value.is_empty() {
        return Err(failure(format!("{name} was given no value.")));
    }
    if value.len() > MAX_VALUE_BYTES {
        return Err(failure(format!(
            "the value for {name} is {} bytes and the limit is 64 KiB.",
            value.len()
        )));
    }
    Ok(value)
}

fn stdin_is_a_terminal() -> bool {
    std::io::IsTerminal::is_terminal(&std::io::stdin())
}

fn from_stdin(name: &str) -> Result<String, CliError> {
    let mut buf = String::new();
    std::io::Read::read_to_string(&mut std::io::stdin(), &mut buf)
        .map_err(|e| failure(format!("reading the value for {name} from stdin: {e}")))?;
    Ok(chomp(&buf))
}

/// One trailing newline off, and not one character more.
fn chomp(value: &str) -> String {
    value
        .strip_suffix("\r\n")
        .or_else(|| value.strip_suffix('\n'))
        .unwrap_or(value)
        .to_owned()
}

/// The refusal for a value typed where other processes can read it.
fn value_on_argv(name: &str) -> CliError {
    CliError::usage(format!(
        "the value cannot go on the command line, where every other process on this machine \
         can read it. Use `reachpad secrets set {name} -` to read it from stdin, `@<path>` to \
         read it from a file, or `env:<VAR>` to read it from the environment."
    ))
}

/// The refusal for reading a value where the terminal would show it: an
/// explicit `-` with a terminal on stdin, and a terminal that will not turn
/// echo off. One sentence for both, because they are one problem.
fn would_echo(name: &str) -> CliError {
    failure(format!(
        "the value would be echoed as you type it here. Pipe it in instead: \
         `printf %s \"$VALUE\" | reachpad secrets set {name}`."
    ))
}

/// Ask for the value with the terminal's echo off.
///
/// The prompt goes to stderr, so `reachpad secrets set K --json` still puts
/// one machine-readable line and nothing else on stdout.
///
/// Two things have to be true for the terminal to survive this. Echo must go
/// off, and it must come back on EVERY path out, including Ctrl-C, which does
/// not unwind and so runs no destructor. So a SIGINT watcher is registered
/// BEFORE echo goes off (there is no window where a signal finds the terminal
/// silent and no handler), it restores the saved terminal state itself, and it
/// is deliberately never aborted: once tokio has taken SIGINT over, dropping
/// the watcher would leave a process that ignores Ctrl-C for the rest of the
/// command, and restoring an already-restored terminal costs nothing.
async fn prompt(name: &str) -> Result<String, CliError> {
    let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
        .map_err(|e| {
            failure(format!(
                "this process cannot catch Ctrl-C ({e}), and a prompt that cannot put the \
                 terminal back is worse than no prompt. Pipe the value in instead."
            ))
        })?;
    let guard = NoEcho::enter().ok_or_else(|| would_echo(name))?;
    let saved = guard.saved.clone();
    let _watcher = tokio::spawn(async move {
        if sigint.recv().await.is_some() {
            NoEcho::restore(&saved);
            eprintln!();
            std::process::exit(EXIT_INTERRUPTED);
        }
    });

    eprint!("Value for {name}: ");
    let _ = std::io::Write::flush(&mut std::io::stderr());
    let mut line = String::new();
    let read = std::io::BufRead::read_line(&mut std::io::stdin().lock(), &mut line);
    drop(guard);
    // The newline the terminal did not echo when Enter was pressed.
    eprintln!();
    read.map_err(|e| {
        failure(format!(
            "reading the value for {name} from the terminal: {e}"
        ))
    })?;
    Ok(chomp(&line))
}

/// What a shell reports for a command its user interrupted.
const EXIT_INTERRUPTED: i32 = 130;

/// Terminal echo off, restored on drop, including on an error return.
///
/// `stty`, not a termios crate, for the reason `attach` gives: the workspace
/// forbids `unsafe` outside blockd and this runs once per command.
struct NoEcho {
    saved: String,
}

impl NoEcho {
    fn enter() -> Option<NoEcho> {
        let saved = std::process::Command::new("stty")
            .arg("-g")
            .stdin(std::process::Stdio::inherit())
            .output()
            .ok()?;
        if !saved.status.success() {
            return None;
        }
        let saved = String::from_utf8_lossy(&saved.stdout).trim().to_owned();
        let set = std::process::Command::new("stty")
            .arg("-echo")
            .stdin(std::process::Stdio::inherit())
            .status()
            .ok()?;
        set.success().then_some(NoEcho { saved })
    }

    fn restore(saved: &str) {
        let _ = std::process::Command::new("stty")
            .arg(saved)
            .stdin(std::process::Stdio::inherit())
            .status();
    }
}

impl Drop for NoEcho {
    fn drop(&mut self) {
        NoEcho::restore(&self.saved);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_names_an_app_can_bind() {
        let longest = "A".repeat(MAX_NAME);
        for good in [
            "STRIPE_KEY",
            "A",
            "A1",
            "OPENAI_API_KEY_2",
            longest.as_str(),
        ] {
            assert!(name_reason(good).is_none(), "{good} was refused");
        }
    }

    #[test]
    fn every_refusal_says_which_rule_the_name_broke() {
        let cases = [
            ("stripe_key", "uppercase letters, digits and underscores"),
            ("1STRIPE", "uppercase letters, digits and underscores"),
            ("_STRIPE", "uppercase letters, digits and underscores"),
            ("STRIPE-KEY", "uppercase letters, digits and underscores"),
            ("STRIPE KEY", "uppercase letters, digits and underscores"),
            ("", "a secret needs a name"),
            ("RP_TOKEN", "reserved for Reachpad"),
            ("reachpad", "the binding every function already has"),
            ("REACHPAD", "the binding every function already has"),
        ];
        for (name, says) in cases {
            let reason = name_reason(name).expect("the name was allowed");
            assert!(reason.contains(says), "{name}: {reason}");
            assert_eq!(check_name(name).unwrap_err().exit_code, 1);
        }
        let long = "A".repeat(MAX_NAME + 1);
        let reason = name_reason(&long).expect("a 65-character name was allowed");
        assert!(reason.contains("the limit is 64"), "{reason}");
    }

    /// A value is taken as it is, minus the one newline a shell or an editor
    /// put there. A PEM key is the case that matters: leading whitespace,
    /// interior newlines and a final one, all of which a trim would eat.
    #[tokio::test]
    async fn a_value_keeps_everything_but_one_trailing_newline() {
        let pem = "-----BEGIN PRIVATE KEY-----\n  indented\nline\n-----END PRIVATE KEY-----\n";
        let path = std::env::temp_dir().join(format!("reach-pem-{}", std::process::id()));
        std::fs::write(&path, pem).unwrap();
        let read = read_value("KEY", Some(&format!("@{}", path.display())))
            .await
            .unwrap();
        std::fs::remove_file(&path).unwrap();
        assert_eq!(read, pem.strip_suffix('\n').unwrap());
        assert!(read.ends_with("-----END PRIVATE KEY-----"));
        assert!(read.contains("\n  indented\n"), "the inside was rewritten");

        assert_eq!(chomp("v\r\n"), "v");
        assert_eq!(chomp("v\n\n"), "v\n");
        assert_eq!(chomp(" v "), " v ");
    }

    #[tokio::test]
    async fn the_value_comes_from_a_file_or_an_environment_variable_but_never_from_argv() {
        std::env::set_var("REACH_TEST_SECRET_VALUE", "sk_live_from_env");
        assert_eq!(
            read_value("STRIPE_KEY", Some("env:REACH_TEST_SECRET_VALUE"))
                .await
                .unwrap(),
            "sk_live_from_env"
        );
        std::env::remove_var("REACH_TEST_SECRET_VALUE");

        let err = read_value("STRIPE_KEY", Some("sk_live_typed_here"))
            .await
            .expect_err("argv allowed");
        assert_eq!(err.exit_code, crate::errors::EXIT_USAGE);
        assert!(
            err.message
                .contains("Use `reachpad secrets set STRIPE_KEY -`"),
            "{}",
            err.message
        );
        assert!(!err.message.contains('—'), "an em dash: {}", err.message);
        // Whatever it says, it does not say the secret.
        assert!(
            !err.message.contains("sk_live_typed_here"),
            "{}",
            err.message
        );
    }

    #[tokio::test]
    async fn a_value_past_the_ceiling_is_refused_before_the_wire() {
        let path = std::env::temp_dir().join(format!("reach-big-secret-{}", std::process::id()));
        std::fs::write(&path, "x".repeat(MAX_VALUE_BYTES + 1)).unwrap();
        let err = read_value("BIG", Some(&format!("@{}", path.display())))
            .await
            .expect_err("an oversized value was accepted");
        std::fs::remove_file(&path).unwrap();
        assert!(
            err.message.contains("the limit is 64 KiB"),
            "{}",
            err.message
        );
    }

    /// Both ways of reading a value off a terminal refuse with one sentence.
    #[test]
    fn the_terminal_refusal_is_one_sentence_for_both_of_its_causes() {
        let says = would_echo("STRIPE_KEY").message;
        assert!(says.contains("would be echoed as you type it"), "{says}");
        assert!(says.contains("printf"), "{says}");
    }
}
