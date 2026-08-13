//! Where the CLI keeps its endpoint and its credential, and the strict file
//! format both are written in.
//!
//! ```text
//! ~/.config/reachpad/            (0700)
//!   config.toml                  (0600)  endpoint, per profile — NO SECRETS
//!   credentials.toml             (0600)  the long-lived operator credential
//! ~/.local/state/reachpad/<profile>/     (0700)   see `state.rs`
//! ```
//!
//! The files are named `.toml` and are a STRICT SUBSET of TOML: `[section]`
//! headers and `key = "value"` lines, full-line `#` comments, nothing else.
//! Only `\\` and `\"` are escapes. An unknown key or a line this parser does
//! not understand is REFUSED, naming the file and the line — a config reader
//! that silently ignores what it does not understand is how a setting a user
//! wrote stops taking effect without anyone noticing.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context};

use crate::errors::CliError;
use crate::privatefile;

pub const DEFAULT_PROFILE: &str = "default";

const CONFIG_KEYS: &[&str] = &["endpoint"];
const CREDENTIAL_KEYS: &[&str] = &["operator_token", "token_id", "token_expires_at_ms"];

// ---------------------------------------------------------------------------
// The strict subset
// ---------------------------------------------------------------------------

/// A refusal from [`Doc::parse`], carrying the line so the caller can name the
/// file and the line together.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub line: usize,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub value: String,
    pub line: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Section {
    pub line: usize,
    pub entries: BTreeMap<String, Entry>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Doc {
    sections: BTreeMap<String, Section>,
}

impl Doc {
    pub fn parse(text: &str) -> Result<Doc, Refusal> {
        let refuse = |line: usize, reason: &str| Refusal {
            line,
            reason: reason.to_owned(),
        };
        let mut doc = Doc::default();
        let mut current: Option<String> = None;
        for (index, raw) in text.lines().enumerate() {
            let line = index + 1;
            let trimmed = raw.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            if let Some(rest) = trimmed.strip_prefix('[') {
                let name = rest
                    .strip_suffix(']')
                    .ok_or_else(|| refuse(line, "a section header must end with `]`"))?;
                if name.is_empty() || !name.chars().all(is_section_char) {
                    return Err(refuse(
                        line,
                        "a section name may hold only letters, digits, `.`, `-` and `_`",
                    ));
                }
                doc.sections.entry(name.to_owned()).or_insert(Section {
                    line,
                    entries: BTreeMap::new(),
                });
                current = Some(name.to_owned());
                continue;
            }
            let Some((key, value)) = trimmed.split_once('=') else {
                return Err(refuse(line, "expected `key = \"value\"`"));
            };
            let key = key.trim();
            if key.is_empty() || !key.chars().all(is_key_char) {
                return Err(refuse(
                    line,
                    "a key may hold only letters, digits, `-` and `_`",
                ));
            }
            let Some(section) = current.as_deref() else {
                return Err(refuse(line, "a key must come after a `[section]` header"));
            };
            let value = unquote(value.trim()).map_err(|reason| refuse(line, &reason))?;
            let previous = doc
                .sections
                .get_mut(section)
                .expect("the current section was just inserted")
                .entries
                .insert(key.to_owned(), Entry { value, line });
            if let Some(previous) = previous {
                return Err(refuse(
                    line,
                    &format!("`{key}` is already set on line {}", previous.line),
                ));
            }
        }
        Ok(doc)
    }

    pub fn render(&self) -> String {
        let mut out = String::new();
        for (name, section) in &self.sections {
            if !out.is_empty() {
                out.push('\n');
            }
            out.push('[');
            out.push_str(name);
            out.push_str("]\n");
            for (key, entry) in &section.entries {
                out.push_str(key);
                out.push_str(" = \"");
                out.push_str(&escape(&entry.value));
                out.push_str("\"\n");
            }
        }
        out
    }

    pub fn get(&self, section: &str, key: &str) -> Option<&str> {
        Some(self.sections.get(section)?.entries.get(key)?.value.as_str())
    }

    fn entry(&self, section: &str, key: &str) -> Option<&Entry> {
        self.sections.get(section)?.entries.get(key)
    }

    pub fn set(&mut self, section: &str, key: &str, value: &str) -> anyhow::Result<()> {
        anyhow::ensure!(
            !value.chars().any(char::is_control),
            "a config value may not hold control characters ({section}.{key})"
        );
        let section = self.sections.entry(section.to_owned()).or_default();
        section.entries.insert(
            key.to_owned(),
            Entry {
                value: value.to_owned(),
                line: 0,
            },
        );
        Ok(())
    }

    pub fn remove_section(&mut self, section: &str) {
        self.sections.remove(section);
    }

    pub fn is_empty(&self) -> bool {
        self.sections.values().all(|s| s.entries.is_empty())
    }
}

fn is_section_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_')
}

fn is_key_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '-' | '_')
}

fn unquote(raw: &str) -> Result<String, String> {
    let inner = raw
        .strip_prefix('"')
        .and_then(|r| r.strip_suffix('"'))
        .ok_or_else(|| "a value must be a double-quoted string".to_owned())?;
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => match chars.next() {
                Some('\\') => out.push('\\'),
                Some('"') => out.push('"'),
                _ => return Err("only `\\\\` and `\\\"` are escapes".to_owned()),
            },
            '"' => return Err("an unescaped `\"` inside a value".to_owned()),
            other => out.push(other),
        }
    }
    Ok(out)
}

fn escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

// ---------------------------------------------------------------------------
// Where the files live
// ---------------------------------------------------------------------------

/// The paths one profile uses. `--profile` makes config, credential and cached
/// tokens disjoint, so two profiles never see each other's anything.
#[derive(Debug, Clone)]
pub struct Paths {
    home: PathBuf,
    profile: String,
}

impl Paths {
    /// The real paths, rooted at `$HOME`.
    pub fn new(profile: &str) -> Paths {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."));
        Paths::under(home, profile)
    }

    /// The same layout under an explicit home — what the tests drive.
    pub fn under(home: impl Into<PathBuf>, profile: &str) -> Paths {
        Paths {
            home: home.into(),
            profile: profile.to_owned(),
        }
    }

    pub fn profile(&self) -> &str {
        &self.profile
    }

    pub fn home(&self) -> &Path {
        &self.home
    }

    pub fn config_dir(&self) -> PathBuf {
        self.home.join(".config").join("reachpad")
    }

    pub fn state_dir(&self) -> PathBuf {
        self.home
            .join(".local")
            .join("state")
            .join("reachpad")
            .join(&self.profile)
    }

    pub fn config_file(&self) -> PathBuf {
        self.config_dir().join("config.toml")
    }

    pub fn credentials_file(&self) -> PathBuf {
        self.config_dir().join("credentials.toml")
    }

    /// The section both files key this profile's settings under.
    pub fn section(&self) -> String {
        format!("profile.{}", self.profile)
    }
}

fn load_doc(path: &Path, allowed: &[&str]) -> anyhow::Result<Doc> {
    let Some(text) = privatefile::read(path)? else {
        return Ok(Doc::default());
    };
    let doc = Doc::parse(&text)
        .map_err(|r| anyhow::anyhow!("{}:{}: {}", path.display(), r.line, r.reason))?;
    for (name, section) in &doc.sections {
        if !name.starts_with("profile.") {
            bail!(
                "{}:{}: unknown section `[{name}]` (sections are `[profile.<name>]`)",
                path.display(),
                section.line
            );
        }
        for (key, entry) in &section.entries {
            if !allowed.contains(&key.as_str()) {
                bail!(
                    "{}:{}: unknown key `{key}` (this file takes {})",
                    path.display(),
                    entry.line,
                    allowed.join(", ")
                );
            }
        }
    }
    Ok(doc)
}

fn u64_field(path: &Path, doc: &Doc, section: &str, key: &str) -> anyhow::Result<Option<u64>> {
    let Some(entry) = doc.entry(section, key) else {
        return Ok(None);
    };
    let parsed = entry
        .value
        .parse::<u64>()
        .with_context(|| format!("{}:{}: `{key}` is not a number", path.display(), entry.line))?;
    Ok(Some(parsed))
}

// ---------------------------------------------------------------------------
// config.toml
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Config {
    pub endpoint: Option<String>,
}

pub fn load_config(paths: &Paths) -> anyhow::Result<Config> {
    let path = paths.config_file();
    let doc = load_doc(&path, CONFIG_KEYS)?;
    Ok(Config {
        endpoint: doc.get(&paths.section(), "endpoint").map(str::to_owned),
    })
}

/// Persist the endpoint for this profile, leaving every other profile alone.
pub fn save_endpoint(paths: &Paths, endpoint: &str) -> anyhow::Result<()> {
    let path = paths.config_file();
    let mut doc = load_doc(&path, CONFIG_KEYS)?;
    doc.set(&paths.section(), "endpoint", endpoint)?;
    privatefile::write(&path, doc.render().as_bytes())
}

// ---------------------------------------------------------------------------
// credentials.toml
// ---------------------------------------------------------------------------

/// The long-lived operator credential from reachpad.dev/connect, plus what the
/// server told us about the row it belongs to (`auth logout` revokes exactly
/// that row).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credential {
    pub operator_token: String,
    pub token_id: Option<String>,
    pub expires_at_ms: Option<u64>,
}

impl Credential {
    /// Carrier 1: `Authorization: Bearer` — every route but the three below.
    pub fn bearer(&self) -> &str {
        &self.operator_token
    }

    /// Carrier 2: the `operator_token` FIELD of the request body, which is how
    /// `POST /v1/api-keys`, `GET /v1/api-keys` and `POST /v1/api-keys/:id/
    /// revoke` take it (docs/TRAPS.md trap 35). Same secret, different place on
    /// the wire; the two spellings exist so a call site cannot pick the wrong
    /// one by accident.
    pub fn body_value(&self) -> &str {
        &self.operator_token
    }
}

/// What is on disk for this profile. `Expired` is distinct from `Missing`
/// because the remedy differs and the sentences differ.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stored {
    Missing,
    Expired,
    Present(Credential),
}

/// Expiry, decided fail-closed: `now_ms == 0` means the clock read failed
/// (`wall_now_ms` returns 0 on error, docs/API.md §11), and a credential whose
/// age cannot be judged is treated as expired rather than as fresh.
pub fn is_expired(expires_at_ms: Option<u64>, now_ms: u64) -> bool {
    match expires_at_ms {
        None => false,
        Some(expires_at_ms) => now_ms == 0 || now_ms >= expires_at_ms,
    }
}

pub fn load_credential(paths: &Paths, now_ms: u64) -> anyhow::Result<Stored> {
    let path = paths.credentials_file();
    let doc = load_doc(&path, CREDENTIAL_KEYS)?;
    let section = paths.section();
    let Some(operator_token) = doc.get(&section, "operator_token") else {
        return Ok(Stored::Missing);
    };
    if operator_token.trim().is_empty() {
        return Ok(Stored::Missing);
    }
    let expires_at_ms = u64_field(&path, &doc, &section, "token_expires_at_ms")?;
    if is_expired(expires_at_ms, now_ms) {
        return Ok(Stored::Expired);
    }
    Ok(Stored::Present(Credential {
        operator_token: operator_token.trim().to_owned(),
        token_id: doc.get(&section, "token_id").map(str::to_owned),
        expires_at_ms,
    }))
}

/// Write this profile's credential, REPLACING what was there.
///
/// The section is cleared first rather than merged into: `token_id` and
/// `token_expires_at_ms` are absent on a fleet that predates ADR-0069, and a
/// merge would leave the PREVIOUS credential's id and expiry describing a new
/// credential — an `auth logout` that revokes a row still in use on another
/// machine, and an expiry that refuses a credential that was just accepted.
/// The file says exactly what is in it and nothing else.
pub fn save_credential(paths: &Paths, credential: &Credential) -> anyhow::Result<()> {
    let path = paths.credentials_file();
    let mut doc = load_doc(&path, CREDENTIAL_KEYS)?;
    let section = paths.section();
    doc.remove_section(&section);
    doc.set(&section, "operator_token", credential.operator_token.trim())?;
    if let Some(id) = &credential.token_id {
        doc.set(&section, "token_id", id)?;
    }
    if let Some(expires_at_ms) = credential.expires_at_ms {
        doc.set(&section, "token_expires_at_ms", &expires_at_ms.to_string())?;
    }
    privatefile::write(&path, doc.render().as_bytes())
}

/// Forget this profile's credential. Other profiles keep theirs; a file left
/// holding nothing at all is deleted rather than left as an empty husk.
pub fn forget_credential(paths: &Paths) -> anyhow::Result<()> {
    let path = paths.credentials_file();
    let mut doc = load_doc(&path, CREDENTIAL_KEYS)?;
    doc.remove_section(&paths.section());
    if doc.is_empty() {
        privatefile::remove(&path)
    } else {
        privatefile::write(&path, doc.render().as_bytes())
    }
}

// ---------------------------------------------------------------------------
// Secret-carrying flag values
// ---------------------------------------------------------------------------

/// The three ways a secret may be named on the command line. A literal is
/// REFUSED as a usage error (exit 2): inside a workspace every process's argv
/// is readable, so a key passed literally is a key handed to whatever else is
/// running there (docs/TRAPS.md trap 36).
pub fn read_secret_arg(flag: &str, value: &str) -> Result<String, CliError> {
    let secret = if value == "-" {
        let mut buf = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut buf)
            .with_context(|| format!("reading {flag} from stdin"))?;
        buf
    } else if let Some(path) = value.strip_prefix('@') {
        std::fs::read_to_string(path).with_context(|| format!("reading {flag} from {path}"))?
    } else if let Some(name) = value.strip_prefix("env:") {
        std::env::var(name)
            .with_context(|| format!("reading {flag} from the environment variable {name}"))?
    } else {
        return Err(CliError::usage(format!(
            "{flag} does not take the secret itself — argv is readable by every other process \
             in the workspace. Use `{flag} -` (stdin), `{flag} @<path>` or `{flag} env:<VAR>`."
        )));
    };
    let secret = secret.trim().to_owned();
    if secret.is_empty() {
        return Err(CliError::usage(format!(
            "{flag} resolved to an empty value"
        )));
    }
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("reach-conf-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn the_subset_round_trips() {
        let text = "# a comment\n\n[profile.default]\nendpoint = \"m1.reachpad.dev\"\n\n[profile.staging]\nendpoint = \"a \\\"b\\\" c\\\\d\"\n";
        let doc = Doc::parse(text).unwrap();
        assert_eq!(
            doc.get("profile.default", "endpoint"),
            Some("m1.reachpad.dev")
        );
        assert_eq!(doc.get("profile.staging", "endpoint"), Some("a \"b\" c\\d"));
        let again = Doc::parse(&doc.render()).unwrap();
        assert_eq!(
            again.get("profile.staging", "endpoint"),
            doc.get("profile.staging", "endpoint")
        );
        assert_eq!(again.render(), doc.render());
    }

    #[test]
    fn every_line_the_subset_does_not_understand_is_refused() {
        let cases = [
            ("[profile.default]\nendpoint = m1.reachpad.dev\n", 2),
            ("[profile.default]\nendpoint\n", 2),
            ("endpoint = \"x\"\n", 1),
            ("[profile default\nendpoint = \"x\"\n", 1),
            ("[profile.default]\nend point = \"x\"\n", 2),
            ("[profile.default]\nendpoint = \"a\\tb\"\n", 2),
            ("[profile.default]\nendpoint = \"a\"b\"\n", 2),
            ("[profile.default]\nendpoint = \"a\"\nendpoint = \"b\"\n", 3),
        ];
        for (text, line) in cases {
            let refusal = Doc::parse(text).unwrap_err();
            assert_eq!(refusal.line, line, "{text:?} -> {refusal:?}");
        }
    }

    #[test]
    fn an_unknown_key_is_refused_and_names_the_file_and_line() {
        let dir = scratch("unknown");
        let paths = Paths::under(&dir, DEFAULT_PROFILE);
        privatefile::write(
            &paths.config_file(),
            b"[profile.default]\nendpoint = \"h\"\nendpiont = \"h\"\n",
        )
        .unwrap();
        let err = load_config(&paths).unwrap_err().to_string();
        assert!(err.contains("config.toml:3"), "{err}");
        assert!(err.contains("endpiont"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn zero_environment_is_a_working_configuration() {
        // What `dev_mode_boots_with_zero_env` used to prove, in the layer that
        // replaced it: a bare machine with no config and no environment loads,
        // holds no credential, and says so instead of failing.
        let dir = scratch("zeroenv");
        let paths = Paths::under(&dir, DEFAULT_PROFILE);
        assert_eq!(load_config(&paths).unwrap(), Config { endpoint: None });
        assert_eq!(load_credential(&paths, 1).unwrap(), Stored::Missing);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_endpoint_and_credential_persist_per_profile() {
        let dir = scratch("profiles");
        let default = Paths::under(&dir, DEFAULT_PROFILE);
        let staging = Paths::under(&dir, "staging");
        save_endpoint(&default, "m1.reachpad.dev").unwrap();
        save_endpoint(&staging, "staging.reachpad.dev").unwrap();
        save_credential(
            &default,
            &Credential {
                operator_token: "rpop1.default".into(),
                token_id: Some("tok-1".into()),
                expires_at_ms: Some(5_000),
            },
        )
        .unwrap();
        save_credential(
            &staging,
            &Credential {
                operator_token: "rpop1.staging".into(),
                token_id: None,
                expires_at_ms: None,
            },
        )
        .unwrap();

        assert_eq!(
            load_config(&default).unwrap().endpoint.as_deref(),
            Some("m1.reachpad.dev")
        );
        assert_eq!(
            load_config(&staging).unwrap().endpoint.as_deref(),
            Some("staging.reachpad.dev")
        );
        let Stored::Present(c) = load_credential(&default, 1).unwrap() else {
            panic!("the default profile has a credential");
        };
        assert_eq!(c.bearer(), "rpop1.default");
        assert_eq!(c.body_value(), c.bearer());
        assert_eq!(c.token_id.as_deref(), Some("tok-1"));

        // Logging out of one profile leaves the other's credential and both
        // endpoints untouched.
        forget_credential(&default).unwrap();
        assert_eq!(load_credential(&default, 1).unwrap(), Stored::Missing);
        assert!(matches!(
            load_credential(&staging, 1).unwrap(),
            Stored::Present(_)
        ));
        assert_eq!(
            load_config(&default).unwrap().endpoint.as_deref(),
            Some("m1.reachpad.dev")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn expiry_fails_closed() {
        let dir = scratch("expiry");
        let paths = Paths::under(&dir, DEFAULT_PROFILE);
        save_credential(
            &paths,
            &Credential {
                operator_token: "rpop1.x".into(),
                token_id: None,
                expires_at_ms: Some(1_000),
            },
        )
        .unwrap();
        assert!(matches!(
            load_credential(&paths, 999).unwrap(),
            Stored::Present(_)
        ));
        assert_eq!(load_credential(&paths, 1_000).unwrap(), Stored::Expired);
        // A clock that could not be read is not a fresh credential.
        assert_eq!(load_credential(&paths, 0).unwrap(), Stored::Expired);
        assert!(!is_expired(None, 0), "no expiry recorded claims nothing");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Logging in REPLACES the row. A fleet that predates ADR-0069 echoes no
    /// `token_id` and no expiry, and a merge would leave the previous
    /// credential's id on disk — so `auth logout` would revoke a row still in
    /// use on another machine, and the previous expiry would refuse the
    /// credential that was just accepted.
    #[test]
    fn a_second_login_replaces_the_row_it_does_not_merge_into_it() {
        let dir = scratch("relogin");
        let paths = Paths::under(&dir, DEFAULT_PROFILE);
        save_credential(
            &paths,
            &Credential {
                operator_token: "rpop1.first".into(),
                token_id: Some("tok-first".into()),
                expires_at_ms: Some(9_000),
            },
        )
        .unwrap();
        save_credential(
            &paths,
            &Credential {
                operator_token: "rpop1.second".into(),
                token_id: None,
                expires_at_ms: None,
            },
        )
        .unwrap();

        let Stored::Present(c) = load_credential(&paths, 10_000).unwrap() else {
            panic!("the second credential is present, and not expired by the first's expiry");
        };
        assert_eq!(c.bearer(), "rpop1.second");
        assert_eq!(c.token_id, None, "the first credential's id is gone");
        assert_eq!(c.expires_at_ms, None);
        let text = std::fs::read_to_string(paths.credentials_file()).unwrap();
        assert!(!text.contains("tok-first"), "{text}");
        assert!(!text.contains("9000"), "{text}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_secret_is_never_taken_from_argv() {
        let dir = scratch("secretarg");
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("key");
        std::fs::write(&file, "rpak1.abc.def\n").unwrap();

        let err = read_secret_arg("--api-key", "rpak1.abc.def").unwrap_err();
        assert_eq!(err.exit_code, crate::errors::EXIT_USAGE);
        assert!(err.message.contains("--api-key -"), "{}", err.message);
        assert!(err.message.contains("@<path>"), "{}", err.message);
        assert!(err.message.contains("env:<VAR>"), "{}", err.message);

        assert_eq!(
            read_secret_arg("--api-key", &format!("@{}", file.display())).unwrap(),
            "rpak1.abc.def"
        );
        std::env::set_var("REACH_TEST_SECRET_ARG", "rpak1.env.value");
        assert_eq!(
            read_secret_arg("--api-key", "env:REACH_TEST_SECRET_ARG").unwrap(),
            "rpak1.env.value"
        );
        std::env::remove_var("REACH_TEST_SECRET_ARG");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
