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
const CREDENTIAL_KEYS: &[&str] = &[
    "operator_token",
    "token_id",
    "token_expires_at_ms",
    "endpoint_host",
    // The WorkOS half of the same sign-in. The apps API (reports/apps-v1
    // API.md "Auth") takes the WorkOS access token as its bearer, not the
    // `rpop1` operator credential, so the pair the device flow returns is kept
    // here beside it rather than thrown away. Same file, same 0600, same
    // `logout`. See `Credential::workos`.
    "workos_access_token",
    "workos_refresh_token",
    "workos_expires_at_ms",
    "workos_client_id",
];

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
    ///
    /// An unset `HOME` is REFUSED rather than defaulted. It used to fall back
    /// to `.`, which does not mean "nowhere" — it means the current directory,
    /// so `auth login` under a cron job, a container entrypoint or a `sudo`
    /// that dropped the variable wrote `./.config/reachpad/credentials.toml`
    /// into whatever repository the command happened to run in, and the next
    /// command in a different directory read no credential and started a fresh
    /// sign-in. A long-lived operator credential committed to a checkout is
    /// the worst outcome available here, and the relocation was silent.
    /// Failing is recoverable in one line; the disclosure is not.
    pub fn new(profile: &str) -> anyhow::Result<Paths> {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .filter(|home| !home.as_os_str().is_empty())
            .context(
                "HOME is not set, so there is nowhere to keep your credential. This used to \
                 fall back to the current directory, which wrote the credential into whatever \
                 repository you happened to be in. Set HOME, or pass an API key with \
                 `--api-key env:<VAR>` for the verbs that take one.",
            )?;
        Ok(Paths::under(home, profile))
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
/// that row) and the host that issued it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credential {
    /// The fleet credential, EMPTY for an apps-only sign-in.
    ///
    /// reachpad.dev answers the credential exchange with `fleet_unconfigured`
    /// when it is not a fleet front door, which is the ordinary answer now
    /// that the product there is apps. That sign-in is real — it produced a
    /// WorkOS session the apps API takes — it just has no operator half. Read
    /// it through [`Credential::has_operator`] rather than by testing the
    /// string, and never put an empty one on a bearer header.
    pub operator_token: String,
    pub token_id: Option<String>,
    pub expires_at_ms: Option<u64>,
    /// The control-plane HOST this credential was signed in against.
    ///
    /// Without it a stored credential was portable to any endpoint BY
    /// CONSTRUCTION: nothing on disk said where it came from, so nothing could
    /// refuse to send it somewhere else. `None` is a record written before this
    /// field existed — see [`Credential::check_endpoint`] for what that costs.
    ///
    /// The host, not the authority: the port a dev controld listens on is not
    /// a trust boundary, and a laptop that moves between `127.0.0.1:7401` and
    /// `127.0.0.1:9001` is still talking to itself.
    pub endpoint_host: Option<String>,
    /// The WorkOS session the same sign-in produced, when there was one.
    ///
    /// `None` for a credential installed with `--operator-token`, which never
    /// touched WorkOS: that laptop can drive workspaces and cannot drive apps,
    /// and the apps verbs say so rather than sending the apps API a credential
    /// it does not accept.
    pub workos: Option<WorkosSession>,
}

/// The WorkOS access/refresh pair, and the client id that refreshes it.
///
/// A WorkOS access token lives about five minutes, so the refresh token is the
/// durable half and the access token is a cache of the last refresh. Both are
/// secrets and both live in the same 0600 file as the operator credential — a
/// second store would be a second place to get the mode wrong.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkosSession {
    pub access_token: String,
    pub refresh_token: String,
    /// When the access token stops being accepted, from its own `exp` claim.
    pub expires_at_ms: Option<u64>,
    /// The public CLI client id the deployment published; refreshing needs it.
    pub client_id: String,
}

/// What [`Credential::check_endpoint`] found. The caller decides what a
/// warning costs; only [`Binding::Foreign`] is a refusal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Binding {
    /// Bound to this host, or bound to no host because the endpoint is
    /// loopback — this machine talking to itself.
    Ok,
    /// A record written before `endpoint_host` existed. Degraded to a warning
    /// on purpose: hard-failing would sign every existing laptop out on
    /// upgrade, in the name of a binding that laptop never had a chance to
    /// write. It carries the sentence to print and the re-auth prompt.
    Unbound,
    /// Bound to a DIFFERENT host than the one this command is aimed at. This
    /// is the case the field exists for and it is always a refusal.
    Foreign { stored_host: String },
}

impl Credential {
    /// Refuse to hand this credential to a host other than the one that issued
    /// it.
    ///
    /// The bearer header is the whole attack surface: an `rpop1` credential is
    /// the account's root secret, it is long-lived, and every control call
    /// attaches it. Pinning `--endpoint` to Reachpad DNS closes the arbitrary
    /// -host hole; this closes the one inside it, where a credential minted
    /// against one fleet host is replayed against another.
    ///
    /// Loopback is exempt in both directions. A dev controld is this machine,
    /// the port it listens on is ephemeral in every integration test, and a
    /// binding that changes on every `cargo nextest run` would teach people to
    /// ignore the warning.
    pub fn check_endpoint(&self, endpoint_host: &str) -> Binding {
        let endpoint_host = endpoint_host.trim();
        match self.endpoint_host.as_deref().map(str::trim) {
            None | Some("") => Binding::Unbound,
            Some(stored) if stored.eq_ignore_ascii_case(endpoint_host) => Binding::Ok,
            Some(stored) if is_loopback_host(stored) && is_loopback_host(endpoint_host) => {
                Binding::Ok
            }
            Some(stored) => Binding::Foreign {
                stored_host: stored.to_owned(),
            },
        }
    }

    /// Whether this record has a fleet credential at all.
    ///
    /// False for an apps-only sign-in, and every control-plane door checks it:
    /// an empty bearer is not a credential, and sending one would turn "this
    /// endpoint has no fleet" into an unauthorized from a host that was never
    /// going to answer.
    pub fn has_operator(&self) -> bool {
        !self.operator_token.trim().is_empty()
    }

    /// Carrier 1: `Authorization: Bearer` — every route but the three below.
    ///
    /// Only for a record [`Credential::has_operator`] said yes about.
    pub fn bearer(&self) -> &str {
        &self.operator_token
    }

    /// The WorkOS access token, when there is one that is still good.
    pub fn workos_access(&self, now_ms: u64) -> Option<&str> {
        let workos = self.workos.as_ref()?;
        // A minute of margin, taken off the expiry rather than added to the
        // clock, so `now_ms == 0` (a clock that could not be read) fails
        // closed into a refresh rather than into a stale bearer.
        if is_expired(
            workos.expires_at_ms.map(|at| at.saturating_sub(60_000)),
            now_ms,
        ) {
            return None;
        }
        Some(&workos.access_token)
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
    // All three are required together: an access token with no refresh token
    // is five minutes of apps access and then a sign-in, and a refresh token
    // with no client id cannot be spent. A half-written record is read as no
    // record.
    let workos = match (
        doc.get(&section, "workos_access_token"),
        doc.get(&section, "workos_refresh_token"),
        doc.get(&section, "workos_client_id"),
    ) {
        (Some(access), Some(refresh), Some(client_id))
            if !access.is_empty() && !refresh.is_empty() && !client_id.is_empty() =>
        {
            Some(WorkosSession {
                access_token: access.to_owned(),
                refresh_token: refresh.to_owned(),
                expires_at_ms: u64_field(&path, &doc, &section, "workos_expires_at_ms")?,
                client_id: client_id.to_owned(),
            })
        }
        _ => None,
    };
    let endpoint_host = doc
        .get(&section, "endpoint_host")
        .map(|host| host.trim().to_owned())
        .filter(|host| !host.is_empty());
    let operator_token = doc
        .get(&section, "operator_token")
        .map(str::trim)
        .filter(|token| !token.is_empty());
    let Some(operator_token) = operator_token else {
        // No operator half. With a WorkOS session that is an apps-only
        // sign-in and a usable record; without one there is nothing here.
        // The fleet fields stay empty rather than being invented: `token_id`
        // names a row to revoke and `token_expires_at_ms` an expiry, and
        // neither exists when no credential was ever minted.
        return Ok(match workos {
            Some(workos) => Stored::Present(Credential {
                operator_token: String::new(),
                token_id: None,
                expires_at_ms: None,
                endpoint_host,
                workos: Some(workos),
            }),
            None => Stored::Missing,
        });
    };
    let expires_at_ms = u64_field(&path, &doc, &section, "token_expires_at_ms")?;
    if is_expired(expires_at_ms, now_ms) {
        return Ok(Stored::Expired);
    }
    Ok(Stored::Present(Credential {
        operator_token: operator_token.to_owned(),
        token_id: doc.get(&section, "token_id").map(str::to_owned),
        expires_at_ms,
        endpoint_host,
        workos,
    }))
}

/// The three names that mean "this machine", matched literally. No DNS
/// resolution, for the same reason [`crate::http_min::Endpoint::is_loopback`]
/// does none: a name that merely *resolves* to 127.0.0.1 today must not be
/// able to pass itself off as loopback tomorrow.
fn is_loopback_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<std::net::IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false)
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
    // Omitted entirely for an apps-only sign-in. An empty value would be a
    // key that reads back as no key, which is a slower way of saying nothing.
    if credential.has_operator() {
        doc.set(&section, "operator_token", credential.operator_token.trim())?;
    }
    if let Some(id) = &credential.token_id {
        doc.set(&section, "token_id", id)?;
    }
    if let Some(expires_at_ms) = credential.expires_at_ms {
        doc.set(&section, "token_expires_at_ms", &expires_at_ms.to_string())?;
    }
    if let Some(host) = &credential.endpoint_host {
        doc.set(&section, "endpoint_host", host.trim())?;
    }
    if let Some(workos) = &credential.workos {
        doc.set(&section, "workos_access_token", &workos.access_token)?;
        doc.set(&section, "workos_refresh_token", &workos.refresh_token)?;
        doc.set(&section, "workos_client_id", &workos.client_id)?;
        if let Some(expires_at_ms) = workos.expires_at_ms {
            doc.set(&section, "workos_expires_at_ms", &expires_at_ms.to_string())?;
        }
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
                endpoint_host: Some("m1.reachpad.dev".into()),
                workos: None,
            },
        )
        .unwrap();
        save_credential(
            &staging,
            &Credential {
                operator_token: "rpop1.staging".into(),
                token_id: None,
                expires_at_ms: None,
                endpoint_host: Some("staging.reachpad.dev".into()),
                workos: None,
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
        assert_eq!(c.endpoint_host.as_deref(), Some("m1.reachpad.dev"));

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

    /// A stored credential used to be portable to any endpoint BY
    /// CONSTRUCTION: the record held a token, an id and an expiry, and nothing
    /// that said where it came from — so nothing could refuse to send it
    /// somewhere else. The `rpop1` credential is the account's root secret and
    /// it is long-lived, so one delivery to the wrong host is permanent.
    #[test]
    fn a_credential_is_refused_against_an_endpoint_it_was_not_issued_for() {
        let bound = |host: Option<&str>| Credential {
            operator_token: "rpop1.id.secret".into(),
            token_id: None,
            expires_at_ms: None,
            endpoint_host: host.map(str::to_owned),
            workos: None,
        };

        assert_eq!(
            bound(Some("m1.reachpad.dev")).check_endpoint("m1.reachpad.dev"),
            Binding::Ok
        );
        // Hostnames are case-insensitive; a credential is not re-issued
        // because someone typed the endpoint in capitals.
        assert_eq!(
            bound(Some("M1.Reachpad.Dev")).check_endpoint("m1.reachpad.dev"),
            Binding::Ok
        );
        // The case the field exists for.
        assert_eq!(
            bound(Some("m1.reachpad.dev")).check_endpoint("m2.reachpad.dev"),
            Binding::Foreign {
                stored_host: "m1.reachpad.dev".to_owned()
            }
        );
        // And a same-account sibling is still a different host: this is not a
        // "reachpad.dev or not" check, which is what `--endpoint` already does.
        assert_eq!(
            bound(Some("m1.reachpad.dev")).check_endpoint("staging.reachpad.dev"),
            Binding::Foreign {
                stored_host: "m1.reachpad.dev".to_owned()
            }
        );

        // Loopback is this machine whichever spelling and whichever port, and
        // an integration test gets a new ephemeral port every run. A binding
        // that broke on that would only teach people to ignore it.
        assert_eq!(
            bound(Some("127.0.0.1")).check_endpoint("localhost"),
            Binding::Ok
        );
        assert_eq!(bound(Some("::1")).check_endpoint("127.0.0.1"), Binding::Ok);
        // But loopback is not a wildcard in either direction.
        assert_eq!(
            bound(Some("127.0.0.1")).check_endpoint("m1.reachpad.dev"),
            Binding::Foreign {
                stored_host: "127.0.0.1".to_owned()
            }
        );

        // A record written before the field existed. A warning and a re-auth
        // prompt, NEVER a refusal: hard-failing here would sign out every
        // laptop on upgrade over a binding it never had a chance to write.
        assert_eq!(
            bound(None).check_endpoint("m1.reachpad.dev"),
            Binding::Unbound
        );
        assert_eq!(
            bound(Some("  ")).check_endpoint("m1.reachpad.dev"),
            Binding::Unbound
        );
    }

    /// The binding is worth nothing if it does not survive the file. It is
    /// written by `auth login` and read back by every command after it.
    #[test]
    fn the_endpoint_binding_round_trips_through_the_file() {
        let dir = scratch("binding");
        let paths = Paths::under(&dir, DEFAULT_PROFILE);
        save_credential(
            &paths,
            &Credential {
                operator_token: "rpop1.id.secret".into(),
                token_id: None,
                expires_at_ms: None,
                endpoint_host: Some("m1.reachpad.dev".into()),
                workos: None,
            },
        )
        .unwrap();
        let Stored::Present(c) = load_credential(&paths, 1).unwrap() else {
            panic!("the credential is present");
        };
        assert_eq!(c.endpoint_host.as_deref(), Some("m1.reachpad.dev"));
        assert_eq!(
            c.check_endpoint("evil.example.com"),
            Binding::Foreign {
                stored_host: "m1.reachpad.dev".to_owned()
            }
        );

        // A file written before the field existed still loads — the parser
        // refuses keys it does not know, so the reverse direction is what
        // would break, and it does not.
        privatefile::write(
            &paths.credentials_file(),
            b"[profile.default]\noperator_token = \"rpop1.old.secret\"\n",
        )
        .unwrap();
        let Stored::Present(c) = load_credential(&paths, 1).unwrap() else {
            panic!("a pre-binding credential still loads");
        };
        assert_eq!(c.endpoint_host, None);
        assert_eq!(c.check_endpoint("m1.reachpad.dev"), Binding::Unbound);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `HOME` unset used to fall back to `.`, which is not "nowhere" — it is
    /// the current directory, so `auth login` under a cron job or a container
    /// entrypoint wrote the account's long-lived credential into whatever
    /// repository the command ran in, and the next command in another
    /// directory found no credential and started a fresh sign-in.
    #[test]
    fn an_unset_home_refuses_rather_than_writing_the_credential_into_the_cwd() {
        // Every test is its own process under nextest, which is how this
        // workspace runs them — the same assumption `tests/common` makes when
        // it sets `HOME` for a scratch home.
        let restore = std::env::var_os("HOME");
        std::env::remove_var("HOME");
        let refused = Paths::new(DEFAULT_PROFILE);
        std::env::set_var("HOME", "");
        let empty = Paths::new(DEFAULT_PROFILE);
        if let Some(home) = restore {
            std::env::set_var("HOME", home);
        } else {
            std::env::remove_var("HOME");
        }

        let message = refused.expect_err("an unset HOME is refused").to_string();
        assert!(message.contains("HOME is not set"), "{message}");
        assert!(
            empty.is_err(),
            "an empty HOME is the same nowhere as an unset one"
        );
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
                endpoint_host: None,
                workos: None,
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
                endpoint_host: Some("first.reachpad.dev".into()),
                workos: None,
            },
        )
        .unwrap();
        save_credential(
            &paths,
            &Credential {
                operator_token: "rpop1.second".into(),
                token_id: None,
                expires_at_ms: None,
                endpoint_host: None,
                workos: None,
            },
        )
        .unwrap();

        let Stored::Present(c) = load_credential(&paths, 10_000).unwrap() else {
            panic!("the second credential is present, and not expired by the first's expiry");
        };
        assert_eq!(c.bearer(), "rpop1.second");
        assert_eq!(c.token_id, None, "the first credential's id is gone");
        assert_eq!(c.expires_at_ms, None);
        assert_eq!(
            c.endpoint_host, None,
            "the first credential's endpoint binding is gone too — a merge would leave the \
             new credential looking bound to the old host"
        );
        let text = std::fs::read_to_string(paths.credentials_file()).unwrap();
        assert!(!text.contains("tok-first"), "{text}");
        assert!(!text.contains("9000"), "{text}");
        assert!(!text.contains("first.reachpad.dev"), "{text}");
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
