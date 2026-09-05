//! `reachpad.json` — the file the first publish writes beside the source, and
//! the thing every later app verb reads to know what it is looking at.
//!
//! ```json
//! { "app": "app_…", "kind": "page", "entry": "index.html",
//!   "env": {}, "services": [], "secrets": [] }
//! ```
//!
//! The schema is ADDITIVE ONLY (reports/apps-v1 "Fixed forever"), which is why
//! [`Manifest`] keeps an `extra` map of every key it does not know: a newer
//! CLI's field must survive an older one rewriting the file after `link` or a
//! first `publish`, and a field this version drops is a field the server never
//! sees again.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::errors::CliError;

/// The file name, everywhere. Never spelled inline.
pub const MANIFEST_FILE: &str = "reachpad.json";

/// The runtime a version is built for (`AppKind` in API.md).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// A file tree served as-is; `entry` is what `/` answers with.
    Page,
    /// One JavaScript module exporting `default { fetch(request, env) }`.
    Function,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Page => "page",
            Kind::Function => "function",
        }
    }
}

impl std::fmt::Display for Kind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    /// Set by the first publish (or by `link`). Absent means "not linked yet".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app: Option<String>,
    pub kind: Kind,
    pub entry: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub services: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secrets: Vec<String>,
    /// Every key this version of the CLI does not know, kept verbatim.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

impl Manifest {
    /// What `init` writes for a tree that has neither an entry nor a manifest.
    pub fn page(entry: &str) -> Manifest {
        Manifest {
            app: None,
            kind: Kind::Page,
            entry: entry.to_owned(),
            env: BTreeMap::new(),
            services: Vec::new(),
            secrets: Vec::new(),
            extra: BTreeMap::new(),
        }
    }

    /// The `manifest` object the create and version routes take. `app` is the
    /// client's own bookkeeping and is deliberately not sent.
    pub fn wire(&self) -> serde_json::Value {
        let mut value = serde_json::json!({
            "kind": self.kind.as_str(),
            "entry": self.entry,
            "env": self.env,
            "services": self.services,
            "secrets": self.secrets,
        });
        let object = value.as_object_mut().expect("a json! object");
        for (key, extra) in &self.extra {
            object.insert(key.clone(), extra.clone());
        }
        value
    }
}

/// A manifest and the directory it governs.
#[derive(Debug, Clone)]
pub struct Linked {
    pub root: PathBuf,
    pub manifest: Manifest,
}

impl Linked {
    pub fn path(&self) -> PathBuf {
        self.root.join(MANIFEST_FILE)
    }
}

/// Read `reachpad.json` from `dir` itself. `Ok(None)` when there is none.
pub fn read_at(dir: &Path) -> Result<Option<Manifest>, CliError> {
    let path = dir.join(MANIFEST_FILE);
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(super::failure(format!("reading {}: {e}", path.display()))),
    };
    Ok(Some(parse(&text).map_err(|reason| {
        super::failure(format!("{}: {reason}", path.display()))
    })?))
}

/// Parse manifest text, with the schema refusals said in full sentences.
pub fn parse(text: &str) -> Result<Manifest, String> {
    let value: serde_json::Value =
        serde_json::from_str(text).map_err(|e| format!("this is not JSON ({e})"))?;
    let object = value
        .as_object()
        .ok_or_else(|| "a manifest is a JSON object".to_owned())?;
    match object.get("kind").and_then(|k| k.as_str()) {
        Some("page") | Some("function") => {}
        Some(other) => {
            return Err(format!(
                "`kind` is {other:?}; it is \"page\" or \"function\""
            ))
        }
        None => return Err("`kind` is missing; it is \"page\" or \"function\"".to_owned()),
    }
    match object.get("entry").and_then(|e| e.as_str()) {
        Some(entry) if !entry.trim().is_empty() => {
            if entry.starts_with('/') || entry.split('/').any(|part| part == "..") {
                return Err(format!(
                    "`entry` is {entry:?}; it is a path relative to this folder"
                ));
            }
        }
        Some(_) => return Err("`entry` is empty".to_owned()),
        None => return Err("`entry` is missing".to_owned()),
    }
    // `secrets` is a list of names an app binds, and every one of them has to
    // be a name the org could have set. A publish that names STRIPE_key fails
    // at the front door with a sentence about a secret nobody set, which is a
    // true sentence about the wrong problem; this one is about the typo.
    if let Some(secrets) = object.get("secrets") {
        let list = secrets.as_array().ok_or_else(|| {
            format!(
                "`secrets` is {}; it is an array of names, like [\"STRIPE_KEY\"]",
                shape(secrets)
            )
        })?;
        for entry in list {
            let name = entry.as_str().ok_or_else(|| {
                format!(
                    "`secrets` holds {}; every entry is a name, like \"STRIPE_KEY\"",
                    shape(entry)
                )
            })?;
            if let Some(reason) = super::secrets::name_reason(name) {
                return Err(format!("`secrets`: {reason}"));
            }
        }
    }
    serde_json::from_value(value).map_err(|e| format!("{e}"))
}

/// What kind of JSON this is, for a refusal that has to say what arrived.
fn shape(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "a boolean",
        serde_json::Value::Number(_) => "a number",
        serde_json::Value::String(_) => "a string",
        serde_json::Value::Array(_) => "an array",
        serde_json::Value::Object(_) => "an object",
    }
}

/// Write the manifest back, pretty and newline-terminated, so a person diffing
/// it after a publish sees one changed line rather than one changed file.
pub fn write(dir: &Path, manifest: &Manifest) -> Result<(), CliError> {
    let path = dir.join(MANIFEST_FILE);
    let mut text = serde_json::to_string_pretty(manifest)
        .map_err(|e| super::failure(format!("rendering {}: {e}", path.display())))?;
    text.push('\n');
    std::fs::write(&path, text)
        .map_err(|e| super::failure(format!("writing {}: {e}", path.display())))
}

/// The linked project this command is inside: `reachpad.json` in `start` or in
/// any parent of it. This is what makes every verb work with no flags from
/// anywhere in the tree.
pub fn find_upward(start: &Path) -> Result<Option<Linked>, CliError> {
    let mut dir = Some(start);
    while let Some(current) = dir {
        if let Some(manifest) = read_at(current)? {
            return Ok(Some(Linked {
                root: current.to_path_buf(),
                manifest,
            }));
        }
        dir = current.parent();
    }
    Ok(None)
}

/// What `init` guesses from the files already in the folder: `server.js` (or
/// `.mjs`) means a function, an `index.html` means a page, and an empty folder
/// means the page an agent is about to write.
pub fn detect(dir: &Path) -> Manifest {
    for candidate in ["server.js", "server.mjs"] {
        if dir.join(candidate).is_file() {
            return Manifest {
                kind: Kind::Function,
                entry: candidate.to_owned(),
                ..Manifest::page("index.html")
            };
        }
    }
    Manifest::page("index.html")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_manifest_round_trips_and_keeps_fields_this_version_never_heard_of() {
        let text = r#"{"app":"app_1","kind":"function","entry":"server.js",
            "env":{"A":"b"},"services":["db"],"secrets":["S"],"regions":["iad"]}"#;
        let manifest = parse(text).unwrap();
        assert_eq!(manifest.kind, Kind::Function);
        assert_eq!(manifest.entry, "server.js");
        assert_eq!(manifest.app.as_deref(), Some("app_1"));
        assert_eq!(manifest.services, vec!["db".to_owned()]);
        // The additive-only rule, enforced: an unknown key survives a rewrite.
        assert_eq!(
            manifest.extra.get("regions"),
            Some(&serde_json::json!(["iad"]))
        );
        let again = parse(&serde_json::to_string(&manifest).unwrap()).unwrap();
        assert_eq!(again, manifest);
        assert_eq!(again.wire()["regions"], serde_json::json!(["iad"]));
        // `app` is the CLI's bookkeeping; the server is never told it.
        assert!(again.wire().get("app").is_none());
    }

    #[test]
    fn the_schema_refusals_name_what_is_wrong() {
        assert!(parse("nonsense").unwrap_err().contains("not JSON"));
        assert!(parse(r#"{"entry":"a"}"#).unwrap_err().contains("`kind`"));
        assert!(parse(r#"{"kind":"site","entry":"a"}"#)
            .unwrap_err()
            .contains("\"page\" or \"function\""));
        assert!(parse(r#"{"kind":"page"}"#).unwrap_err().contains("`entry`"));
        // An entry that climbs out of the tree is refused here, not at the tar.
        assert!(parse(r#"{"kind":"page","entry":"../x.html"}"#)
            .unwrap_err()
            .contains("relative"));
        assert!(parse(r#"{"kind":"page","entry":"/etc/passwd"}"#).is_err());
    }

    #[test]
    fn a_page_manifest_omits_the_empty_halves() {
        let text = serde_json::to_string(&Manifest::page("index.html")).unwrap();
        assert_eq!(text, r#"{"kind":"page","entry":"index.html"}"#);
    }
}
