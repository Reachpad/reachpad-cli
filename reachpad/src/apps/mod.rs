//! Apps: the second product this CLI drives.
//!
//! An app is a document. It has a name, an owner, a link, and a version history
//! where every publish is immutable; `https://<slug>.<apps-domain>/` points at
//! whichever version is live. None of that touches a workspace, a node or the
//! fleet control plane — the apps API is a separate service with a separate
//! credential (see [`client`]), and this module is the whole of the CLI's
//! knowledge of it.
//!
//! Two conventions run through every verb here, and both are load-bearing for
//! the agents that will use them:
//!
//! - **Every remote command prints one `URL:` line** and nothing else a caller
//!   has to parse. The agent instructions say to copy that line verbatim and
//!   never to construct a URL from a slug, because slugs get suffixed on
//!   collision and a constructed link is a link that 404s.
//! - **The first publish writes `reachpad.json` beside the source**, so every
//!   later command in that folder knows what it is looking at with no flags.

pub mod client;
pub mod db;
pub mod manifest;
pub mod pack;
pub mod secrets;
pub mod skill;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::cli::{
    AccessArg, AccessCommand, DevCommand, SecretsCommand, ShareRoleArg, SharesCommand, SkillCommand,
};
use crate::commands::Ctx;
use crate::errors::{CliError, EXIT_OK};

use client::Apps;
use manifest::{Kind, Linked, Manifest};

/// A local refusal: something this CLI decided, as opposed to something the
/// server said. Exit 1, like every apps failure.
pub fn failure(message: impl Into<String>) -> CliError {
    CliError {
        code: "apps".to_owned(),
        message: message.into(),
        next_command: None,
        retriable: false,
        status: None,
        exit_code: 1,
        data: None,
    }
}

/// Where `sync` keeps what the tree last agreed with.
const BASE_FILE: &str = "base.json";

// ---------------------------------------------------------------------------
// Opening the client, and finding the app
// ---------------------------------------------------------------------------

fn base_url() -> String {
    std::env::var(client::APPS_API_ENV)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| client::DEFAULT_APPS_API.to_owned())
}

/// Say out loud, once, that this command is not talking to reachpad.dev.
///
/// The override exists for Vercel previews and for the tests' fake server, and
/// the allowlist in [`client::validate_apps_origin`] keeps it off arbitrary
/// hosts — but `*.vercel.app` is an origin anybody can deploy to, and what
/// travels here is the WorkOS access token and the customer's whole source
/// tree. An environment variable set once in a shell profile must not be able
/// to redirect both without the person seeing where they went.
fn warn_if_overridden(ctx: &Ctx, base: &str) {
    if base == client::DEFAULT_APPS_API {
        return;
    }
    if ctx.is_quiet() {
        return;
    }
    let host = crate::http_min::parse_url(base)
        .map(|endpoint| endpoint.authority())
        .unwrap_or_else(|_| base.to_owned());
    eprintln!(
        "reachpad: {} points the apps API at {host}; your sign-in and your source go there.",
        client::APPS_API_ENV
    );
}

/// The webapp origin behind the apps API, which is where an app's own page
/// lives. Derived from the API base rather than hardcoded, so a preview
/// deployment links to itself.
fn site_origin(base: &str) -> String {
    match crate::http_min::parse_url(base) {
        Ok(endpoint) => {
            let scheme = match endpoint.scheme {
                crate::http_min::Scheme::Tls => "https",
                crate::http_min::Scheme::Plaintext => "http",
            };
            let port = match (endpoint.scheme, endpoint.port) {
                (crate::http_min::Scheme::Tls, 443) | (crate::http_min::Scheme::Plaintext, 80) => {
                    String::new()
                }
                (_, port) => format!(":{port}"),
            };
            format!("{scheme}://{}{port}", endpoint.host)
        }
        Err(_) => "https://reachpad.dev".to_owned(),
    }
}

async fn open(ctx: &Ctx) -> Result<Apps, CliError> {
    ctx.deny_api_key()?;
    let base = base_url();
    // Before the bearer is even loaded: the warning is about where it would go.
    warn_if_overridden(ctx, &base);
    let bearer = client::bearer(&ctx.paths, crate::commands::now_ms()).await?;
    Apps::new(base, bearer, ctx.trust())
}

/// The folder this command acts on: the argument, else the linked project, else
/// the working directory.
fn project(path: Option<PathBuf>) -> Result<(PathBuf, Option<Linked>), CliError> {
    let here = std::env::current_dir()
        .map_err(|e| failure(format!("this process has no working directory ({e})")))?;
    match path {
        Some(path) => {
            let root = if path.is_absolute() {
                path
            } else {
                here.join(path)
            };
            // `reachpad check .` should not print `…/todo/.` back at anyone.
            // Canonicalizing only when the folder is already there keeps
            // `init <new folder>` working, and it is the same folder either
            // way — `.` and `..` are the only things resolved.
            let root = root.canonicalize().unwrap_or(root);
            let linked = manifest::read_at(&root)?.map(|manifest| Linked {
                root: root.clone(),
                manifest,
            });
            Ok((root, linked))
        }
        None => match manifest::find_upward(&here)? {
            Some(linked) => Ok((linked.root.clone(), Some(linked))),
            None => Ok((here, None)),
        },
    }
}

/// The two verbs that publish act on a FOLDER, not on a named app: what goes
/// up is this tree, and which app receives it is the `reachpad.json` beside it.
/// `--target` is global, so it parses on them; ignoring it silently would let
/// `reachpad publish --target <other app>` create a version on the linked app
/// while the person believed they had named a different one.
fn deny_target(ctx: &Ctx, verb: &str) -> Result<(), CliError> {
    if ctx.target().is_none() {
        return Ok(());
    }
    Err(failure(format!(
        "`{verb}` publishes the folder it is run in, and the app it publishes to is the one \
         `{}` names. `--target` does not change that. Run it in the linked folder, or \
         `reachpad link <url>` there first.",
        manifest::MANIFEST_FILE
    )))
}

/// The app id this command acts on: `--target`, else the linked project.
async fn target_app(ctx: &Ctx, apps: &Apps) -> Result<Value, CliError> {
    if let Some(target) = ctx.target() {
        return resolve_target(apps, target).await;
    }
    let (_, linked) = project(None)?;
    let id = linked
        .and_then(|linked| linked.manifest.app)
        .ok_or_else(|| {
            failure(
                "this folder is not linked to an app. Run `reachpad link <url>` here, \
                 publish it with `reachpad publish`, or name one with `--target`.",
            )
        })?;
    apps.app(&id).await.map(|body| body["app"].clone())
}

/// One `--target` value: an app URL, a version URL, or an app id.
async fn resolve_target(apps: &Apps, target: &str) -> Result<Value, CliError> {
    if target.starts_with("https://") || target.starts_with("http://") {
        let body = apps.resolve(target).await?;
        return Ok(body["app"].clone());
    }
    apps.app(target).await.map(|body| body["app"].clone())
}

fn app_id(app: &Value) -> Result<&str, CliError> {
    app["id"]
        .as_str()
        .ok_or_else(|| failure("the apps API answered with an app that has no id."))
}

/// The `URL:` line, the one thing every remote verb prints.
fn url_line(url: &str) -> String {
    format!("URL: {url}")
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

pub(crate) async fn init(ctx: &Ctx, path: Option<PathBuf>) -> Result<i32, CliError> {
    let (root, linked) = project(path)?;
    if !root.is_dir() {
        std::fs::create_dir_all(&root)
            .map_err(|e| failure(format!("creating {}: {e}", root.display())))?;
    }
    let (manifest, wrote) = match linked {
        Some(linked) => (linked.manifest, false),
        None => {
            let manifest = manifest::detect(&root);
            manifest::write(&root, &manifest)?;
            (manifest, true)
        }
    };
    let entry_exists = root.join(&manifest.entry).is_file();
    let mut lines = vec![if wrote {
        format!(
            "Wrote {} ({}, entry {}).",
            root.join(manifest::MANIFEST_FILE).display(),
            manifest.kind,
            manifest.entry
        )
    } else {
        format!(
            "{} is already here ({}, entry {}).",
            manifest::MANIFEST_FILE,
            manifest.kind,
            manifest.entry
        )
    }];
    if !entry_exists {
        lines.push(format!("  next: write {}", manifest.entry));
    }
    lines.push("  then: reachpad check && reachpad publish -m \"First version\"".to_owned());
    ctx.emit(
        json!({
            "path": root.display().to_string(),
            "created": wrote,
            "kind": manifest.kind.as_str(),
            "entry": manifest.entry,
            "entry_exists": entry_exists,
        }),
        &lines,
    );
    Ok(EXIT_OK)
}

pub(crate) async fn link(ctx: &Ctx, url: String, path: Option<PathBuf>) -> Result<i32, CliError> {
    let apps = open(ctx).await?;
    let app = resolve_target(&apps, &url).await?;
    let id = app_id(&app)?.to_owned();
    let (root, linked) = project(path)?;
    let mut manifest = match linked {
        Some(linked) => linked.manifest,
        None => manifest::detect(&root),
    };
    manifest.app = Some(id.clone());
    manifest::write(&root, &manifest)?;
    let live = app["url"].as_str().unwrap_or_default().to_owned();
    ctx.emit(
        json!({ "app": app, "path": root.display().to_string() }),
        &[
            format!(
                "Linked {} to {}.",
                root.display(),
                app["name"].as_str().unwrap_or(&id)
            ),
            url_line(&live),
        ],
    );
    Ok(EXIT_OK)
}

/// What `check` found, and what `publish` reuses so the tree is walked once.
struct Checked {
    root: PathBuf,
    manifest: Manifest,
    files: Vec<pack::Entry>,
    bytes: u64,
}

fn check_tree(path: Option<PathBuf>) -> Result<Checked, CliError> {
    let (root, linked) = project(path)?;
    let manifest = linked.map(|linked| linked.manifest).ok_or_else(|| {
        failure(format!(
            "there is no {} in {} or any folder above it. Run `reachpad init` here.",
            manifest::MANIFEST_FILE,
            root.display()
        ))
    })?;
    let entry = root.join(&manifest.entry);
    if !entry.is_file() {
        return Err(failure(format!(
            "the entry {} is not a file in {}.",
            manifest.entry,
            root.display()
        )));
    }
    match manifest.kind {
        Kind::Page => {
            let lower = manifest.entry.to_ascii_lowercase();
            if !(lower.ends_with(".html") || lower.ends_with(".htm")) {
                return Err(failure(format!(
                    "a page's entry is the HTML file served at `/`, and {} is not one.",
                    manifest.entry
                )));
            }
        }
        Kind::Function => {
            let lower = manifest.entry.to_ascii_lowercase();
            if !(lower.ends_with(".js") || lower.ends_with(".mjs")) {
                return Err(failure(format!(
                    "a function's entry is a JavaScript module, and {} is not one. \
                     Publish the built `.js` rather than its source.",
                    manifest.entry
                )));
            }
            let source = std::fs::read_to_string(&entry)
                .map_err(|e| failure(format!("reading {}: {e}", entry.display())))?;
            if !exports_default_fetch(&source) {
                return Err(failure(format!(
                    "{} has to export a default object with a `fetch` handler:\n  \
                     export default {{ async fetch(request, env) {{ … }} }}",
                    manifest.entry
                )));
            }
        }
    }
    let excludes = pack::Excludes::read(&root)?;
    let files = pack::collect(&root, &excludes)?;
    if files.is_empty() {
        return Err(failure(format!(
            "{} holds nothing to publish.",
            root.display()
        )));
    }
    if !files.iter().any(|file| file.path == manifest.entry) {
        return Err(failure(format!(
            "the entry {} is excluded from the snapshot by {} or by a rule. \
             A snapshot without its entry cannot be served.",
            manifest.entry,
            pack::IGNORE_FILE
        )));
    }
    let bytes = files.iter().map(|file| file.bytes).sum();
    Ok(Checked {
        root,
        manifest,
        files,
        bytes,
    })
}

/// A regex-level check, as CLI.md asks for: does this module export a default
/// object carrying a `fetch`? Not a parser — the point is to catch the common
/// wrong shapes (a bare function, `module.exports`, no default at all) before
/// an upload, not to be a JavaScript engine.
fn exports_default_fetch(source: &str) -> bool {
    let Some(at) = source.find("export default") else {
        return false;
    };
    // `fetch` has to appear inside the exported object, not merely somewhere in
    // the file: `export default handler` with a `fetch(` in a comment above it
    // is exactly the shape this is meant to reject.
    let rest = &source[at + "export default".len()..];
    let Some(open) = rest.find('{') else {
        return false;
    };
    // A `{` that is not the start of the exported object (e.g. `export default
    // foo;` followed by another block) means the export is not an object.
    if rest[..open].chars().any(|c| !c.is_whitespace()) {
        return false;
    }
    rest[open..].contains("fetch")
}

pub(crate) async fn check(ctx: &Ctx, path: Option<PathBuf>) -> Result<i32, CliError> {
    let checked = check_tree(path)?;
    ctx.emit(
        json!({
            "path": checked.root.display().to_string(),
            "kind": checked.manifest.kind.as_str(),
            "entry": checked.manifest.entry,
            "files": checked.files.len(),
            "bytes": checked.bytes,
        }),
        &[
            format!(
                "{} is ready: {} {}, {} in {} file(s).",
                checked.root.display(),
                checked.manifest.kind,
                checked.manifest.entry,
                pack::human_bytes(checked.bytes),
                checked.files.len(),
            ),
            "  next: reachpad publish -m \"What changed\"".to_owned(),
        ],
    );
    Ok(EXIT_OK)
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn publish(
    ctx: &Ctx,
    path: Option<PathBuf>,
    slug: Option<String>,
    name: Option<String>,
    message: Option<String>,
    access: Option<AccessArg>,
    password_stdin: bool,
    expires_at: Option<String>,
) -> Result<i32, CliError> {
    deny_target(ctx, "publish")?;
    let checked = check_tree(path)?;
    let apps = open(ctx).await?;
    let first = checked.manifest.app.is_none();
    let sharing_given = slug.is_some()
        || name.is_some()
        || access.is_some()
        || password_stdin
        || expires_at.is_some();
    if !first && sharing_given {
        return Err(failure(
            "the name, the address and the sharing flags are set when the app is created. \
             Use `reachpad access set <level>` to change who can open this one, and \
             `reachpad share <email>` to add a person.",
        ));
    }
    let message = message.unwrap_or_else(|| "Published from the CLI".to_owned());

    let tarball = pack::tar_gz(&checked.root, &checked.files)?;
    if tarball.len() as u64 > pack::MAX_TARBALL_BYTES {
        return Err(failure(format!(
            "the snapshot is {} and the limit is 50 MiB. Add what does not belong in the \
             app to {}.",
            pack::human_bytes(tarball.len() as u64),
            pack::IGNORE_FILE
        )));
    }
    let ticket = apps.upload_ticket(tarball.len() as u64).await?;
    let put_url = ticket["put_url"]
        .as_str()
        .ok_or_else(|| failure("the apps API issued an upload ticket with no address."))?;
    let uploaded = apps.put_snapshot(put_url, &tarball).await?;
    let snapshot = uploaded["snapshot_id"]
        .as_str()
        .or_else(|| ticket["snapshot_id"].as_str())
        .ok_or_else(|| failure("the upload finished without naming a snapshot."))?
        .to_owned();

    let (app, version) = if first {
        let name = name.unwrap_or_else(|| folder_name(&checked.root));
        let mut body = json!({
            "name": name,
            "type": "app",
            "message": message,
            "manifest": checked.manifest.wire(),
            "snapshot_id": snapshot,
        });
        if let Some(slug) = slug {
            body["slug"] = json!(slug);
        }
        let mut access_body = json!({ "level": access.unwrap_or(AccessArg::Restricted).wire() });
        if password_stdin {
            access_body["password"] = json!(read_password()?);
        }
        if let Some(expires_at) = expires_at {
            access_body["expires_at"] = json!(expires_at);
        }
        body["access"] = access_body;
        let created = apps.create_app(&body).await?;
        let app = created["app"].clone();
        // The manifest is written the moment the app exists, so a failure after
        // this point is a retry rather than a second app.
        let mut manifest = checked.manifest.clone();
        manifest.app = Some(app_id(&app)?.to_owned());
        manifest::write(&checked.root, &manifest)?;
        (app, created["version"].clone())
    } else {
        let id = checked.manifest.app.clone().expect("checked above");
        let created = apps
            .create_version(
                &id,
                &json!({
                    "snapshot_id": snapshot,
                    "message": message,
                    "manifest": checked.manifest.wire(),
                }),
            )
            .await?;
        let app = apps.app(&id).await?["app"].clone();
        (app, created["version"].clone())
    };

    let number = version["number"].as_u64().unwrap_or(1);
    write_base(&checked.root, number, &checked.files)?;
    let name = app["name"].as_str().unwrap_or("this app").to_owned();
    let pending = version["status"].as_str() == Some("pending_review");
    let live_url = app["url"].as_str().unwrap_or_default().to_owned();
    let version_url = version["url"].as_str().unwrap_or(&live_url).to_owned();

    let mut lines = vec![format!("Published {name} v{number}")];
    if pending {
        lines.push(url_line(&version_url));
        lines.push(format!(
            "Awaiting review at {}/apps/{}",
            site_origin(apps.base()),
            app_id(&app)?
        ));
    } else {
        lines.push(url_line(&live_url));
    }
    ctx.emit(json!({ "app": app, "version": version }), &lines);
    Ok(EXIT_OK)
}

/// The shape check, not a validator: exactly one `@`, something either side,
/// and a dot in the domain. The server owns the real rule; this exists so a
/// workspace id or a folder name never reaches it as an invitation.
fn looks_like_email(value: &str) -> bool {
    let value = value.trim();
    let Some((user, domain)) = value.split_once('@') else {
        return false;
    };
    !user.is_empty()
        && !domain.is_empty()
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && !value.contains(char::is_whitespace)
        && !domain.contains('@')
}

fn folder_name(root: &Path) -> String {
    root.file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .unwrap_or("App")
        .to_owned()
}

fn read_password() -> Result<String, CliError> {
    let mut buf = String::new();
    std::io::Read::read_to_string(&mut std::io::stdin(), &mut buf)
        .map_err(|e| failure(format!("reading the password from stdin: {e}")))?;
    let password = buf.trim_end_matches(['\r', '\n']).to_owned();
    if password.is_empty() {
        return Err(failure("--password-stdin was given but stdin was empty."));
    }
    Ok(password)
}

// ---------------------------------------------------------------------------
// Reading a version back
// ---------------------------------------------------------------------------

async fn snapshot_files(
    apps: &Apps,
    app: &str,
    version: Option<u64>,
) -> Result<BTreeMap<String, Vec<u8>>, CliError> {
    let raw = apps.source(app, version, "format=tar").await?;
    pack::untar_gz(&raw.body)
}

pub(crate) async fn pull(
    ctx: &Ctx,
    path: Option<PathBuf>,
    from: Option<u64>,
    force: bool,
) -> Result<i32, CliError> {
    let apps = open(ctx).await?;
    let app = target_app(ctx, &apps).await?;
    let id = app_id(&app)?.to_owned();
    let (root, _) = project(path)?;
    let remote = snapshot_files(&apps, &id, from).await?;
    let number = match from {
        Some(number) => number,
        None => app["live_version"].as_u64().unwrap_or(0),
    };

    // A file this folder has changed since the last pull or publish is not
    // overwritten without being asked: `pull` is not a way to lose work.
    //
    // Driven off the INCOMING files, not off the base record. The base record
    // is what the last pull or publish agreed with, and it may not exist at all
    // — `reachpad link` then `reachpad pull` in a folder somebody has been
    // working in is the ordinary way to reach this code with no record. The old
    // loop walked the record, so no record meant no check and every local file
    // was overwritten in silence. Anything the record does not vouch for is
    // treated as changed here, which is the fail-closed reading.
    if !force {
        let base = read_base(&root)?.unwrap_or_default();
        let mut modified: Vec<String> = Vec::new();
        for (name, content) in &remote {
            let Ok(bytes) = std::fs::read(root.join(name)) else {
                continue; // Not here yet; writing it loses nothing.
            };
            let here = digest(&bytes);
            // A local copy that already matches what is coming down is not work
            // anyone can lose, whatever the record says.
            if here == digest(content) {
                continue;
            }
            if base.files.get(name).map(String::as_str) != Some(here.as_str()) {
                modified.push(name.clone());
            }
        }
        if !modified.is_empty() {
            modified.sort();
            return Err(failure(format!(
                "these files have changed here since the last pull:\n  {}\nPublish them, or \
                 pass --force to overwrite them.",
                modified.join("\n  ")
            )));
        }
    }

    for (name, content) in &remote {
        write_file(&root, name, content)?;
    }
    write_base_hashes(
        &root,
        number,
        remote.iter().map(|(k, v)| (k.clone(), digest(v))).collect(),
    )?;
    ctx.emit(
        json!({ "app": app, "version": number, "files": remote.len() }),
        &[
            format!(
                "Pulled {} file(s) of v{number} into {}.",
                remote.len(),
                root.display()
            ),
            url_line(app["url"].as_str().unwrap_or_default()),
        ],
    );
    Ok(EXIT_OK)
}

pub(crate) async fn restore(
    ctx: &Ctx,
    file: String,
    from: u64,
    path: Option<PathBuf>,
) -> Result<i32, CliError> {
    let apps = open(ctx).await?;
    let app = target_app(ctx, &apps).await?;
    let id = app_id(&app)?.to_owned();
    let (root, _) = project(path)?;
    pack::check_extract_path(&file)?;
    let raw = apps
        .source(&id, Some(from), &format!("path={}", client::encode(&file)))
        .await?;
    write_file(&root, &file, &raw.body)?;
    ctx.emit(
        json!({ "app": app, "version": from, "file": file, "bytes": raw.body.len() }),
        &[
            format!(
                "Restored {file} from v{from} into {} ({}).",
                root.display(),
                pack::human_bytes(raw.body.len() as u64)
            ),
            url_line(app["url"].as_str().unwrap_or_default()),
        ],
    );
    Ok(EXIT_OK)
}

pub(crate) async fn versions(ctx: &Ctx) -> Result<i32, CliError> {
    let apps = open(ctx).await?;
    let app = target_app(ctx, &apps).await?;
    let body = apps.versions(app_id(&app)?, 50).await?;
    let rows = body["versions"].as_array().cloned().unwrap_or_default();
    let mut lines = Vec::new();
    for version in &rows {
        let number = version["number"].as_u64().unwrap_or(0);
        let message = version["message"].as_str().unwrap_or("");
        let message = if message.trim().is_empty() {
            "No change message"
        } else {
            message
        };
        lines.push(format!(
            "v{number:<4} {:<10} {:<22} {}",
            version["status"].as_str().unwrap_or("?"),
            version["author"]["name"].as_str().unwrap_or("?"),
            message
        ));
        lines.push(format!(
            "        {}  {}",
            version["created_at"].as_str().unwrap_or(""),
            version["url"].as_str().unwrap_or("")
        ));
    }
    if rows.is_empty() {
        lines.push("Nothing published yet.".to_owned());
    }
    // CLI.md: every remote verb that names an app ends with the one line an
    // agent is told to copy. The per-version links above are not it.
    lines.push(url_line(app["url"].as_str().unwrap_or_default()));
    ctx.emit(json!({ "app": app, "versions": rows }), &lines);
    Ok(EXIT_OK)
}

pub(crate) async fn read(
    ctx: &Ctx,
    path: Option<String>,
    version: Option<u64>,
) -> Result<i32, CliError> {
    let apps = open(ctx).await?;
    let app = target_app(ctx, &apps).await?;
    let id = app_id(&app)?.to_owned();
    let file = match path {
        Some(path) => {
            pack::check_extract_path(&path)?;
            path
        }
        None => {
            // The entry of the version being read, which is a property of the
            // VERSION and not of the app: an older version may have had a
            // different one.
            let number = match version {
                Some(number) => number,
                None => app["live_version"].as_u64().unwrap_or(0),
            };
            let listed = apps.versions(&id, 100).await?;
            listed["versions"]
                .as_array()
                .and_then(|rows| {
                    rows.iter()
                        .find(|row| row["number"].as_u64() == Some(number))
                })
                .and_then(|row| row["entry"].as_str())
                .map(str::to_owned)
                .ok_or_else(|| {
                    failure(format!(
                        "v{number} does not say which file it serves; name one, e.g. \
                         `reachpad read index.html`."
                    ))
                })?
        }
    };
    let raw = apps
        .source(&id, version, &format!("path={}", client::encode(&file)))
        .await?;
    if ctx.is_json() {
        ctx.emit(
            json!({
                "app": app,
                "path": file,
                "content_type": raw.content_type,
                "content": String::from_utf8_lossy(&raw.body),
            }),
            &[],
        );
    } else {
        crate::out::out_bytes(&raw.body);
    }
    Ok(EXIT_OK)
}

// ---------------------------------------------------------------------------
// sync: pull, merge, publish
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
struct Base {
    version: u64,
    files: BTreeMap<String, String>,
}

fn base_path(root: &Path) -> PathBuf {
    root.join(pack::BASE_DIR).join(BASE_FILE)
}

fn digest(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

fn read_base(root: &Path) -> Result<Option<Base>, CliError> {
    let path = base_path(root);
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(failure(format!("reading {}: {e}", path.display()))),
    };
    // A record that no longer parses is a record that is gone: it is a cache of
    // an agreement, and losing it costs one `pull`.
    let Ok(value) = serde_json::from_str::<Value>(&text) else {
        return Ok(None);
    };
    Ok(Some(Base {
        version: value["version"].as_u64().unwrap_or(0),
        files: value["files"]
            .as_object()
            .map(|map| {
                map.iter()
                    .filter_map(|(k, v)| Some((k.clone(), v.as_str()?.to_owned())))
                    .collect()
            })
            .unwrap_or_default(),
    }))
}

fn write_base(root: &Path, version: u64, files: &[pack::Entry]) -> Result<(), CliError> {
    let mut hashes = BTreeMap::new();
    for file in files {
        let bytes = std::fs::read(root.join(&file.path))
            .map_err(|e| failure(format!("reading {}: {e}", file.path)))?;
        hashes.insert(file.path.clone(), digest(&bytes));
    }
    write_base_hashes(root, version, hashes)
}

fn write_base_hashes(
    root: &Path,
    version: u64,
    files: BTreeMap<String, String>,
) -> Result<(), CliError> {
    let path = base_path(root);
    let dir = path.parent().expect("the base file is inside a directory");
    std::fs::create_dir_all(dir)
        .map_err(|e| failure(format!("creating {}: {e}", dir.display())))?;
    let text = serde_json::to_string_pretty(&json!({ "version": version, "files": files }))
        .map_err(|e| failure(format!("rendering {}: {e}", path.display())))?;
    // Through a temporary and a rename, like every other file this CLI owns.
    // A half-written record is what `pull`'s overwrite check reads next time,
    // and a truncated one reads as "this folder agreed with nothing".
    crate::privatefile::write(&path, text.as_bytes())
        .map_err(|e| failure(format!("writing {}: {e}", path.display())))
}

fn write_file(root: &Path, name: &str, content: &[u8]) -> Result<(), CliError> {
    pack::check_extract_path(name)?;
    let path = root.join(name);
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)
            .map_err(|e| failure(format!("creating {}: {e}", dir.display())))?;
    }
    std::fs::write(&path, content).map_err(|e| failure(format!("writing {}: {e}", path.display())))
}

pub(crate) async fn sync(
    ctx: &Ctx,
    path: Option<PathBuf>,
    message: Option<String>,
) -> Result<i32, CliError> {
    deny_target(ctx, "sync")?;
    let (root, linked) = project(path.clone())?;
    let linked = linked.ok_or_else(|| {
        failure(format!(
            "there is no {} in {} or any folder above it.",
            manifest::MANIFEST_FILE,
            root.display()
        ))
    })?;
    let id = linked.manifest.app.clone().ok_or_else(|| {
        failure("this folder is not linked to an app yet. `reachpad publish` creates one.")
    })?;
    let Some(base) = read_base(&root)? else {
        return Err(failure(
            "there is no record of what this folder last agreed with, so a three-way merge \
             has nothing to merge against. Run `reachpad pull` first (it writes one), or \
             `reachpad publish` to make this folder the new version.",
        ));
    };

    let apps = open(ctx).await?;
    let app = apps.app(&id).await?["app"].clone();
    let remote = snapshot_files(&apps, &id, None).await?;
    let excludes = pack::Excludes::read(&root)?;
    let local: BTreeMap<String, String> = pack::collect(&root, &excludes)?
        .into_iter()
        .map(|entry| {
            let bytes = std::fs::read(root.join(&entry.path))
                .map_err(|e| failure(format!("reading {}: {e}", entry.path)))?;
            Ok((entry.path, digest(&bytes)))
        })
        .collect::<Result<_, CliError>>()?;

    let mut names: BTreeSet<String> = base.files.keys().cloned().collect();
    names.extend(local.keys().cloned());
    names.extend(remote.keys().cloned());

    let mut conflicts = Vec::new();
    let mut take_remote = Vec::new();
    let mut drop_local = Vec::new();
    for name in &names {
        let was = base.files.get(name);
        let here = local.get(name).cloned();
        let there = remote.get(name).map(|bytes| digest(bytes));
        let changed_here = here.as_deref() != was.map(String::as_str);
        let changed_there = there.as_deref() != was.map(String::as_str);
        match (changed_here, changed_there) {
            // Nobody moved, or both made the same change: nothing to do.
            (false, false) => {}
            (true, true) if here == there => {}
            (true, true) => conflicts.push(name.clone()),
            // Only the app moved: bring it down.
            (false, true) => match &there {
                Some(_) => take_remote.push(name.clone()),
                None => drop_local.push(name.clone()),
            },
            // Only this folder moved: it goes up in the publish below.
            (true, false) => {}
        }
    }
    if !conflicts.is_empty() {
        return Err(failure(format!(
            "these files changed both here and in the app since v{}:\n  {}\nResolve them and \
             run `reachpad sync` again, or `reachpad pull --force` to take the app's copy.",
            base.version,
            conflicts.join("\n  ")
        )));
    }

    for name in &take_remote {
        write_file(&root, name, &remote[name])?;
    }
    for name in &drop_local {
        let _ = std::fs::remove_file(root.join(name));
    }
    if !take_remote.is_empty() || !drop_local.is_empty() {
        eprintln!(
            "reachpad: brought down {} change(s) from the app before publishing.",
            take_remote.len() + drop_local.len()
        );
    }
    publish(ctx, path, None, None, message, None, false, None).await?;
    let _ = app;
    Ok(EXIT_OK)
}

// ---------------------------------------------------------------------------
// Access and people
// ---------------------------------------------------------------------------

fn access_lines(app: &Value) -> Vec<String> {
    let access = &app["access"];
    let level = match access["level"].as_str() {
        Some("restricted") => "restricted — the owner and the people it is shared with",
        Some("org_link") => "org-link — anyone in the org with the link",
        Some("public_link") => "public-link — anyone with the link",
        other => other.unwrap_or("unknown"),
    };
    let mut lines = vec![format!("Access: {level}")];
    if access["has_password"].as_bool() == Some(true) {
        lines.push("  a password is set".to_owned());
    }
    if let Some(expires) = access["expires_at"].as_str() {
        lines.push(format!("  the link stops working at {expires}"));
    }
    lines.push(url_line(app["url"].as_str().unwrap_or_default()));
    lines
}

pub(crate) async fn access(ctx: &Ctx, command: Option<AccessCommand>) -> Result<i32, CliError> {
    let apps = open(ctx).await?;
    let app = target_app(ctx, &apps).await?;
    let Some(AccessCommand::Set {
        level,
        password_stdin,
        clear_password,
        expires_at,
        clear_expiry,
    }) = command
    else {
        ctx.emit(json!({ "app": app }), &access_lines(&app));
        return Ok(EXIT_OK);
    };
    if password_stdin && clear_password {
        return Err(CliError::usage(
            "--password-stdin and --clear-password ask for opposite things.",
        ));
    }
    if expires_at.is_some() && clear_expiry {
        return Err(CliError::usage(
            "--expires-at and --clear-expiry ask for opposite things.",
        ));
    }
    let mut body = json!({ "level": level.wire() });
    if password_stdin {
        body["password"] = json!(read_password()?);
    }
    if clear_password {
        body["clear_password"] = json!(true);
    }
    if let Some(expires_at) = expires_at {
        body["expires_at"] = json!(expires_at);
    }
    if clear_expiry {
        body["clear_expiry"] = json!(true);
    }
    let updated = apps.set_access(app_id(&app)?, &body).await?["app"].clone();
    ctx.emit(json!({ "app": updated }), &access_lines(&updated));
    Ok(EXIT_OK)
}

pub(crate) async fn share(
    ctx: &Ctx,
    email: String,
    role: ShareRoleArg,
    notify: bool,
    message: Option<String>,
) -> Result<i32, CliError> {
    // `share` used to mean "give another account access to this WORKSPACE"
    // (ADR-0075 retired it). It now means "give a person access to this app",
    // and its argument is an email address — so a workspace id typed into the
    // old muscle memory is refused here, by name, rather than posted to the
    // apps API as if it were a person.
    if !looks_like_email(&email) {
        return Err(failure(format!(
            "{email:?} is not an email address. `reachpad share` gives one person access to              an app by email; workspaces are not shared with this verb."
        )));
    }
    let apps = open(ctx).await?;
    let app = target_app(ctx, &apps).await?;
    let mut body = json!({ "email": email, "role": role.wire(), "notify": notify });
    if let Some(message) = message {
        body["message"] = json!(message);
    }
    let created = apps.add_share(app_id(&app)?, &body).await?["share"].clone();
    let pending = created["accepted"].as_bool() != Some(true);
    let mut lines = vec![format!(
        "Shared with {email} as {}{}.",
        role.wire(),
        if pending {
            " (they get it when they sign in)"
        } else {
            ""
        }
    )];
    lines.push(url_line(app["url"].as_str().unwrap_or_default()));
    ctx.emit(json!({ "app": app, "share": created }), &lines);
    Ok(EXIT_OK)
}

pub(crate) async fn shares(ctx: &Ctx, command: SharesCommand) -> Result<i32, CliError> {
    let apps = open(ctx).await?;
    let app = target_app(ctx, &apps).await?;
    let id = app_id(&app)?.to_owned();
    let listed = apps.shares(&id).await?;
    let rows = listed["shares"].as_array().cloned().unwrap_or_default();
    match command {
        SharesCommand::List => {
            let mut lines: Vec<String> = rows
                .iter()
                .map(|share| {
                    format!(
                        "{:<32} {:<7} {}",
                        share["email"].as_str().unwrap_or("?"),
                        share["role"].as_str().unwrap_or("?"),
                        if share["accepted"].as_bool() == Some(true) {
                            ""
                        } else {
                            "invited"
                        }
                    )
                    .trim_end()
                    .to_owned()
                })
                .collect();
            if lines.is_empty() {
                lines.push("Nobody yet.".to_owned());
            }
            lines.push(url_line(app["url"].as_str().unwrap_or_default()));
            ctx.emit(json!({ "app": app, "shares": rows }), &lines);
        }
        SharesCommand::Revoke { email } => {
            let share = rows
                .iter()
                .find(|share| {
                    share["email"]
                        .as_str()
                        .is_some_and(|value| value.eq_ignore_ascii_case(email.trim()))
                })
                .ok_or_else(|| failure(format!("{email} is not on this app's list.")))?;
            let share_id = share["id"]
                .as_str()
                .ok_or_else(|| failure("that share has no id."))?;
            apps.revoke_share(&id, share_id).await?;
            ctx.emit(
                json!({ "app": app, "revoked": email }),
                &[
                    format!("{email} can no longer open it."),
                    url_line(app["url"].as_str().unwrap_or_default()),
                ],
            );
        }
    }
    Ok(EXIT_OK)
}

// ---------------------------------------------------------------------------
// The org's secrets
// ---------------------------------------------------------------------------

/// `reachpad secrets set|list|remove` — the org's secrets, which every app in
/// the org binds by name.
///
/// No app is named and none is needed, which is why `--target` is refused
/// here rather than ignored: a person who typed it believed this command
/// concerned one app, and it never does.
///
/// The value is read AFTER the client opens, so a machine that is not signed
/// in says so before anyone types a key at a prompt.
///
/// Nothing the server sends is passed through to `--json`. Every field these
/// verbs emit is one this CLI knows the name and the type of, built here, so a
/// field the API grows tomorrow cannot appear in a caller's output as though
/// this version had promised it, and a value can never ride out on a field
/// nobody read.
pub(crate) async fn secrets_verb(ctx: &Ctx, command: SecretsCommand) -> Result<i32, CliError> {
    if ctx.target().is_some() {
        return Err(failure(
            "`secrets` acts on the org, and every app in it binds the same names. `--target` \
             does not narrow that.",
        ));
    }
    match command {
        SecretsCommand::Set { name, value } => {
            secrets::check_name(&name)?;
            let apps = open(ctx).await?;
            let value = secrets::read_value(&name, value.as_deref()).await?;
            let answer = apps.set_secret(&name, &value).await?;
            let rotation = Rotation::from(&answer);
            let mut lines = vec![format!("Set {name}.")];
            lines.extend(rotation.lines());
            ctx.emit(rotation.json(&name), &lines);
        }
        SecretsCommand::List => {
            let apps = open(ctx).await?;
            let listed = apps.secrets().await?;
            // A bare array is the contract. Anything else is a server this
            // version does not understand, and printing "no secrets yet" for
            // it would be a lie a person acts on by setting one twice.
            let rows = listed.as_array().ok_or_else(|| {
                failure(format!(
                    "the apps API answered GET /api/secrets with {}, and this verb reads an \
                     array of secrets.",
                    shape(&listed)
                ))
            })?;
            let rows: Vec<Value> = rows.iter().map(secret_json).collect();
            ctx.emit(Value::Array(rows.clone()), &secret_lines(&rows));
        }
        SecretsCommand::Remove { name } => {
            secrets::check_name(&name)?;
            let apps = open(ctx).await?;
            let answer = apps.remove_secret(&name).await?;
            let rotation = Rotation::from(&answer);
            let mut lines = vec![format!("Removed {name}.")];
            lines.extend(rotation.lines());
            ctx.emit(rotation.json(&name), &lines);
        }
    }
    Ok(EXIT_OK)
}

/// What a set or a remove did to the versions already running.
///
/// Rotation is the half of this feature a person cannot see: the value changed
/// on every live version that binds the name, with no republish. Silence would
/// leave them wondering whether the old key is still out there. A version the
/// server could not reach is named, because that one still holds it.
struct Rotation {
    updated: u64,
    failed: Vec<String>,
}

impl Rotation {
    /// The two fields this CLI knows, read at the types it knows them at.
    fn from(answer: &Value) -> Rotation {
        Rotation {
            updated: answer["rotated"].as_u64().unwrap_or(0),
            failed: answer["failed"]
                .as_array()
                .map(|ids| {
                    ids.iter()
                        .filter_map(|id| id.as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default(),
        }
    }

    fn lines(&self) -> Vec<String> {
        let mut lines = Vec::new();
        match self.updated {
            0 => {}
            1 => lines.push("Updated 1 running version.".to_owned()),
            n => lines.push(format!("Updated {n} running versions.")),
        }
        match self.failed.len() {
            0 => {}
            1 => lines.push(format!(
                "Warning: {} still holds the old value. Publish that version again.",
                self.failed[0]
            )),
            _ => lines.push(format!(
                "Warning: {} still hold the old value. Publish those versions again.",
                self.failed.join(", ")
            )),
        }
        lines
    }

    fn json(&self, name: &str) -> Value {
        json!({ "name": name, "rotated": self.updated, "failed": self.failed })
    }
}

/// One listed secret, rebuilt from the fields this version knows.
fn secret_json(row: &Value) -> Value {
    json!({
        "name": row["name"].as_str().unwrap_or_default(),
        "set_by": {
            "id": row["set_by"]["id"].as_str().unwrap_or_default(),
            "name": row["set_by"]["name"].as_str().unwrap_or_default(),
        },
        "set_at": row["set_at"].as_str().unwrap_or_default(),
        "apps": row["apps"]
            .as_array()
            .map(|apps| {
                apps.iter()
                    .map(|app| {
                        json!({
                            "id": app["id"].as_str().unwrap_or_default(),
                            "name": app["name"].as_str().unwrap_or_default(),
                            "slug": app["slug"].as_str().unwrap_or_default(),
                        })
                    })
                    .collect::<Vec<Value>>()
            })
            .unwrap_or_default(),
    })
}

/// What kind of JSON this is, for a refusal that has to say what arrived.
fn shape(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Array(_) => "an array",
        Value::Object(_) => "an object",
    }
}

/// The listing: a header and one row per secret, with the apps that bind it.
/// Never a value — the API does not send one and this would not print it.
fn secret_lines(rows: &[Value]) -> Vec<String> {
    if rows.is_empty() {
        return vec!["No secrets yet. Set one with `reachpad secrets set NAME`.".to_owned()];
    }
    let mut lines = vec![format!(
        "{:<24} {:<20} {:<12} {}",
        "NAME", "SET BY", "SET", "APPS"
    )];
    lines.extend(rows.iter().map(|row| {
        let apps: Vec<&str> = row["apps"]
            .as_array()
            .map(|apps| apps.iter().filter_map(|app| app["name"].as_str()).collect())
            .unwrap_or_default();
        let set_by = row["set_by"]["name"]
            .as_str()
            .filter(|name| !name.is_empty())
            .or_else(|| row["set_by"]["id"].as_str())
            .unwrap_or("?");
        format!(
            "{:<24} {:<20} {:<12} {}",
            row["name"].as_str().unwrap_or("?"),
            set_by,
            // The date, not the timestamp: a column a person reads across.
            row["set_at"]
                .as_str()
                .and_then(|at| at.split('T').next())
                .unwrap_or(""),
            if apps.is_empty() {
                "none".to_owned()
            } else {
                apps.join(", ")
            }
        )
        .trim_end()
        .to_owned()
    }));
    lines
}

// ---------------------------------------------------------------------------
// Finding things, and the folder hierarchy
// ---------------------------------------------------------------------------

fn app_lines(rows: &[Value]) -> Vec<String> {
    rows.iter()
        .map(|app| {
            format!(
                "{:<28} {:<6} {}",
                app["name"].as_str().unwrap_or("?"),
                app["type"].as_str().unwrap_or("app"),
                app["url"].as_str().unwrap_or("")
            )
        })
        .collect()
}

pub(crate) async fn search(
    ctx: &Ctx,
    query: String,
    app_type: Option<String>,
) -> Result<i32, CliError> {
    let apps = open(ctx).await?;
    let mut params = format!("q={}", client::encode(&query));
    if let Some(app_type) = &app_type {
        params.push_str(&format!("&type={}", client::encode(app_type)));
    }
    let body = apps.search(&params).await?;
    let rows = body["apps"].as_array().cloned().unwrap_or_default();
    let mut lines = app_lines(&rows);
    if lines.is_empty() {
        lines.push(format!("Nothing matches {query:?}."));
    }
    ctx.emit(json!({ "apps": rows }), &lines);
    Ok(EXIT_OK)
}

pub(crate) async fn ls(ctx: &Ctx, folder: Option<String>) -> Result<i32, CliError> {
    let apps = open(ctx).await?;
    let folders = apps.folders().await?["folders"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let here: Vec<&Value> = folders
        .iter()
        .filter(|row| row["parent_id"].as_str() == folder.as_deref())
        .collect();
    let mut params = "view=home&sort=modified&limit=100".to_owned();
    if let Some(folder) = &folder {
        params.push_str(&format!("&folder={}", client::encode(folder)));
    }
    let listed = apps.list(&params).await?;
    let mut rows = listed["apps"].as_array().cloned().unwrap_or_default();
    if folder.is_none() {
        // Without a `folder` the listing is the whole org, so the top level is
        // filtered here rather than asked for.
        rows.retain(|app| app["folder_id"].is_null());
    }
    let mut lines: Vec<String> = here
        .iter()
        .map(|row| {
            format!(
                "{:<28} folder {}",
                row["name"].as_str().unwrap_or("?"),
                row["id"].as_str().unwrap_or("")
            )
        })
        .collect();
    lines.extend(app_lines(&rows));
    if lines.is_empty() {
        lines.push("Empty.".to_owned());
    }
    ctx.emit(json!({ "folders": here, "apps": rows }), &lines);
    Ok(EXIT_OK)
}

pub(crate) async fn tree(ctx: &Ctx) -> Result<i32, CliError> {
    let apps = open(ctx).await?;
    let folders = apps.folders().await?["folders"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let mut lines = Vec::new();
    render_tree(&folders, None, 0, &mut lines);
    if lines.is_empty() {
        lines.push("No folders.".to_owned());
    }
    ctx.emit(json!({ "folders": folders }), &lines);
    Ok(EXIT_OK)
}

fn render_tree(folders: &[Value], parent: Option<&str>, depth: usize, out: &mut Vec<String>) {
    // Depth-bounded on purpose: the tree comes off the network, and a record
    // whose parent chain loops would otherwise recurse until the stack ends.
    if depth > 32 {
        return;
    }
    for folder in folders
        .iter()
        .filter(|row| row["parent_id"].as_str() == parent)
    {
        out.push(format!(
            "{}{}  {}",
            "  ".repeat(depth),
            folder["name"].as_str().unwrap_or("?"),
            folder["id"].as_str().unwrap_or("")
        ));
        render_tree(folders, folder["id"].as_str(), depth + 1, out);
    }
}

pub(crate) async fn mkdir(
    ctx: &Ctx,
    name: String,
    parent: Option<String>,
) -> Result<i32, CliError> {
    let apps = open(ctx).await?;
    let mut body = json!({ "name": name });
    if let Some(parent) = parent {
        body["parent_id"] = json!(parent);
    }
    let folder = apps.create_folder(&body).await?["folder"].clone();
    ctx.emit(
        json!({ "folder": folder }),
        &[format!(
            "Created folder {} ({}).",
            folder["name"].as_str().unwrap_or(&name),
            folder["id"].as_str().unwrap_or("")
        )],
    );
    Ok(EXIT_OK)
}

pub(crate) async fn mv(ctx: &Ctx, what: String, to: String) -> Result<i32, CliError> {
    let apps = open(ctx).await?;
    // `/` is the top level, which the API spells as a null parent.
    let destination = if to == "/" || to.is_empty() {
        Value::Null
    } else {
        json!(to)
    };
    if what.starts_with("app_") || what.starts_with("https://") || what.starts_with("http://") {
        let app = resolve_target(&apps, &what).await?;
        let moved = apps
            .patch_app(app_id(&app)?, &json!({ "folder_id": destination }))
            .await?["app"]
            .clone();
        ctx.emit(
            json!({ "app": moved }),
            &[
                format!("Moved {}.", moved["name"].as_str().unwrap_or("it")),
                url_line(moved["url"].as_str().unwrap_or_default()),
            ],
        );
        return Ok(EXIT_OK);
    }
    // A folder move carries `base_updated_at`, so a concurrent move is a 409
    // rather than a silent clobber.
    let folders = apps.folders().await?["folders"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let folder = folders
        .iter()
        .find(|row| row["id"].as_str() == Some(what.as_str()))
        .ok_or_else(|| failure(format!("there is no folder {what}.")))?;
    let moved = apps
        .patch_folder(
            &what,
            &json!({
                "parent_id": destination,
                "base_updated_at": folder["updated_at"],
            }),
        )
        .await?["folder"]
        .clone();
    ctx.emit(
        json!({ "folder": moved }),
        &[format!(
            "Moved folder {}.",
            moved["name"].as_str().unwrap_or(&what)
        )],
    );
    Ok(EXIT_OK)
}

pub(crate) async fn rmdir(ctx: &Ctx, folder: String) -> Result<i32, CliError> {
    let apps = open(ctx).await?;
    apps.delete_folder(&folder).await?;
    ctx.emit(
        json!({ "folder": folder, "removed": true }),
        &[format!(
            "Removed the folder {folder}. Nothing inside it was deleted."
        )],
    );
    Ok(EXIT_OK)
}

// ---------------------------------------------------------------------------
// Instructions, and the developer namespace
// ---------------------------------------------------------------------------

pub(crate) fn run_skill(ctx: &Ctx, command: SkillCommand) -> Result<i32, CliError> {
    match command {
        SkillCommand::List => {
            ctx.emit(
                json!({ "topics": skill::TOPICS.iter().map(|(name, about)| json!({
                    "name": name, "about": about
                })).collect::<Vec<_>>() }),
                &skill::TOPICS
                    .iter()
                    .map(|(name, about)| format!("{name:<8} {about}"))
                    .collect::<Vec<_>>(),
            );
            Ok(EXIT_OK)
        }
        SkillCommand::Get { topic } => {
            if topic != "core" {
                return Err(failure(format!(
                    "there is no skill topic {topic:?}. `reachpad skill list` says what there is."
                )));
            }
            let text = skill::core();
            if ctx.is_json() {
                ctx.emit(json!({ "topic": "core", "text": text }), &[]);
            } else {
                crate::out::out_bytes(text.as_bytes());
            }
            Ok(EXIT_OK)
        }
    }
}

/// `reachpad db "<sql>" [--params '[…]']` — one statement, one answer.
///
/// The two local refusals ([`db::refuse_schema_change`], [`db::parse_params`])
/// run BEFORE the client is opened, so a schema change costs no round trip and
/// leaks no statement to the server.
///
/// The answer is JSON on stdout and nothing else — no `URL:` line, no count
/// sentence. This is the one apps verb whose output is read by a program every
/// time, and Dir's shape (`rows`, `rowCount`, `changes`) is the one agents
/// already know.
pub(crate) async fn database(
    ctx: &Ctx,
    sql: String,
    params: Option<String>,
) -> Result<i32, CliError> {
    db::refuse_schema_change(&sql)?;
    let params = db::parse_params(params.as_deref())?;
    let apps = open(ctx).await?;
    let app = target_app(ctx, &apps).await?;
    let body = apps
        .db(app_id(&app)?, &json!({ "sql": sql, "params": params }))
        .await?;
    let rows = body["rows"].as_array().cloned().unwrap_or_default();
    let changes = body.get("changes").cloned().unwrap_or_else(|| json!(0));
    // Fourth and last, because an `INSERT` typed at a terminal is followed by
    // the question "which row?", and answering it only under `--json` makes a
    // person run the statement again to find out.
    let last_insert_rowid = body.get("lastInsertRowid").cloned().unwrap_or(Value::Null);
    let answer = json!({
        "rows": rows,
        "rowCount": rows.len(),
        "changes": changes,
        "lastInsertRowid": last_insert_rowid,
    });
    if ctx.is_json() {
        ctx.emit(
            json!({
                "app": app,
                "rows": rows,
                "rowCount": rows.len(),
                "changes": changes,
                "lastInsertRowid": last_insert_rowid,
            }),
            &[],
        );
    } else {
        let text = serde_json::to_string_pretty(&answer).unwrap_or_else(|_| answer.to_string());
        crate::out::out_bytes(format!("{text}\n").as_bytes());
    }
    Ok(EXIT_OK)
}

pub(crate) async fn dev(ctx: &Ctx, command: DevCommand) -> Result<i32, CliError> {
    let DevCommand::Logs { since, tail } = command;
    let apps = open(ctx).await?;
    let app = target_app(ctx, &apps).await?;
    let mut params = format!("limit={tail}");
    if let Some(since) = &since {
        params.push_str(&format!("&since={}", client::encode(since)));
    }
    let body = match apps.logs(app_id(&app)?, &params).await {
        Ok(body) => body,
        Err(e) if e.status == Some(501) => {
            return Err(failure("Logs are available for function apps only."))
        }
        Err(e) => return Err(e),
    };
    let lines = body["lines"].as_array().cloned().unwrap_or_default();
    let mut rendered: Vec<String> = lines
        .iter()
        .map(|line| {
            format!(
                "{} {:<5} {}",
                line["at"].as_str().unwrap_or(""),
                line["level"].as_str().unwrap_or("info"),
                line["text"].as_str().unwrap_or("")
            )
        })
        .collect();
    rendered.push(url_line(app["url"].as_str().unwrap_or_default()));
    ctx.emit(json!({ "app": app, "lines": lines }), &rendered);
    Ok(EXIT_OK)
}

/// `whoami` for a machine whose sign-in produced no fleet credential.
///
/// The whole answer comes from the apps API, because on an endpoint that
/// refused the credential exchange with `fleet_unconfigured` there is nothing
/// else to ask. Same three lines as the fleet answer where they mean the same
/// thing — who, which org, which kind of credential — and no workspace or
/// credit numbers, which would be invented.
pub(crate) async fn whoami(ctx: &Ctx) -> Result<i32, CliError> {
    let base = base_url();
    let apps = open(ctx).await?;
    let me = apps.me().await?;
    let user = me["user"].clone();
    let org = me["org"].clone();
    let who = user["email"]
        .as_str()
        .or_else(|| user["id"].as_str())
        .unwrap_or("?")
        .to_owned();
    ctx.emit(
        json!({
            "endpoint": Value::Null,
            "user": user["id"],
            "email": user["email"],
            "org": org,
            "credential": { "kind": "apps" },
        }),
        &[
            format!("{who} at {}", site_origin(&base)),
            format!(
                "  org: {} ({})",
                org["name"].as_str().unwrap_or("?"),
                org["id"].as_str().unwrap_or("?")
            ),
            "  credential: apps; workspaces are not available on this endpoint".to_owned(),
        ],
    );
    Ok(EXIT_OK)
}

/// The org half of the fleet `whoami`, best effort.
///
/// The fleet `whoami` answers for the credential it has always reported on, so
/// an apps API that is unreachable, or a laptop that signed in with
/// `--operator-token` and has no WorkOS session, must not turn the whole
/// command into a failure. The build prompt reads `org:` from here, and its
/// absence is the signal it checks for.
pub(crate) async fn whoami_org(ctx: &Ctx) -> Option<Value> {
    let apps = open(ctx).await.ok()?;
    let me = apps.me().await.ok()?;
    Some(me["org"].clone()).filter(|org| !org.is_null())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_function_contract_check_reads_the_exported_object() {
        assert!(exports_default_fetch(
            "export default { async fetch(request, env) { return new Response('x'); } };"
        ));
        assert!(exports_default_fetch(
            "const h = 1;\nexport default {\n  fetch(req) { return new Response('x'); },\n};"
        ));
        // A default export that is not an object carrying `fetch`.
        assert!(!exports_default_fetch("export default handler;"));
        assert!(!exports_default_fetch("module.exports = { fetch() {} };"));
        assert!(!exports_default_fetch("export default { onRequest() {} };"));
        assert!(!exports_default_fetch("// fetch(\nexport default handler;"));
        assert!(!exports_default_fetch("function fetch() {}"));
    }

    #[test]
    fn the_site_origin_comes_off_the_api_base_rather_than_a_constant() {
        assert_eq!(
            site_origin("https://reachpad.dev/api/apps"),
            "https://reachpad.dev"
        );
        assert_eq!(
            site_origin("https://rp-abc.vercel.app/api/apps"),
            "https://rp-abc.vercel.app"
        );
        assert_eq!(
            site_origin("http://127.0.0.1:7788/api/apps"),
            "http://127.0.0.1:7788"
        );
    }

    #[test]
    fn every_remote_verb_prints_one_url_line_in_the_one_shape() {
        assert_eq!(
            url_line("https://todo.apps.reachpad.dev/"),
            "URL: https://todo.apps.reachpad.dev/"
        );
    }

    #[test]
    fn an_app_share_takes_an_email_and_says_so_when_it_is_not() {
        for good in ["a@b.com", "me+tag@example.co.uk", "  a@b.io  "] {
            assert!(looks_like_email(good), "{good:?}");
        }
        // The one that matters: the workspace id an old runbook would type.
        for bad in [
            "ws-1",
            "ws-430",
            "",
            "@b.com",
            "a@",
            "a@b",
            "a b@c.com",
            "a@b@c.com",
        ] {
            assert!(!looks_like_email(bad), "{bad:?}");
        }
    }

    #[test]
    fn access_is_explained_by_who_can_open_it() {
        let lines = access_lines(&json!({
            "url": "https://todo.apps.reachpad.dev/",
            "access": { "level": "public_link", "has_password": true, "expires_at": "2027-01-01T00:00:00Z" }
        }));
        assert!(lines[0].contains("anyone with the link"), "{lines:?}");
        assert!(lines.iter().any(|l| l.contains("password")));
        assert!(lines.iter().any(|l| l.contains("2027-01-01")));
        assert_eq!(
            lines.last().unwrap(),
            "URL: https://todo.apps.reachpad.dev/"
        );
    }
}
