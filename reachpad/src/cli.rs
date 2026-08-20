//! The clap surface: eight workspace verbs, two namespaces, and every v0.1.0
//! spelling kept as a hidden alias.
//!
//! One grammar, no exceptions (design §Principles 1): workspace verbs are bare
//! (`create`/`list`/`status`/`run`/`pause`/`fork`/`archive`/`events`) and every
//! other noun is namespaced (`auth`, `keys`). The v0.1.0 tree — `ws <verb>`,
//! `exec`, `key`, `auth session` — still parses, hidden, because scripts and
//! runbooks written against it must not break on the day this ships.
//!
//! The default endpoint is PRODUCTION (ADR-0040: one host, one port, both
//! planes). Loopback needs `--endpoint http://127.0.0.1:7401`, or the bare
//! name `localhost`, which expands to the dev listen addresses of controld
//! (7401) and hub (7420) — plaintext reaches nothing else (`http_min`).

use std::path::PathBuf;

use clap::{ArgAction, Parser, Subcommand, ValueEnum};

/// The public endpoint, and the default (design §Global flags).
pub const DEFAULT_ENDPOINT: &str = "m1.reachpad.dev";
/// controld's dev listen address (`controld::DEV_LISTEN`).
pub const DEV_CONTROLD: &str = "http://127.0.0.1:7401";
/// hub's dev WebSocket URL (`DEFAULT_LISTEN` + the `/ws` route).
pub const DEV_HUB: &str = "ws://127.0.0.1:7420/ws";
/// Client-side deadline for everything, unless `--timeout` says otherwise.
pub const DEFAULT_TIMEOUT: &str = "10m";

#[derive(Parser, Debug)]
#[command(
    name = "reachpad",
    version,
    about = "reachpad — run your agents in workspaces that never lose their place",
    after_help = "The whole lifecycle is three verbs: create -> run -> pause.\n\
                  `reachpad --help --json` prints the whole command catalog."
)]
pub struct Cli {
    /// The reachpad endpoint: one host, one port (443), both planes.
    /// Defaults to what `auth login` saved, or `m1.reachpad.dev`.
    #[arg(long, global = true, env = "REACHPAD_ENDPOINT")]
    pub endpoint: Option<String>,

    /// An API key (`rpak1.…`) instead of your saved credential. Takes `-`
    /// (stdin), `@<path>` or `env:<VAR>` — never the secret itself, because
    /// argv is readable by every other process in a workspace.
    #[arg(
        long,
        global = true,
        env = "REACHPAD_API_KEY",
        value_name = "-|@path|env:VAR"
    )]
    pub api_key: Option<String>,

    /// The workspace this command concerns. Supplies the `<workspace>`
    /// argument of any verb that takes one — an explicit argument wins — and
    /// is the repeatable scope list of `keys mint`.
    #[arg(
        short = 'w',
        long,
        global = true,
        env = "REACHPAD_WORKSPACE",
        value_name = "ID"
    )]
    pub workspace: Vec<String>,

    /// Print one JSON object per command instead of prose.
    ///
    /// The env var takes the spellings a person actually exports —
    /// `REACHPAD_JSON=1`, `=true`, `=yes`, `=on` and their negatives. clap's
    /// default parser for a flag accepts only `true`/`false`, so the `=1` the
    /// reference documents used to make EVERY command die with a usage error
    /// before it dispatched. `--json` on its own still takes no value;
    /// `--json=false` turns an exported one off.
    #[arg(
        long,
        global = true,
        env = "REACHPAD_JSON",
        value_parser = clap::builder::BoolishValueParser::new(),
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "true",
        default_value_t = false,
    )]
    pub json: bool,

    /// Print only workspace ids, one per line — xargs food. Wins over --json.
    #[arg(short = 'q', long, global = true, action = ArgAction::SetTrue)]
    pub quiet: bool,

    /// Give up after this long, e.g. 90s / 30m / 12h.
    #[arg(
        long,
        global = true,
        env = "REACHPAD_TIMEOUT",
        default_value = DEFAULT_TIMEOUT,
        value_parser = parse_duration_ms,
    )]
    pub timeout: u64,

    /// Keep a separate endpoint, credential and cache under this name.
    #[arg(long, global = true, env = "REACHPAD_PROFILE", default_value = crate::conf::DEFAULT_PROFILE)]
    pub profile: String,

    /// Trust EXACTLY these PEM anchors instead of the OS trust store.
    /// Required against an endpoint on a Let's Encrypt *staging* certificate,
    /// whose hierarchy deliberately roots in no OS trust store. Repeatable.
    /// Narrower than the default, never wider — and there is deliberately no
    /// flag that disables verification.
    #[arg(long = "hub-ca", global = true, value_name = "PEM")]
    pub hub_ca: Vec<PathBuf>,

    /// v0.1.0: the control-plane URL on its own. `--endpoint` sets it.
    #[arg(long, global = true, hide = true)]
    pub controld: Option<String>,

    /// v0.1.0: the data-plane URL on its own. `--endpoint` sets it.
    #[arg(long, global = true, hide = true)]
    pub hub: Option<String>,

    /// v0.1.0: a workspace token (base64) presented as-is.
    #[arg(long, global = true, hide = true)]
    pub token: Option<String>,

    /// v0.1.0: the file a workspace token is read from and written to.
    #[arg(long, global = true, hide = true)]
    pub token_file: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Option<Command>,
}

/// The two URLs an endpoint stands for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Planes {
    pub controld: String,
    pub hub: String,
}

impl Cli {
    /// The endpoint in force: the flag or `REACHPAD_ENDPOINT`, else what
    /// `auth login` saved for this profile, else production.
    pub fn endpoint(&self, saved: Option<&str>) -> String {
        self.endpoint
            .clone()
            .or_else(|| saved.map(str::to_owned))
            .unwrap_or_else(|| DEFAULT_ENDPOINT.to_owned())
    }

    /// Expand an endpoint into the control and data plane URLs, with an
    /// explicit `--controld` / `--hub` winning its own half.
    ///
    /// A bare host (or `https://host`) is the production shape: control over
    /// HTTPS, data over QUIC, both on 443. A loopback name or an explicit
    /// `http://` URL is the dev shape — plaintext is refused to anything else
    /// before a socket opens, so this can only ever name this machine.
    pub fn planes(&self, endpoint: &str) -> Planes {
        planes_from(endpoint, self.controld.clone(), self.hub.clone())
    }

    /// The TLS trust posture for both planes — one decision, applied to the
    /// control connection and the data connection alike.
    pub fn trust(&self) -> crate::transport::TlsTrust {
        crate::transport::TlsTrust {
            dev_pin: false,
            ca_files: self.hub_ca.clone(),
        }
    }
}

/// [`Cli::planes`] as a free function, so `auth login` can expand the endpoint
/// a WorkOS sign-in named without holding the parsed `Cli`.
pub fn planes_from(
    endpoint: &str,
    controld_override: Option<String>,
    hub_override: Option<String>,
) -> Planes {
    let endpoint = endpoint.trim().trim_end_matches('/');
    let (controld, hub) = if let Some(rest) = endpoint.strip_prefix("http://") {
        let host = rest.split(':').next().unwrap_or(rest);
        (format!("http://{rest}"), format!("ws://{host}:7420/ws"))
    } else {
        let host = endpoint.strip_prefix("https://").unwrap_or(endpoint);
        if is_loopback_name(host) {
            (DEV_CONTROLD.to_owned(), DEV_HUB.to_owned())
        } else {
            (format!("https://{host}"), format!("quic://{host}"))
        }
    };
    Planes {
        controld: controld_override.unwrap_or(controld),
        hub: hub_override.unwrap_or(hub),
    }
}

/// Hosts that mean "this machine", where the dev listen addresses are what an
/// endpoint with no port can only have meant.
fn is_loopback_name(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1" | "[::1]")
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Create a workspace and print its id. The name is a label; the id is
    /// the handle.
    Create {
        /// A label for it. Optional — an unnamed workspace is fine.
        name: Option<String>,
        /// The same label, named. `create <name>` is the shorter spelling.
        #[arg(long = "name", value_name = "NAME")]
        name_flag: Option<String>,
    },
    /// Your workspaces and what each one is doing.
    List {
        /// Which to show. Archived ones are hidden unless you ask.
        #[arg(long, value_enum)]
        state: Option<StateFilter>,
    },
    /// One workspace: state, save, lease, limits.
    Status {
        /// Workspace id (or `-w` / REACHPAD_WORKSPACE).
        workspace: Option<String>,
        /// Block until it reaches this state, or `--timeout` runs out.
        #[arg(long, value_enum)]
        wait: Option<WaitState>,
    },
    /// Run ONE command in a workspace, waking it if it is paused.
    ///
    /// Everything after `--` is argv, passed to the guest as a list —
    /// `reachpad run ws-1 -- ls -la /mnt`. For a shell line, `-s` says so out
    /// loud: `reachpad run ws-1 -s 'cd /repo && make'`.
    ///
    /// Without --json this is byte-exact: the guest's stdout goes to stdout,
    /// its stderr to stderr, unmerged, and this process exits with the
    /// guest's own exit code.
    #[command(alias = "exec")]
    Run {
        /// Workspace id (or `-w` / REACHPAD_WORKSPACE).
        workspace: Option<String>,
        /// A shell line, run as `sh -lc '<line>'`.
        #[arg(short = 's', long = "shell", value_name = "SHELL-LINE")]
        shell: Option<String>,
        /// Working directory inside the guest.
        #[arg(long)]
        cwd: Option<String>,
        /// `NAME=VALUE`, repeatable. Added to the guest's environment.
        #[arg(long = "env", value_name = "NAME=VALUE")]
        env: Vec<String>,
        /// Read local stdin to EOF and feed it to the command (about 1 MiB
        /// through the public endpoint).
        #[arg(long)]
        stdin: bool,
        /// The command and its arguments.
        #[arg(last = true)]
        argv: Vec<String>,
    },
    /// Save disk and memory, then stop the meter.
    Pause {
        /// Workspace id (or `-w` / REACHPAD_WORKSPACE).
        workspace: Option<String>,
        /// Block until the save has finished, not just started.
        #[arg(long)]
        wait: bool,
    },
    /// Branch new workspaces from this one's last save.
    Fork {
        /// SOURCE workspace id (or `-w` / REACHPAD_WORKSPACE).
        workspace: Option<String>,
        /// How many children to make from that one save.
        #[arg(long, default_value_t = 1, value_name = "N")]
        count: u32,
        /// The save to root them at. Defaults to the current one.
        #[arg(long)]
        snapshot: Option<String>,
        /// A label for the child (only with --count 1).
        #[arg(long)]
        name: Option<String>,
    },
    /// Put a workspace away. Frees its slot; deletes nothing.
    Archive {
        /// Workspace id (or `-w` / REACHPAD_WORKSPACE).
        workspace: Option<String>,
    },
    /// Live event stream for one workspace.
    Events {
        /// Workspace id (or `-w` / REACHPAD_WORKSPACE).
        workspace: Option<String>,
        /// Replay everything after this event number first.
        #[arg(long, value_name = "SEQ")]
        since: Option<u64>,
    },
    /// Your credential: sign in, see who you are, sign out.
    #[command(subcommand)]
    Auth(AuthCommand),
    /// API keys (`rpak1.…`) — the credential an agent or CI runner holds.
    #[command(subcommand, alias = "key")]
    Keys(KeysCommand),
    /// Model spend: what is left, and the ceilings that bound it.
    #[command(subcommand)]
    Budget(BudgetCommand),
    /// The account-wide stop: cut every connection and pause everything.
    #[command(subcommand, name = "kill-switch")]
    KillSwitch(KillSwitchCommand),
    /// Ports inside a workspace, opened to the web (ADR-0103).
    ///
    /// A namespaced noun, not a bare verb: bare verbs act on a workspace and
    /// nothing else (ADR-0079 §1, which amended `0069-cli-v1-surface.md` §1
    /// into the rule rather than the list). And deliberately not
    /// `share`, which this CLI already taught as "give another account access
    /// to this workspace" — see the note where that verb used to be.
    #[command(subcommand, alias = "port")]
    Ports(PortsCommand),

    // ---- this installation, not the account ------------------------------
    /// Check this installation: binary, PATH, saved login, endpoints, reach.
    ///
    /// Reads state and reports it; changes nothing. Prints no credential
    /// value — only whether one is there, whether its file is private, and
    /// whether the server accepts it.
    Doctor,
    /// Update to the latest release, the way this copy was installed.
    ///
    /// A native install re-runs the checksum-verifying installer. Homebrew and
    /// Cargo builds print the command their own installer owns instead: two
    /// writers to one binary is how a working install becomes a broken one.
    Update,
    /// Print a shell completion script on stdout.
    Completions {
        /// The shell to generate for.
        #[arg(value_enum)]
        shell: CompletionShell,
    },

    // ---- v0.1.0 spellings, kept working and out of the way ---------------
    /// v0.1.0: the workspace verbs before they were flattened.
    #[command(subcommand, hide = true)]
    Ws(WsCommand),
    /// v0.1.0: an interactive terminal in a workspace (ADR-0033).
    #[command(hide = true)]
    Attach {
        workspace: Option<String>,
        #[arg(long, default_value_t = 0, conflicts_with_all = ["new", "list"])]
        pty: u32,
        /// Open a NEW terminal in the workspace and attach to it (ADR-0063).
        #[arg(long, conflicts_with = "list")]
        new: bool,
        /// Print the roster of live PTYs and exit.
        #[arg(long)]
        list: bool,
        /// Skip the controld attach call and go straight to hub.
        #[arg(long)]
        no_place: bool,
        /// Non-interactive only: keep printing output this long after stdin
        /// EOF before detaching.
        #[arg(long, default_value_t = 2_000)]
        linger_ms: u64,
        /// Never put the terminal in raw mode (scripted runs, tests).
        #[arg(long)]
        no_raw: bool,
        /// Wait up to this long for the workspace's node to join the session
        /// before sending the first keystroke (0 disables the wait).
        #[arg(long, default_value_t = 30_000)]
        wait_for_node_ms: u64,
    },
    /// v0.1.0: the event tail, before it was `events`.
    #[command(hide = true)]
    Tail { workspace: Option<String> },
    // `share` lived here until ADR-0075. It posted a grant AND printed the
    // same narrowing recomputed offline with `authz::attenuate` — the second
    // half being the mechanism ADR-0075 closes as a way to share a workspace,
    // because an appended block cannot rebind `principal`, so what it handed
    // out was the OWNER's authority under a narrower role: invisible to the
    // server, attributable to the wrong person, and unrevocable. Sharing is
    // now a server-minted row (`POST /v1/workspaces/:id/shares`) and the CLI
    // noun for it is deliberately absent until ADR-0069 §1's grammar question
    // is settled (ADR-0077) — an agent reaches the route directly.
    /// v0.1.0: the compute-credit balance, now part of `auth whoami`.
    #[command(hide = true)]
    Credits,
    /// v0.1.0: offline token utilities.
    #[command(subcommand, hide = true)]
    Token(TokenCommand),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum CompletionShell {
    Bash,
    Zsh,
    Fish,
}

#[derive(Subcommand, Debug)]
pub enum KeysCommand {
    /// Mint an `rpak1` key. Needs your own credential — a key cannot mint a
    /// key (ADR-0059 §4). The secret is printed once, alone on the last line.
    ///
    /// `--workspace <id>` (repeatable) names what the key may touch; with
    /// none it covers the whole account.
    Mint {
        /// Free-form label ("ci runner"). Never a secret.
        #[arg(long)]
        label: Option<String>,
        /// What the key may do: `collaborator` runs commands, `owner` also
        /// archives.
        #[arg(long, value_enum, default_value_t = KeyRoleArg::Collaborator)]
        role: KeyRoleArg,
        /// Key lifetime, e.g. 30d (server default 90d, max 365d).
        #[arg(long, value_parser = parse_duration_ms)]
        ttl: Option<u64>,
    },
    /// Your keys: metadata only, secrets are never readable again.
    List,
    /// Revoke a key by id. Idempotent.
    Revoke {
        /// The key id (the middle of `rpak1.<id>.<secret>`).
        id: String,
    },
}

/// `budget` is a NAMESPACE, not a bare verb: ADR-0079 §1 makes a verb bare
/// when its direct object is a WORKSPACE, and the object here is a budget.
/// `--workspace` narrows the read; it does not make the workspace the object.
#[derive(Subcommand, Debug)]
pub enum BudgetCommand {
    /// What is left: the account pool, each connection's ceiling, and — with
    /// `--workspace` — that workspace's per-link caps.
    ///
    /// Every number comes from the server (I13). A cap you cannot read is a
    /// cap you can only discover by hitting it.
    Show {
        /// Also show this workspace's per-link caps.
        #[arg(long, value_name = "WORKSPACE")]
        workspace: Option<String>,
    },
    /// Set the account-level ceiling on ONE connection: the number fan-out
    /// cannot multiply.
    ///
    /// Per-link caps are independent ceilings, so N spawned children sum to
    /// N× a parent's. This is the one that bounds the account.
    Ceiling {
        /// The connection, by name or id.
        #[arg(long, value_name = "CONNECTION")]
        connection: String,
        /// The ceiling per 30-day period, in dollars (`25`, `12.50`).
        #[arg(long, value_name = "USD", value_parser = parse_usd_micros)]
        amount: u64,
    },
    /// Set ONE link's cap inside a workspace.
    Cap {
        /// The workspace holding the link.
        workspace: Option<String>,
        /// The link id (`reachpad budget show --workspace <ws>` lists them).
        #[arg(long, value_name = "LINK")]
        link: String,
        /// The cap per 30-day period, in dollars. `0` stops the edge without
        /// cutting it — which is reversible, and an unlink is not.
        #[arg(long, value_name = "USD", value_parser = parse_usd_micros)]
        amount: u64,
    },
}

/// The kill switch is its own namespace because it is not a budget: it is an
/// account-wide stop that cuts every connection AND pauses every running
/// workspace. Burying it under `budget` would make the most destructive verb
/// in the CLI look like a settings change.
#[derive(Subcommand, Debug)]
pub enum KillSwitchCommand {
    /// STOP EVERYTHING: cut every connection on this account and pause every
    /// running workspace.
    ///
    /// This is the one place reachpad stops your work on purpose. Releasing
    /// it re-allows spend; it does not re-link what it cut.
    Engage {
        /// Why — recorded in the audit trail beside who pulled it.
        #[arg(long)]
        reason: Option<String>,
    },
    /// Allow spend again. Connections stay unlinked and workspaces stay
    /// paused: re-link what you want back.
    Release,
    /// Is it engaged?
    Status,
}

/// Dollars → micros, exactly and without floating point.
///
/// `12.50` is 12_500_000 micros. Money never travels through an `f64` here:
/// the fraction is parsed as digits and scaled, so `0.1` is 100_000 and not
/// 99_999.99999999999. More than six decimal places is refused rather than
/// rounded — a silently truncated ceiling is a ceiling nobody chose.
pub fn parse_usd_micros(raw: &str) -> Result<u64, String> {
    let text = raw.trim().trim_start_matches('$');
    let (whole, frac) = match text.split_once('.') {
        Some((w, f)) => (w, f),
        None => (text, ""),
    };
    if whole.is_empty() && frac.is_empty() {
        return Err("expected an amount in dollars, e.g. 25 or 12.50".to_owned());
    }
    if !whole.chars().all(|c| c.is_ascii_digit()) || !frac.chars().all(|c| c.is_ascii_digit()) {
        return Err(format!("{raw:?} is not an amount in dollars"));
    }
    if frac.len() > 6 {
        return Err(format!(
            "{raw:?} has more than six decimal places; the smallest unit is one micro-dollar"
        ));
    }
    let dollars: u64 = if whole.is_empty() {
        0
    } else {
        whole
            .parse()
            .map_err(|_| format!("{raw:?} is larger than this command can express"))?
    };
    let mut micros = frac.to_owned();
    while micros.len() < 6 {
        micros.push('0');
    }
    let micros: u64 = micros.parse().map_err(|_| "bad fraction".to_owned())?;
    dollars
        .checked_mul(1_000_000)
        .and_then(|d| d.checked_add(micros))
        .ok_or_else(|| format!("{raw:?} is larger than this command can express"))
}

/// `reachpad ports …` — the three things an owner does with a shared port.
///
/// Every one of them takes the port FIRST and the workspace second: the port
/// is what the person is thinking about, and the workspace is usually already
/// in `-w`/`REACHPAD_WORKSPACE`. `KeysCommand` is the structural template
/// (mint/list/revoke); the shape is deliberately the same so a person who has
/// used one namespace can guess the other.
#[derive(Subcommand, Debug)]
pub enum PortsCommand {
    /// Open a port inside the workspace and print the link that reaches it.
    ///
    /// Anyone who has the link AND is signed in to Reachpad can open it; it
    /// carries no port, no workspace id and no account name. Re-running it
    /// for a port that is already open returns the SAME link rather than a
    /// second one.
    Expose {
        /// The port your app is listening on inside the workspace (1–65535).
        port: u32,
        /// Workspace id (or `-w` / REACHPAD_WORKSPACE).
        workspace: Option<String>,
    },
    /// The ports open on this workspace, oldest first, with their links.
    List {
        /// Workspace id (or `-w` / REACHPAD_WORKSPACE).
        workspace: Option<String>,
    },
    /// Close one port. The link stops working at the visitor's next request,
    /// and re-opening the same port later mints a NEW link — a closed one
    /// never comes back.
    Revoke {
        /// The port to stop sharing.
        port: u32,
        /// Workspace id (or `-w` / REACHPAD_WORKSPACE).
        workspace: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum AuthCommand {
    /// Sign in and save the credential, after checking that it works. Also
    /// saves the endpoint, so nothing else needs it.
    ///
    /// With no flags this is WorkOS CLI Auth (ADR-0070): the command prints a
    /// short code, opens hosted AuthKit in a browser, and waits while WorkOS
    /// applies the account's configured login, MFA and SSO policy. Reachpad
    /// never receives a password or authentication factor.
    ///
    /// `--operator-token` is the non-interactive path, for automation and for
    /// the credential shown once at https://reachpad.dev/connect.
    Login {
        /// Where to read the credential: `-` (stdin), `@<path>` or
        /// `env:<VAR>`. Absent signs in through WorkOS in a browser.
        #[arg(long, value_name = "-|@path|env:VAR")]
        operator_token: Option<String>,
        /// Reachpad account service. Plain HTTP is accepted only on loopback.
        #[arg(long, default_value = crate::cli_auth::DEFAULT_ACCOUNT_URL)]
        account_url: String,
        /// Print the WorkOS URL and code without trying to open a browser.
        #[arg(long)]
        no_browser: bool,
    },
    /// Who am I, which credential, when it expires, my limits, my balance.
    #[command(alias = "session")]
    Whoami,
    /// Revoke the credential on the server and delete it from this machine.
    Logout {
        /// Revoke every credential you sign in WITH, including the ones on
        /// your other machines. The account's scoped credentials — the
        /// front door that issues new ones — are left alone.
        #[arg(long)]
        all: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum WsCommand {
    /// v0.1.0 `create`.
    Create {
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        user: Option<String>,
        #[arg(long, default_value = "dev-principal")]
        principal: String,
        #[arg(long, requires = "user")]
        idp_assertion: Option<String>,
    },
    /// v0.1.0 `list`.
    List {
        #[arg(long)]
        user: Option<String>,
        #[arg(long, default_value = "dev-principal")]
        principal: String,
        #[arg(long, requires = "user")]
        idp_assertion: Option<String>,
    },
    /// Place the lease and print node + fencing token (§8.3).
    Attach { id: String },
    /// v0.1.0 `run`.
    Exec {
        id: Option<String>,
        #[arg(long)]
        cwd: Option<String>,
        #[arg(long = "env", value_name = "NAME=VALUE")]
        env: Vec<String>,
        #[arg(long)]
        stdin: bool,
        #[arg(last = true)]
        argv: Vec<String>,
    },
    /// v0.1.0 `fork`.
    Fork {
        id: Option<String>,
        #[arg(long)]
        snapshot: Option<String>,
        #[arg(long)]
        name: Option<String>,
    },
    /// Move a workspace back to an earlier save; the forward history is
    /// preserved as an auto-created fork (§8 flow 6).
    Rewind {
        id: String,
        #[arg(long)]
        snapshot: String,
        #[arg(long)]
        preserved_name: Option<String>,
    },
    /// End the lease. Seals first by default; `--discard` does not.
    Release {
        id: Option<String>,
        #[arg(long)]
        fencing_token: Option<u64>,
        /// Skip the save: end the lease and kill the VM immediately.
        /// EVERYTHING SINCE THE LAST SAVE IS LOST.
        #[arg(long)]
        discard: bool,
    },
    /// Every sealed snapshot of a workspace, oldest first.
    Lineage { id: Option<String> },
    /// v0.1.0 `archive`.
    Archive { id: Option<String> },
    /// Mint a fresh workspace token for a workspace you own (ADR-0060).
    Token {
        id: String,
        #[arg(long)]
        user: Option<String>,
        #[arg(long, default_value = "dev-principal")]
        principal: String,
        #[arg(long, requires = "user")]
        idp_assertion: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum TokenCommand {
    /// Print a token's facts offline — parse only, no verification.
    Inspect,
}

/// What `list --state` names. The two transient states are bucketed:
/// `sealing` is still running (it holds its slot), `never_started` is paused
/// (it holds none).
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum StateFilter {
    Running,
    Paused,
    Archived,
    All,
}

impl StateFilter {
    pub fn as_str(self) -> &'static str {
        match self {
            StateFilter::Running => "running",
            StateFilter::Paused => "paused",
            StateFilter::Archived => "archived",
            StateFilter::All => "all",
        }
    }
}

/// What `status --wait` names. `list --state` has a fourth value, `all`,
/// which no workspace can ever reach — sharing that enum made `--help`
/// advertise `--wait all` and the code refuse it at runtime. Three values,
/// and clap says so.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum WaitState {
    Running,
    Paused,
    Archived,
}

impl WaitState {
    pub fn as_str(self) -> &'static str {
        match self {
            WaitState::Running => "running",
            WaitState::Paused => "paused",
            WaitState::Archived => "archived",
        }
    }
}

/// The bucket a wire state belongs to (design §Lifecycle).
#[must_use]
pub fn bucket(state: &str) -> &'static str {
    match state {
        "running" | "sealing" => "running",
        "paused" | "never_started" => "paused",
        "archived" => "archived",
        _ => "unknown",
    }
}

// `GrantRoleArg` (viewer｜collaborator) went with the `share` verb. Nothing in
// the CLI names a grantable role any more, and the rule it encoded now lives
// where it is enforced: controld refuses `owner` and `harness` at the share
// routes with `400 invalid_role` (ADR-0074), which is the only place a direct
// API caller passes through.

/// Roles a KEY may hold. `owner` is mintable (the server's `KEY_ROLES` allows
/// it) and is what a key needs to archive; it is not *grantable* — see the
/// note above, and `keys_mint_can_ask_for_owner_and_no_verb_grants_a_role`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum KeyRoleArg {
    Collaborator,
    Owner,
}

impl KeyRoleArg {
    pub fn as_str(self) -> &'static str {
        match self {
            KeyRoleArg::Collaborator => "collaborator",
            KeyRoleArg::Owner => "owner",
        }
    }
}

/// Parse a human duration (`90s`, `30m`, `12h`, `7d`; bare digits are
/// seconds) into milliseconds.
pub fn parse_duration_ms(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty duration".to_owned());
    }
    let (digits, unit) = match s.find(|c: char| !c.is_ascii_digit()) {
        Some(i) => s.split_at(i),
        None => (s, "s"),
    };
    let n: u64 = digits
        .parse()
        .map_err(|_| format!("invalid duration number in {s:?}"))?;
    let per_unit: u64 = match unit {
        "s" => 1_000,
        "m" => 60_000,
        "h" => 3_600_000,
        "d" => 86_400_000,
        other => return Err(format!("unknown duration unit {other:?} (use s/m/h/d)")),
    };
    n.checked_mul(per_unit)
        .ok_or_else(|| format!("duration {s:?} overflows milliseconds"))
}

// ---------------------------------------------------------------------------
// `--help --json`: the catalog, so an agent plans against data, not prose
// ---------------------------------------------------------------------------

/// Does this argv ask for the machine-readable catalog?
///
/// The scan STOPS at `--`: everything after it is the guest's argv, and
/// `reachpad run ws-1 -- grep --help --json file` is a grep invocation, not a
/// request for this catalog. v0.1.0 scanned the whole argv for
/// `--check-config` and printed a config report instead of running commands;
/// that bug is not worth repeating in a new flag.
#[must_use]
pub fn wants_catalog(argv: &[String]) -> bool {
    let mut help = false;
    let mut json = false;
    for arg in argv.iter().skip(1) {
        match arg.as_str() {
            "--" => break,
            "--help" | "-h" => help = true,
            "--json" => json = true,
            _ => {}
        }
    }
    help && json
}

/// The whole command tree as one JSON object.
#[must_use]
pub fn catalog() -> serde_json::Value {
    use clap::CommandFactory as _;
    describe(&Cli::command())
}

fn describe(cmd: &clap::Command) -> serde_json::Value {
    let args: Vec<serde_json::Value> = cmd
        .get_arguments()
        .filter(|a| a.get_id() != "help" && a.get_id() != "version")
        .map(|a| {
            serde_json::json!({
                "name": a.get_id().as_str(),
                "long": a.get_long(),
                "short": a.get_short().map(|c| c.to_string()),
                "value_name": a.get_value_names().map(|n| n[0].as_str().to_owned()),
                "takes_value": a.get_num_args().is_none_or(|n| n.takes_values()),
                "repeatable": matches!(a.get_action(), clap::ArgAction::Append),
                "required": a.is_required_set(),
                "env": a.get_env().map(|e| e.to_string_lossy().into_owned()),
                "positional": a.is_positional(),
                "hidden": a.is_hide_set(),
                "help": a.get_help().map(ToString::to_string),
            })
        })
        .collect();
    let subcommands: Vec<serde_json::Value> = cmd.get_subcommands().map(describe).collect();
    serde_json::json!({
        "name": cmd.get_name(),
        "about": cmd.get_about().map(ToString::to_string),
        "aliases": cmd.get_all_aliases().collect::<Vec<_>>(),
        "hidden": cmd.is_hide_set(),
        "args": args,
        "subcommands": subcommands,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Cli {
        Cli::try_parse_from(args).expect("args should parse")
    }

    /// Money never travels through an `f64`. `0.1` dollars is exactly 100_000
    /// micros, not 99_999.999…, and a seventh decimal place is REFUSED rather
    /// than rounded — a silently truncated ceiling is a ceiling nobody chose.
    #[test]
    fn dollars_become_micros_exactly_and_over_precision_is_refused() {
        for (text, micros) in [
            ("25", 25_000_000),
            ("$25", 25_000_000),
            ("12.50", 12_500_000),
            ("0.1", 100_000),
            ("0.000001", 1),
            ("0", 0),
            (".5", 500_000),
        ] {
            assert_eq!(parse_usd_micros(text), Ok(micros), "{text}");
        }
        for bad in ["", "abc", "1.2345678", "-5", "1e6", "1.2.3", "$"] {
            assert!(parse_usd_micros(bad).is_err(), "must refuse: {bad:?}");
        }
    }

    /// The C5 verbs parse under ADR-0079's amended rule: `budget` and
    /// `kill-switch` are NAMESPACES (their object is a budget and an account,
    /// not a workspace), and `budget cap` takes the workspace as its first
    /// positional because that one does act on a workspace's link.
    #[test]
    fn the_budget_namespace_parses_as_a_namespace() {
        assert!(matches!(
            parse(&["reachpad", "budget", "show"]).command,
            Some(Command::Budget(BudgetCommand::Show { workspace: None }))
        ));
        assert!(matches!(
            parse(&["reachpad", "budget", "show", "--workspace", "ws-1"]).command,
            Some(Command::Budget(BudgetCommand::Show { workspace: Some(w) })) if w == "ws-1"
        ));
        assert!(matches!(
            parse(&[
                "reachpad", "budget", "ceiling", "--connection", "claude", "--amount", "50"
            ])
            .command,
            Some(Command::Budget(BudgetCommand::Ceiling { amount, .. })) if amount == 50_000_000
        ));
        assert!(matches!(
            parse(&[
                "reachpad", "budget", "cap", "ws-1", "--link", "link-3", "--amount", "1.25"
            ])
            .command,
            Some(Command::Budget(BudgetCommand::Cap { amount, .. })) if amount == 1_250_000
        ));
        assert!(matches!(
            parse(&["reachpad", "kill-switch", "engage", "--reason", "spike"]).command,
            Some(Command::KillSwitch(KillSwitchCommand::Engage { reason: Some(r) })) if r == "spike"
        ));
        assert!(matches!(
            parse(&["reachpad", "kill-switch", "release"]).command,
            Some(Command::KillSwitch(KillSwitchCommand::Release))
        ));
        // `budget` alone is a namespace, so it needs a subcommand — the
        // grammar rule "nothing is both" made testable.
        assert!(Cli::try_parse_from(["reachpad", "budget"]).is_err());
    }

    /// The production endpoint is the default, and a saved one outranks it:
    /// a laptop that logged in once types no URL ever again (v0.1.0 P0 #1).
    #[test]
    fn the_default_endpoint_is_production_and_a_saved_one_wins() {
        let cli = parse(&["reachpad", "list"]);
        assert_eq!(cli.endpoint(None), DEFAULT_ENDPOINT);
        assert_eq!(cli.endpoint(Some("saved.example")), "saved.example");
        let planes = cli.planes(&cli.endpoint(None));
        assert_eq!(planes.controld, "https://m1.reachpad.dev");
        assert_eq!(planes.hub, "quic://m1.reachpad.dev");
        // An explicit flag outranks the saved one.
        let cli = parse(&["reachpad", "--endpoint", "flag.example", "list"]);
        assert_eq!(cli.endpoint(Some("saved.example")), "flag.example");
    }

    /// ADR-0040: one host, one port, both planes — and loopback is the one
    /// shape that is two ports, because that is what dev listens on.
    #[test]
    fn an_endpoint_expands_into_both_planes() {
        let planes = |args: &[&str], endpoint: &str| {
            let cli = parse(args);
            cli.planes(endpoint)
        };
        let p = planes(&["reachpad", "list"], "https://m1.reachpad.dev/");
        assert_eq!(p.controld, "https://m1.reachpad.dev");
        assert_eq!(p.hub, "quic://m1.reachpad.dev");

        let p = planes(&["reachpad", "list"], "localhost");
        assert_eq!(p.controld, DEV_CONTROLD);
        assert_eq!(p.hub, DEV_HUB);

        let p = planes(&["reachpad", "list"], "http://127.0.0.1:9001");
        assert_eq!(p.controld, "http://127.0.0.1:9001");
        assert_eq!(p.hub, "ws://127.0.0.1:7420/ws");

        // The v0.1.0 flags still win their own half.
        let p = planes(
            &["reachpad", "--controld", "http://127.0.0.1:9", "list"],
            "m1.reachpad.dev",
        );
        assert_eq!(p.controld, "http://127.0.0.1:9");
        assert_eq!(p.hub, "quic://m1.reachpad.dev");
    }

    #[test]
    fn trust_is_one_decision_for_both_planes() {
        let cli = parse(&["reachpad", "--hub-ca", "/tmp/staging.pem", "list"]);
        let trust = cli.trust();
        assert!(!trust.dev_pin);
        assert_eq!(trust.ca_files.len(), 1);
        assert_eq!(
            parse(&["reachpad", "list"]).trust().describe(),
            "the OS trust store"
        );
    }

    /// The v0.1.0 tree still parses, and lands on the same verbs.
    #[test]
    fn every_v0_spelling_still_parses() {
        assert!(matches!(
            parse(&["reachpad", "ws", "create", "--name", "x"]).command,
            Some(Command::Ws(WsCommand::Create { .. }))
        ));
        assert!(matches!(
            parse(&["reachpad", "exec", "ws-1", "--", "ls"]).command,
            Some(Command::Run { .. })
        ));
        assert!(matches!(
            parse(&["reachpad", "key", "list"]).command,
            Some(Command::Keys(KeysCommand::List))
        ));
        assert!(matches!(
            parse(&["reachpad", "auth", "session"]).command,
            Some(Command::Auth(AuthCommand::Whoami))
        ));
        // The m1 harness mints its own identity; those three flags stay.
        assert!(matches!(
            parse(&[
                "reachpad",
                "ws",
                "list",
                "--user",
                "u-1",
                "--principal",
                "p",
                "--idp-assertion",
                "v"
            ])
            .command,
            Some(Command::Ws(WsCommand::List { .. }))
        ));
    }

    /// `REACHPAD_JSON=1` is the spelling the reference documents and the one
    /// an agent or a CI runner exports by reflex. clap's default parser for a
    /// flag takes only `true`/`false`, so `=1` used to kill EVERY command
    /// with a usage error before it dispatched — including the ones that
    /// would have answered in the JSON the caller was asking for.
    #[test]
    fn the_json_flag_takes_the_spellings_people_export() {
        assert!(!parse(&["reachpad", "list"]).json);
        assert!(parse(&["reachpad", "--json", "list"]).json);
        for yes in ["1", "true", "yes", "on"] {
            assert!(
                parse(&["reachpad", &format!("--json={yes}"), "list"]).json,
                "--json={yes}"
            );
        }
        for no in ["0", "false", "no", "off"] {
            assert!(
                !parse(&["reachpad", &format!("--json={no}"), "list"]).json,
                "--json={no}"
            );
        }
        // The value is attached, never taken from the next word: a bare
        // `--json` must not swallow the verb after it.
        assert!(matches!(
            parse(&["reachpad", "--json", "list"]).command,
            Some(Command::List { .. })
        ));
    }

    #[test]
    fn auth_login_defaults_to_workos_and_keeps_the_non_interactive_path() {
        let cli = parse(&["reachpad", "auth", "login"]);
        let Some(Command::Auth(AuthCommand::Login {
            operator_token,
            account_url,
            no_browser,
        })) = cli.command
        else {
            panic!("auth login should parse");
        };
        // No `--operator-token` is the WorkOS device flow (ADR-0070), not a
        // prompt: absent means "sign me in", not "type the secret here".
        assert!(operator_token.is_none());
        assert_eq!(account_url, "https://reachpad.dev");
        assert!(!no_browser);

        for form in ["-", "@/tmp/cred", "env:REACHPAD_OPERATOR_TOKEN"] {
            let cli = parse(&["reachpad", "auth", "login", "--operator-token", form]);
            let Some(Command::Auth(AuthCommand::Login { operator_token, .. })) = cli.command else {
                panic!("non-interactive auth login should parse");
            };
            assert_eq!(operator_token.as_deref(), Some(form));
        }
    }

    /// Bare `reachpad` must stay a parse with no command, because that is
    /// what first-run onboarding hangs off (#50). If a default subcommand
    /// were ever added, onboarding would silently stop happening.
    #[test]
    fn bare_reachpad_is_reserved_for_first_run_onboarding() {
        let cli = parse(&["reachpad"]);
        assert!(cli.command.is_none());
    }

    #[test]
    fn maintenance_commands_and_completion_shells_parse() {
        assert!(matches!(
            parse(&["reachpad", "doctor"]).command,
            Some(Command::Doctor)
        ));
        assert!(matches!(
            parse(&["reachpad", "update"]).command,
            Some(Command::Update)
        ));
        assert!(matches!(
            parse(&["reachpad", "completions", "zsh"]).command,
            Some(Command::Completions {
                shell: CompletionShell::Zsh
            })
        ));
        assert!(Cli::try_parse_from(["reachpad", "completions", "nushell"]).is_err());
    }

    #[test]
    fn every_supported_shell_generates_a_reachpad_script() {
        use clap::CommandFactory as _;

        for generator in [
            clap_complete::Shell::Bash,
            clap_complete::Shell::Zsh,
            clap_complete::Shell::Fish,
        ] {
            let mut output = Vec::new();
            clap_complete::generate(generator, &mut Cli::command(), "reachpad", &mut output);
            let script = String::from_utf8(output).unwrap();
            assert!(
                script.contains("reachpad"),
                "empty script for {generator:?}"
            );
        }
    }

    #[test]
    fn run_takes_argv_after_the_separator_or_a_shell_line() {
        let cli = parse(&["reachpad", "run", "ws-1", "--", "cargo", "test"]);
        match cli.command {
            Some(Command::Run {
                workspace,
                argv,
                shell,
                ..
            }) => {
                assert_eq!(workspace.as_deref(), Some("ws-1"));
                assert_eq!(argv, vec!["cargo".to_owned(), "test".to_owned()]);
                assert!(shell.is_none());
            }
            other => panic!("wrong parse: {other:?}"),
        }
        let cli = parse(&["reachpad", "run", "ws-1", "-s", "make -j8"]);
        match cli.command {
            Some(Command::Run { shell, argv, .. }) => {
                assert_eq!(shell.as_deref(), Some("make -j8"));
                assert!(argv.is_empty());
            }
            other => panic!("wrong parse: {other:?}"),
        }
    }

    /// `create <name>` is the short spelling; `create --name <n>` is the one
    /// the runbook and the M1 harness already type.
    #[test]
    fn a_name_can_be_positional_or_named() {
        for args in [
            vec!["reachpad", "create", "demo"],
            vec!["reachpad", "create", "--name", "demo"],
        ] {
            match parse(&args).command {
                Some(Command::Create { name, name_flag }) => {
                    assert_eq!(name.or(name_flag).as_deref(), Some("demo"), "{args:?}");
                }
                other => panic!("wrong parse: {other:?}"),
            }
        }
        // A workspace nobody named is fine; the id is the handle.
        match parse(&["reachpad", "create"]).command {
            Some(Command::Create { name, name_flag }) => {
                assert!(name.is_none() && name_flag.is_none());
            }
            other => panic!("wrong parse: {other:?}"),
        }
    }

    #[test]
    fn keys_mint_can_ask_for_owner_and_no_verb_grants_a_role() {
        let cli = parse(&["reachpad", "keys", "mint", "--role", "owner"]);
        match cli.command {
            Some(Command::Keys(KeysCommand::Mint { role, .. })) => {
                assert_eq!(role, KeyRoleArg::Owner);
            }
            other => panic!("wrong parse: {other:?}"),
        }
        // `owner` is mintable as a KEY role and is not grantable as a SHARE
        // role. The half of that this file used to prove — `share --role
        // owner` refused at clap — went with the verb (ADR-0075): what the
        // CLI now proves is that the verb is gone and stays gone, including
        // its hidden spelling, because a hidden verb is still in the catalog
        // an agent plans against (§13.1). The refusal itself moved
        // server-side, where a direct API caller meets it too:
        // `bins/controld/tests/edges_routes.rs` and `controld_api.rs` assert
        // `400 invalid_role` for `owner` and for `harness`.
        for argv in [
            vec!["reachpad", "share", "ws-1", "--role", "owner"],
            vec!["reachpad", "share", "ws-1", "--role", "viewer"],
            vec!["reachpad", "share", "ws-1"],
        ] {
            assert!(
                Cli::try_parse_from(argv.clone()).is_err(),
                "the retired verb still parses: {argv:?}"
            );
        }
        // The control: an unrelated hidden v0.1.0 spelling still parses, so
        // the assertions above are about `share` and not about a parser that
        // has stopped accepting hidden verbs altogether.
        assert!(Cli::try_parse_from(["reachpad", "credits"]).is_ok());
    }

    /// The port noun is namespaced, takes the port first, and is NOT spelled
    /// `share` — the word this CLI already teaches for "give another account
    /// access to this workspace" (ADR-0075, ADR-0103 §1).
    #[test]
    fn ports_is_a_namespace_and_the_port_comes_before_the_workspace() {
        match parse(&["reachpad", "ports", "expose", "3000", "ws-1"]).command {
            Some(Command::Ports(PortsCommand::Expose { port, workspace })) => {
                assert_eq!(port, 3000);
                assert_eq!(workspace.as_deref(), Some("ws-1"));
            }
            other => panic!("wrong parse: {other:?}"),
        }
        // The workspace is optional here for the same reason it is optional on
        // `archive`: `-w` and REACHPAD_WORKSPACE supply it.
        match parse(&["reachpad", "ports", "expose", "8080"]).command {
            Some(Command::Ports(PortsCommand::Expose { port, workspace })) => {
                assert_eq!(port, 8080);
                assert!(workspace.is_none());
            }
            other => panic!("wrong parse: {other:?}"),
        }
        assert!(matches!(
            parse(&["reachpad", "port", "list"]).command,
            Some(Command::Ports(PortsCommand::List { .. }))
        ));
        assert!(matches!(
            parse(&["reachpad", "ports", "revoke", "3000"]).command,
            Some(Command::Ports(PortsCommand::Revoke { port: 3000, .. }))
        ));
        // A port that is not a number is refused by clap, before a socket
        // opens — the server's own `invalid_port` covers the range.
        assert!(Cli::try_parse_from(["reachpad", "ports", "expose", "http"]).is_err());
        // And the retired spelling stays retired: no bare `share`, and no
        // `expose` outside the namespace.
        assert!(Cli::try_parse_from(["reachpad", "expose", "3000"]).is_err());
    }

    #[test]
    fn states_bucket_the_two_transient_ones() {
        assert_eq!(bucket("sealing"), "running");
        assert_eq!(bucket("never_started"), "paused");
        assert_eq!(bucket("archived"), "archived");
        assert_eq!(bucket("something-new"), "unknown");
    }

    #[test]
    fn the_catalog_is_asked_for_before_the_guests_own_argv() {
        let argv =
            |parts: &[&str]| -> Vec<String> { parts.iter().map(|s| (*s).to_owned()).collect() };
        assert!(wants_catalog(&argv(&["reachpad", "--help", "--json"])));
        assert!(wants_catalog(&argv(&["reachpad", "--json", "list", "-h"])));
        assert!(!wants_catalog(&argv(&["reachpad", "--help"])));
        // The guest's own flags are the guest's.
        assert!(!wants_catalog(&argv(&[
            "reachpad", "run", "ws-1", "--", "grep", "--help", "--json"
        ])));
    }

    #[test]
    fn the_catalog_names_every_verb_and_its_aliases() {
        let catalog = catalog();
        let names: Vec<&str> = catalog["subcommands"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["name"].as_str().unwrap())
            .collect();
        for verb in [
            "create",
            "list",
            "status",
            "run",
            "pause",
            "fork",
            "archive",
            "events",
            "auth",
            "keys",
            "ports",
            // The maintenance verbs are catalog entries too: an agent that
            // plans against this JSON should be able to see that the CLI can
            // diagnose and update itself (#50).
            "doctor",
            "update",
            "completions",
        ] {
            assert!(names.contains(&verb), "{verb} missing from {names:?}");
        }
        let run = catalog["subcommands"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == "run")
            .unwrap();
        assert_eq!(run["aliases"], serde_json::json!(["exec"]));
    }

    #[test]
    fn durations_parse_and_reject_junk() {
        assert_eq!(parse_duration_ms("90s").unwrap(), 90_000);
        assert_eq!(parse_duration_ms("30m").unwrap(), 1_800_000);
        assert_eq!(parse_duration_ms("12h").unwrap(), 43_200_000);
        assert_eq!(parse_duration_ms("7d").unwrap(), 604_800_000);
        assert_eq!(parse_duration_ms("45").unwrap(), 45_000); // bare = seconds
        assert!(parse_duration_ms("").is_err());
        assert!(parse_duration_ms("h").is_err());
        assert!(parse_duration_ms("10w").is_err());
        assert!(parse_duration_ms("999999999999999999d").is_err()); // overflow
    }

    #[test]
    fn the_default_timeout_is_ten_minutes() {
        assert_eq!(parse(&["reachpad", "list"]).timeout, 600_000);
        assert_eq!(
            parse(&["reachpad", "--timeout", "45s", "list"]).timeout,
            45_000
        );
    }

    /// `--wait` and `--state` do not name the same set. Sharing one enum made
    /// `--help` advertise `--wait all` — a state no workspace reaches — and
    /// the command then refused it at runtime, which is a help text that lies
    /// about the surface it documents.
    #[test]
    fn wait_names_three_states_and_all_is_not_one_of_them() {
        for state in ["running", "paused", "archived"] {
            let cli = parse(&["reachpad", "status", "ws-1", "--wait", state]);
            let Some(Command::Status { wait: Some(w), .. }) = cli.command else {
                panic!("status parses with --wait {state}");
            };
            assert_eq!(w.as_str(), state);
        }
        let refused = Cli::try_parse_from(["reachpad", "status", "ws-1", "--wait", "all"])
            .expect_err("--wait all is not a state");
        let rendered = refused.to_string();
        assert!(
            rendered.contains("[possible values: running, paused, archived]"),
            "clap lists exactly the three it accepts: {rendered}"
        );
        // `list --state all` is unaffected: it is a filter, not a destination.
        assert!(Cli::try_parse_from(["reachpad", "list", "--state", "all"]).is_ok());
    }
}
