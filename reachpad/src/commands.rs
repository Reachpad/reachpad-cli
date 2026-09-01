//! Command dispatch. All wall-clock reads and all printing live here, at the
//! outermost shell layer (I12 discipline even in a CLI).
//!
//! Every verb returns an exit code rather than an error string: the refusal a
//! user reads comes from the compiled table in [`crate::errors`], and the
//! number the shell reads comes from the same row. `--json` is a rendering of
//! that one decision, never a second code path.

use std::io::IsTerminal as _;
use std::io::Write as _;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use clap::CommandFactory as _;
use clap::Parser as _;
use serde_json::{json, Value};

use crate::api::{self, Auth, Client, ExecItem, ExecSpec};
use crate::cli::{
    self, AuthCommand, BudgetCommand, Cli, Command, ConnectCommand, KeysCommand, KillSwitchCommand,
    PortsCommand, StateFilter, TokenCommand, WaitState, WsCommand,
};
use crate::conf;
use crate::errors::{self, CliError, EXIT_OK, EXIT_USAGE};
use crate::render;
use crate::state;
use crate::tail::{TailItem, TailOptions, TailSession};

/// How often `--wait` asks, and the bound it asks within.
const POLL_MS: u64 = 2_000;
/// The node's own budget for a seal (`nodeplane::seal_budget_exceeded`).
const SEAL_BUDGET_MS: u64 = 600_000;
/// The lease only ends by TTL after the node stops renewing (`boot.rs`).
const LEASE_TTL_MS: u64 = 30_000;
/// Room for the last heartbeat to land after that.
const SEAL_MARGIN_MS: u64 = 60_000;

/// Where a person connects GitHub. The web app owns the whole ceremony — the
/// App install, the account picker, GitHub's own confirmation — so this
/// constant is the only part of it this CLI knows.
const CONNECT_GITHUB_URL: &str = "https://reachpad.dev/connect/github";
/// How often `connect github` asks whether the browser half has finished.
const CONNECT_POLL_MS: u64 = 3_000;
/// The longest it backs off to after a poll that could not be answered.
const CONNECT_POLL_MAX_MS: u64 = 30_000;
/// How long it waits before saying so. Long enough to install an App on an
/// organization whose owner has to approve it first.
const CONNECT_DEADLINE_MS: u64 = 600_000;

/// Entry point for `main`: returns the process exit code.
///
/// Nothing runs before clap sees the argv. v0.1.0 ran the shared service
/// startup here, which read `REACHPAD_MODE` (so an unrecognized value bricked
/// `--version`), printed a `reachpad ready` line on every command, and scanned
/// the WHOLE argv for `--check-config` — including past `--`, so
/// `run <ws> -- grep --check-config file` printed a config report instead of
/// running anything. A client has no platform config to check.
pub async fn run(argv: Vec<String>) -> anyhow::Result<i32> {
    // `--help --json` is the catalog, so an agent plans against data rather
    // than parsing prose. Scanned before clap, which would print prose and
    // exit — and scanned only up to `--`, so a guest's own `--help` is the
    // guest's.
    if cli::wants_catalog(&argv) {
        println!("{}", serde_json::to_string_pretty(&cli::catalog())?);
        return Ok(EXIT_OK);
    }
    let cli = match Cli::try_parse_from(&argv) {
        Ok(cli) => cli,
        Err(e) => {
            // --help/--version exit 0; usage errors exit 2. clap renders.
            let code = if e.use_stderr() { EXIT_USAGE } else { EXIT_OK };
            let _ = e.print();
            return Ok(code);
        }
    };
    // The endpoint a login saved is resolved inside `Ctx::new` (conf.rs
    // `[endpoint]`), not here: `--endpoint` on the command line, then
    // REACHPAD_ENDPOINT, then the saved one, then the production default.
    let mut cli = cli;
    let Some(command) = cli.command.take() else {
        // No verb is not a usage error on a terminal: it is a person who has
        // just installed this and typed its name (#50). A pipe still gets the
        // refusal, so no script starts a browser sign-in by accident.
        return onboarding(&cli).await;
    };
    // The rendering decision is known from the argv alone, so the refusals
    // raised while BUILDING the context — an unparsable config file, a
    // literal `--api-key` — are rendered the same way as every later one. A
    // caller that asked for JSON and got a prose line on stderr cannot read
    // the code or the remedy, which is the whole point of `--json`.
    let json = cli.json && !cli.quiet;
    let ctx = match Ctx::build(&cli, &command, matches!(command, Command::Doctor)) {
        Ok(ctx) => ctx,
        Err(e) => return Ok(report(&e, command_name(&command), json)),
    };
    match dispatch(&ctx, command).await {
        Ok(code) => Ok(code),
        Err(e) => Ok(ctx.report(&e)),
    }
}

// ---------------------------------------------------------------------------
// Everything one command needs to know about the world
// ---------------------------------------------------------------------------

pub(crate) struct Ctx {
    pub(crate) controld: String,
    pub(crate) hub: String,
    trust: crate::transport::TlsTrust,
    pub(crate) paths: conf::Paths,
    pub(crate) endpoint: String,
    /// The name this command answers to in `--json`.
    command: &'static str,
    json: bool,
    quiet: bool,
    timeout_ms: u64,
    /// `-w` / REACHPAD_WORKSPACE: the fallback for a verb's `<workspace>`
    /// argument, and the scope list of `keys mint`.
    workspaces: Vec<String>,
    api_key: Option<String>,
    token: Option<String>,
    token_file: Option<std::path::PathBuf>,
    /// `--controld` / `--hub`, kept so `auth login` can re-derive the planes
    /// for an endpoint it only learns about mid-command without losing the
    /// overrides that outrank it.
    plane_overrides: (Option<String>, Option<String>),
    /// The older-fleet notice is said once per command, not once per call.
    noticed: std::cell::Cell<bool>,
}

impl Ctx {
    fn new(cli: &Cli, command: &Command) -> Result<Ctx, CliError> {
        Ctx::build(cli, command, false)
    }

    /// `tolerate_unreadable_config` is for `doctor` and nothing else: an
    /// unparsable `config.toml` or `credentials.toml` is exactly the state
    /// doctor exists to name, so refusing to build a context for it would
    /// leave the one command that could explain the breakage unable to run.
    /// Every other command still refuses — acting on a half-understood
    /// configuration is worse than stopping.
    ///
    /// Both steps below have to be tolerated, not just the config load: the
    /// v0.1.0 migration READS the credential store to decide whether it has
    /// anything to do, so a damaged credentials file stops a command there,
    /// one line before the config is even looked at.
    fn build(
        cli: &Cli,
        command: &Command,
        tolerate_unreadable_config: bool,
    ) -> Result<Ctx, CliError> {
        let paths = conf::Paths::new(&cli.profile);
        match state::migrate_v0_files(&paths, now_ms()) {
            Ok(Some(line)) => eprintln!("reachpad: {line}"),
            Ok(None) => {}
            // Doctor re-reads the store itself and reports what it finds
            // there, with the file named. Swallowing the error here loses
            // nothing: the same failure is about to be a printed check.
            Err(_) if tolerate_unreadable_config => {}
            Err(e) => return Err(e.into()),
        }
        let config = match conf::load_config(&paths) {
            Ok(config) => config,
            Err(_) if tolerate_unreadable_config => conf::Config::default(),
            Err(e) => return Err(e.into()),
        };
        let endpoint = cli.endpoint(config.endpoint.as_deref());
        let planes = cli.planes(&endpoint);
        let api_key = match &cli.api_key {
            Some(value) => Some(conf::read_secret_arg("--api-key", value)?),
            None => None,
        };
        Ok(Ctx {
            controld: planes.controld,
            hub: planes.hub,
            trust: cli.trust(),
            paths,
            endpoint,
            command: command_name(command),
            // `-q` wins over `--json`: a caller that asked for ids wants ids.
            json: cli.json && !cli.quiet,
            quiet: cli.quiet,
            timeout_ms: cli.timeout,
            workspaces: cli.workspace.clone(),
            api_key,
            token: cli.token.clone(),
            token_file: cli.token_file.clone(),
            plane_overrides: (cli.controld.clone(), cli.hub.clone()),
            noticed: std::cell::Cell::new(false),
        })
    }

    pub(crate) fn client(&self) -> Client {
        Client::with_trust(&self.controld, self.trust.clone())
    }

    /// The two planes for an endpoint other than this command's own — the one
    /// a WorkOS sign-in just named. `--controld`/`--hub` still win, exactly as
    /// they do for [`Ctx::new`].
    fn planes_for(&self, endpoint: &str) -> cli::Planes {
        if endpoint == self.endpoint {
            return cli::Planes {
                controld: self.controld.clone(),
                hub: self.hub.clone(),
            };
        }
        let (controld, hub) = self.plane_overrides.clone();
        cli::planes_from(endpoint, controld, hub)
    }

    /// The workspace this command acts on: the argument, else `-w` /
    /// `REACHPAD_WORKSPACE`. An explicit argument always wins.
    fn workspace(&self, given: Option<String>) -> Result<String, CliError> {
        if given.is_none() && self.workspaces.len() > 1 {
            return Err(CliError::usage(
                "this command acts on one workspace; `-w` was given more than once.",
            ));
        }
        given
            .or_else(|| self.workspaces.first().cloned())
            .map(|w| w.trim().to_owned())
            .filter(|w| !w.is_empty())
            .ok_or_else(|| {
                CliError::usage(
                    "no workspace given. Name it on the command line, or set one with \
                     `-w <id>` or REACHPAD_WORKSPACE.",
                )
            })
    }

    /// The success rendering: a JSON envelope, or the human lines. `-q` says
    /// only ids are wanted, and those are printed by [`Ctx::ids`].
    pub(crate) fn emit(&self, data: Value, human: &[String]) {
        if self.quiet {
            return;
        }
        if self.json {
            println!("{}", errors::ok_envelope(self.command, data));
            return;
        }
        for line in human {
            println!("{line}");
        }
    }

    /// The `-q` output: workspace ids, one per line, and nothing else.
    fn ids(&self, ids: &[String]) {
        if !self.quiet {
            return;
        }
        for id in ids {
            println!("{id}");
        }
    }

    fn report(&self, err: &CliError) -> i32 {
        report(err, self.command, self.json)
    }

    /// Said once per command, on stderr, when this fleet cannot answer
    /// something this CLI knows how to ask.
    /// What to do with the workspace that was just created.
    ///
    /// `create` prints one bare id and nothing else, which is right — a script
    /// pipes it into the next verb — and which left a person's first workspace
    /// looking like a command that had not finished. This is the missing half,
    /// and it is on STDERR and gated on stderr being a terminal, so
    /// `WS=$(reachpad create)` captures exactly the same bytes it always did.
    /// Silent under `--json` and `-q` for the same reason: both are asked for
    /// by something that is parsing, and neither is a person.
    fn next_step(&self, workspace: &str) {
        use std::io::IsTerminal as _;
        if self.json || self.quiet || !std::io::stderr().is_terminal() {
            return;
        }
        eprintln!(
            "  next: reachpad attach {workspace}  (or `reachpad run {workspace} -- <command>`)"
        );
    }

    fn note_older_fleet(&self) {
        if self.noticed.replace(true) {
            return;
        }
        eprintln!(
            "reachpad: {}",
            CliError::from_code("fleet_older_than_cli", None).message
        );
    }

    /// The user-scoped identity token every account-level verb needs.
    /// The account-scoped identity token, for the verbs that answer for a
    /// whole account rather than one workspace.
    ///
    /// An API key cannot produce one — it names a workspace, not an account —
    /// so this is one of the two doors [`Ctx::deny_api_key`] guards.
    async fn identity(&self) -> Result<state::Identity, CliError> {
        self.deny_api_key()?;
        state::identity(&self.client(), &self.paths, now_ms()).await
    }

    /// Refuse when the caller named an API key a verb cannot use.
    ///
    /// The alternative — what this used to do — is to ignore `--api-key` and
    /// act under whatever `auth login` left on disk. That is a silent change
    /// of identity, in the widening direction, on a command the caller was
    /// deliberately trying to confine. `keys mint` was the sharp edge: it
    /// printed an account-wide key in answer to a workspace-scoped one.
    ///
    /// Guarding the two DOORS rather than each verb is deliberate: a new
    /// account-wide verb reaches for `identity()` or `credential()` on its
    /// first line, and inherits the refusal without anyone remembering to
    /// add it. `budget show` is the proof — it took neither of the paths an
    /// earlier version of this guard covered, and shipped a hole.
    pub(crate) fn deny_api_key(&self) -> Result<(), CliError> {
        if self.api_key.is_some() {
            return Err(CliError::from_code("api_key_not_accepted", None));
        }
        Ok(())
    }

    /// The saved operator credential, or the refusal that says which of the
    /// two reasons it is missing for.
    pub(crate) fn credential(&self) -> Result<conf::Credential, CliError> {
        self.deny_api_key()?;
        match conf::load_credential(&self.paths, now_ms())? {
            conf::Stored::Present(c) => Ok(c),
            conf::Stored::Missing => Err(CliError::from_code("no_credential", None)),
            conf::Stored::Expired => Err(CliError::from_code("operator_token_expired", None)),
        }
    }

    /// What this command presents for ONE workspace, on a route that takes
    /// either carrier.
    async fn authority(&self, workspace: &str) -> Result<Held, CliError> {
        if let Some(key) = &self.api_key {
            return Ok(Held::Key(key.clone()));
        }
        Ok(Held::Biscuit(self.biscuit(workspace).await?))
    }

    /// This workspace's own token, for the routes that take nothing else.
    /// `--token` / `--token-file` are the v0.1.0 overrides; otherwise the
    /// per-workspace cache answers, re-minting silently when it cannot.
    async fn biscuit(&self, workspace: &str) -> Result<String, CliError> {
        if let Some(token) = &self.token {
            return Ok(token.trim().to_owned());
        }
        if let Some(path) = &self.token_file {
            return Ok(crate::tokenfile::read_token(path)?);
        }
        state::workspace_token(&self.client(), &self.paths, workspace, now_ms()).await
    }

    /// Remember a workspace token that a call just handed us. A v0.1.0
    /// `--token-file` still gets its copy, because the scripts that pass one
    /// read it back on the next command.
    fn remember(
        &self,
        workspace: &str,
        biscuit: &str,
        expires_at_ms: Option<u64>,
    ) -> Result<(), CliError> {
        if let Some(path) = &self.token_file {
            crate::tokenfile::write_token(path, biscuit)?;
        }
        if let Some(expires_at_ms) = expires_at_ms {
            let mut cache = state::load_workspace(&self.paths, workspace)?;
            cache.token = Some(biscuit.to_owned());
            cache.expires_at_ms = Some(expires_at_ms);
            state::save_workspace(&self.paths, workspace, &cache)?;
        }
        Ok(())
    }
}

/// The one place a refusal is printed: the envelope, or the sentence and the
/// next command. Used before a [`Ctx`] exists as well as after, so a refusal
/// is never rendered two ways depending on how early it was raised.
fn report(err: &CliError, command: &'static str, json: bool) -> i32 {
    if json {
        println!("{}", err.envelope(command));
    } else {
        eprintln!("reachpad: {}", err.message);
        if let Some(next) = &err.next_command {
            eprintln!("  try: {next}");
        }
    }
    err.exit_code
}

/// What a command holds for one workspace.
enum Held {
    Key(String),
    Biscuit(String),
}

impl Held {
    fn auth(&self) -> Auth<'_> {
        match self {
            Held::Key(k) => Auth::ApiKey(k),
            Held::Biscuit(b) => Auth::Biscuit(b),
        }
    }
}

/// Wall clock, read at the shell layer only (I12). Zero on error, which every
/// expiry check treats as expired.
fn wall_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

pub(crate) fn now_ms() -> u64 {
    wall_now_ms()
}

fn command_name(command: &Command) -> &'static str {
    match command {
        Command::Create { .. } => "workspace.create",
        Command::List { .. } => "workspace.list",
        Command::Status { .. } => "workspace.status",
        Command::Run { .. } => "workspace.run",
        Command::Pause { .. } => "workspace.pause",
        Command::Fork { .. } => "workspace.fork",
        Command::Archive { .. } => "workspace.archive",
        Command::Events { .. } => "workspace.events",
        Command::Auth(AuthCommand::Login { .. }) => "auth.login",
        Command::Auth(AuthCommand::Whoami) => "auth.whoami",
        Command::Auth(AuthCommand::Logout { .. }) => "auth.logout",
        Command::Keys(KeysCommand::Mint { .. }) => "keys.mint",
        Command::Keys(KeysCommand::List) => "keys.list",
        Command::Keys(KeysCommand::Revoke { .. }) => "keys.revoke",
        Command::Budget(BudgetCommand::Show { .. }) => "budget.show",
        Command::Budget(BudgetCommand::Ceiling { .. }) => "budget.ceiling",
        Command::Budget(BudgetCommand::Cap { .. }) => "budget.cap",
        Command::KillSwitch(KillSwitchCommand::Engage { .. }) => "kill-switch.engage",
        Command::KillSwitch(KillSwitchCommand::Release) => "kill-switch.release",
        Command::KillSwitch(KillSwitchCommand::Status) => "kill-switch.status",
        Command::Ports(PortsCommand::Expose { .. }) => "ports.expose",
        Command::Ports(PortsCommand::List { .. }) => "ports.list",
        Command::Ports(PortsCommand::Revoke { .. }) => "ports.revoke",
        Command::Connect(ConnectCommand::Github) => "connect.github",
        Command::Attach { .. } => "workspace.attach",
        Command::Tail { .. } => "workspace.events",
        Command::Credits => "account.credits",
        Command::Doctor => "cli.doctor",
        Command::Update => "cli.update",
        Command::Completions { .. } => "cli.completions",
        Command::Token(TokenCommand::Inspect) => "token.inspect",
        Command::Ws(ws) => match ws {
            WsCommand::Create { .. } => "workspace.create",
            WsCommand::List { .. } => "workspace.list",
            WsCommand::Attach { .. } => "workspace.attach",
            WsCommand::Exec { .. } => "workspace.run",
            WsCommand::Fork { .. } => "workspace.fork",
            WsCommand::Rewind { .. } => "workspace.rewind",
            WsCommand::Release { .. } => "workspace.release",
            WsCommand::Lineage { .. } => "workspace.lineage",
            WsCommand::Archive { .. } => "workspace.archive",
            WsCommand::Token { .. } => "workspace.token",
        },
    }
}

async fn dispatch(ctx: &Ctx, command: Command) -> Result<i32, CliError> {
    match command {
        Command::Create {
            name,
            name_flag,
            repo,
        } => create(ctx, name.or(name_flag), repo, None).await,
        Command::List { state } => list(ctx, state, None).await,
        Command::Status { workspace, wait } => status(ctx, workspace, wait).await,
        Command::Run {
            workspace,
            shell,
            cwd,
            env,
            stdin,
            argv,
        } => {
            run_command(
                ctx,
                RunSpec {
                    workspace,
                    shell,
                    cwd,
                    env,
                    stdin,
                    argv,
                },
            )
            .await
        }
        Command::Pause { workspace, wait } => pause(ctx, workspace, wait).await,
        Command::Fork {
            workspace,
            count,
            snapshot,
            name,
        } => fork(ctx, workspace, count, snapshot, name).await,
        Command::Archive { workspace } => archive(ctx, workspace).await,
        Command::Events { workspace, since } => events(ctx, workspace, since).await,
        Command::Auth(auth) => run_auth(ctx, auth).await,
        Command::Keys(keys) => run_keys(ctx, keys).await,
        Command::Budget(budget) => run_budget(ctx, budget).await,
        Command::KillSwitch(switch) => run_kill_switch(ctx, switch).await,
        Command::Ports(ports) => run_ports(ctx, ports).await,
        Command::Connect(connect) => run_connect(ctx, connect).await,
        Command::Doctor => crate::doctor::run(ctx).await,
        Command::Update => crate::self_update::run(ctx),
        Command::Completions { shell } => {
            let generator = match shell {
                cli::CompletionShell::Bash => clap_complete::Shell::Bash,
                cli::CompletionShell::Zsh => clap_complete::Shell::Zsh,
                cli::CompletionShell::Fish => clap_complete::Shell::Fish,
            };
            // The script goes to stdout even under `-q`: redirecting it into a
            // file is the whole use, and `--json` has nothing to say about a
            // shell script.
            //
            // Generated into a buffer first: clap_complete panics on a write
            // error, and `reachpad completions zsh | head` closes the pipe
            // early. A closed pipe on this path is the reader saying "enough",
            // not a failure.
            let mut script = Vec::new();
            clap_complete::generate(generator, &mut Cli::command(), "reachpad", &mut script);
            use std::io::Write as _;
            match std::io::stdout().write_all(&script) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {}
                Err(e) => return Err(CliError::usage(format!("cannot write completions: {e}"))),
            }
            Ok(EXIT_OK)
        }
        Command::Ws(ws) => run_ws(ctx, ws).await,
        Command::Attach {
            workspace,
            pty,
            new,
            list,
            no_place,
            linger_ms,
            no_raw,
            wait_for_node_ms,
        } => {
            attach_command(
                ctx,
                AttachSpec {
                    workspace,
                    pty,
                    new,
                    list,
                    no_place,
                    linger_ms,
                    no_raw,
                    wait_for_node_ms,
                },
            )
            .await
        }
        Command::Tail { workspace } => tail_command(ctx, workspace).await,
        Command::Credits => credits(ctx).await,
        Command::Token(TokenCommand::Inspect) => {
            let workspace = self_or_any(ctx)?;
            let token = ctx.biscuit(&workspace).await?;
            let facts = crate::inspect::inspect_b64(&token)?;
            print_inspection(&facts);
            Ok(EXIT_OK)
        }
    }
}

/// `token inspect` has no workspace argument of its own; it inspects whatever
/// token this invocation would present.
fn self_or_any(ctx: &Ctx) -> Result<String, CliError> {
    ctx.workspace(None)
}

// ---------------------------------------------------------------------------
// First run: bare `reachpad`
// ---------------------------------------------------------------------------

/// What a bare `reachpad` does, decided before anything is attempted.
///
/// The interactivity test is the safety property, and it is about ONE thing:
/// a browser sign-in is a side effect no script asked for, so it never starts
/// without a terminal to complete it in (#50).
///
/// It used to be applied to the whole command, which made `reachpad` answer
/// `no command given` to a pipe even when the caller was signed in and a
/// listing needed no terminal at all. That is the command the installer's last
/// line tells every new user to run, and an agent or a CI step is exactly the
/// caller that runs it without a tty — so the product's first instruction
/// failed for them, twice over: signed in, it refused a listing it could have
/// printed; signed out, it named `--help` instead of the one command that
/// signs a browserless machine in.
#[derive(Debug, PartialEq, Eq)]
enum Onboarding {
    /// No terminal and no credential: refuse, but name the browserless login.
    /// A browser flow here would print a URL nobody is watching and block.
    RefuseNoCredential,
    /// A terminal with no credential: sign in, then show what is there.
    SignInThenList,
    /// Signed in already: show what is there. A listing is not interactive.
    List,
}

fn onboarding_action(interactive: bool, signed_in: bool) -> Onboarding {
    match (interactive, signed_in) {
        (_, true) => Onboarding::List,
        (true, false) => Onboarding::SignInThenList,
        (false, false) => Onboarding::RefuseNoCredential,
    }
}

/// A bare `reachpad`, rendered through the same context and error table as
/// every verb — it IS `list`, with a sign-in in front of it when there is no
/// credential yet, so its `--json` envelope is a workspace listing.
async fn onboarding(cli: &Cli) -> anyhow::Result<i32> {
    let command = Command::List { state: None };
    let json = cli.json && !cli.quiet;
    let ctx = match Ctx::new(cli, &command) {
        Ok(ctx) => ctx,
        Err(e) => return Ok(report(&e, command_name(&command), json)),
    };
    match run_onboarding(cli, &ctx).await {
        Ok(code) => Ok(code),
        Err(e) => Ok(ctx.report(&e)),
    }
}

async fn run_onboarding(cli: &Cli, ctx: &Ctx) -> Result<i32, CliError> {
    // Both streams, because the sign-in writes its code to stderr and waits:
    // a terminal that cannot show the prompt cannot complete the flow.
    let interactive = std::io::stdin().is_terminal() && std::io::stderr().is_terminal();
    // A credential that cannot be READ is not a first run — it is damage, and
    // the error names the file. Only a missing or expired one starts a login.
    let signed_in = match conf::load_credential(&ctx.paths, now_ms())? {
        conf::Stored::Present(_) => true,
        conf::Stored::Missing | conf::Stored::Expired => false,
    };
    match onboarding_action(interactive, signed_in) {
        Onboarding::RefuseNoCredential => Err(CliError::usage(
            "no saved sign-in on this machine, and no terminal to complete a browser \
             sign-in in. Run `reachpad auth login --no-browser` and open the printed URL \
             on another device, or hold an API key in REACHPAD_API_KEY. \
             `reachpad --help` lists every command.",
        )),
        Onboarding::List => list(ctx, None, None).await,
        Onboarding::SignInThenList => {
            eprintln!("reachpad: no saved sign-in on this machine. Starting browser sign-in.");
            device_login(ctx, crate::cli_auth::DEFAULT_ACCOUNT_URL, false).await?;
            // The sign-in may have named a DIFFERENT endpoint than this
            // invocation defaulted to, and it saved it. Rebuild the context so
            // the listing that follows asks the fleet the credential belongs
            // to, not the one this process started out assuming.
            let ctx = Ctx::new(cli, &Command::List { state: None })?;
            if !ctx.quiet && !ctx.json {
                println!();
            }
            let code = list(&ctx, None, None).await?;
            if !ctx.quiet && !ctx.json {
                println!();
                println!("Next:");
                println!("  reachpad create <name>   a new workspace");
                println!("  reachpad run <id> -- <command>");
                println!("  reachpad attach <id>     an interactive terminal");
            }
            Ok(code)
        }
    }
}

// ---------------------------------------------------------------------------
// create / list / status / pause / fork / archive
// ---------------------------------------------------------------------------

/// The identity a create/list uses: the saved credential, or an IdP assertion
/// the v0.1.0 flags carry (the M1 harness mints its own).
struct Claimed {
    user: Option<String>,
    principal: String,
    idp_assertion: Option<String>,
}

async fn user_identity(ctx: &Ctx, claimed: Option<Claimed>) -> Result<(String, String), CliError> {
    // Also guarded here, not only in `Ctx::identity`: the explicit
    // `--idp-assertion` branch below never reaches that door.
    ctx.deny_api_key()?;
    let client = ctx.client();
    match claimed {
        Some(Claimed {
            user: Some(user),
            principal,
            idp_assertion: Some(assertion),
        }) => {
            let identity = client
                .identity_token(&user, &principal, &assertion)
                .await
                .map_err(|e| CliError::from_api(&e, None))?;
            Ok((user, identity))
        }
        claimed => {
            let identity = ctx.identity().await?;
            if let Some(user) = claimed.and_then(|c| c.user) {
                if user != identity.user_id {
                    return Err(CliError::usage(format!(
                        "--user {user} is not the account your credential names ({})",
                        identity.user_id
                    )));
                }
            }
            Ok((identity.user_id, identity.identity_token))
        }
    }
}

async fn create(
    ctx: &Ctx,
    name: Option<String>,
    repo: Option<String>,
    claimed: Option<Claimed>,
) -> Result<i32, CliError> {
    let (user, identity) = user_identity(ctx, claimed).await?;
    let name = name.unwrap_or_default();
    let created = ctx
        .client()
        .create_workspace(&user, &identity, &name, repo.as_deref())
        .await
        .map_err(|e| CliError::from_api(&e, None))?;
    ctx.remember(&created.workspace, &created.biscuit_b64, None)?;
    ctx.ids(std::slice::from_ref(&created.workspace));
    ctx.emit(
        json!({ "id": created.workspace, "name": name, "repo": repo }),
        // The id IS the output: `reachpad create demo` prints `ws-431` and a
        // script pipes it straight into the next verb.
        std::slice::from_ref(&created.workspace),
    );
    ctx.next_step(&created.workspace);
    Ok(EXIT_OK)
}

async fn list(
    ctx: &Ctx,
    filter: Option<StateFilter>,
    claimed: Option<Claimed>,
) -> Result<i32, CliError> {
    let (user, identity) = user_identity(ctx, claimed).await?;
    let listing = ctx
        .client()
        .list_workspaces(&user, &identity)
        .await
        .map_err(|e| CliError::from_api(&e, None))?;
    let stateless = listing.workspaces.iter().any(|w| w.state.is_none());
    if stateless || listing.limits.is_none() {
        ctx.note_older_fleet();
    }

    let mut counts = (0u64, 0u64, 0u64); // running, paused, archived
    for ws in &listing.workspaces {
        match cli::bucket(&row_state(ws)) {
            "running" => counts.0 += 1,
            "paused" => counts.1 += 1,
            "archived" => counts.2 += 1,
            _ => {}
        }
    }

    // Archived is only ever shown when it was explicitly asked for — as its
    // own filter, or folded into `--state all`. That same ask governs
    // whether the summary and counts mention it at all.
    let archived_requested = matches!(filter, Some(StateFilter::Archived) | Some(StateFilter::All));

    let shown: Vec<&api::Workspace> = listing
        .workspaces
        .iter()
        .filter(|ws| {
            let bucket = cli::bucket(&row_state(ws));
            match filter {
                None => bucket != "archived",
                Some(StateFilter::All) => true,
                Some(want) => bucket == want.as_str(),
            }
        })
        .collect();

    ctx.ids(
        &shown
            .iter()
            .map(|ws| ws.id.clone())
            .collect::<Vec<String>>(),
    );

    let mut data = json!({
        "workspaces": shown.iter().map(|ws| render::workspace_json(ws)).collect::<Vec<_>>(),
    });
    // Counts are a claim about state, so a fleet that reports no state gets
    // no counts rather than a made-up zero. Archived is only in the object
    // when the caller asked for it — same rule as the rows themselves.
    if !stateless {
        data["counts"] = if archived_requested {
            json!({ "running": counts.0, "paused": counts.1, "archived": counts.2 })
        } else {
            json!({ "running": counts.0, "paused": counts.1 })
        };
    }
    if let Some(limits) = &listing.limits {
        data["limits"] = render::limits_json(limits);
    }

    let mut human = Vec::new();
    if shown.is_empty() {
        human.push("no workspaces".to_owned());
    }
    for ws in &shown {
        let head = ws
            .head
            .as_ref()
            .map(|h| format!("saved {}", h.snapshot))
            .unwrap_or_else(|| "never saved".to_owned());
        human.push(format!(
            "{}  {:<16} {:<13} {head}",
            ws.id,
            render::label(&ws.name),
            row_state(ws)
        ));
    }
    if !stateless {
        human.push(if archived_requested {
            format!(
                "{} running, {} paused, {} archived",
                counts.0, counts.1, counts.2
            )
        } else {
            format!("{} running, {} paused", counts.0, counts.1)
        });
    }
    if let Some(limits) = &listing.limits {
        human.push(render::limits_line(limits).trim_start().to_owned());
    }
    ctx.emit(data, &human);
    Ok(EXIT_OK)
}

/// A row's state, with the one thing an older fleet still tells us — that it
/// is archived — read off the row itself.
fn row_state(ws: &api::Workspace) -> String {
    ws.state.clone().unwrap_or_else(|| {
        if ws.archived_at_ms.is_some() {
            "archived".to_owned()
        } else {
            "unknown".to_owned()
        }
    })
}

async fn status(
    ctx: &Ctx,
    workspace: Option<String>,
    wait: Option<WaitState>,
) -> Result<i32, CliError> {
    let workspace = ctx.workspace(workspace)?;
    let held = ctx.authority(&workspace).await?;
    let status = match wait {
        Some(target) => wait_for(ctx, &workspace, &held, target.as_str()).await?,
        None => read_status(ctx, &workspace, &held).await?,
    };
    ctx.emit(
        render::status_json(&status),
        &render::status_lines(&status, now_ms()),
    );
    Ok(EXIT_OK)
}

/// S2, with the documented fallback for a fleet that does not have it yet.
async fn read_status(ctx: &Ctx, workspace: &str, held: &Held) -> Result<api::Status, CliError> {
    match ctx.client().workspace_status(workspace, held.auth()).await {
        Ok(status) => Ok(status),
        Err(e) if api::is_route_absent(&e) => {
            ctx.note_older_fleet();
            compose_status(ctx, workspace, held).await
        }
        Err(e) => Err(CliError::from_api(&e, Some(workspace))),
    }
}

/// The design's own fallback: `list` + `lineage`, with the lease reported as
/// `unknown` because nothing on an older fleet reports it at all.
async fn compose_status(ctx: &Ctx, workspace: &str, held: &Held) -> Result<api::Status, CliError> {
    let client = ctx.client();
    let lineage = client
        .lineage(workspace, held.auth())
        .await
        .map_err(|e| CliError::from_api(&e, Some(workspace)))?;
    let mut status = api::Status {
        id: workspace.to_owned(),
        name: String::new(),
        state: "unknown".to_owned(),
        // An empty node is how the rendering layer says "unknown".
        lease: Some(api::Lease {
            node: String::new(),
            expires_at_ms: 0,
            heartbeat_at_ms: 0,
            fencing_token: None,
        }),
        head: lineage.head.as_ref().map(|h| api::Head {
            snapshot: h.id.clone(),
            sealed_at_ms: Some(h.sealed_at_ms),
        }),
        parent: None,
        snapshots: lineage.snapshots.len() as u64,
        forks: lineage.forks.len() as u64,
        idle_pause_seconds: 0,
        limits: api::Limits::default(),
        // An older fleet reports no device size on any route this fallback
        // reads, and a composed status must not invent one (WP-CP.3).
        device: None,
        // Nor free space (WP-CP.4): this fallback reads lineage and the
        // account listing, and neither carries a guest measurement.
        guest_disk: None,
        created_at_ms: 0,
        archived_at_ms: None,
    };
    // The row, when the credential can read the account listing at all — an
    // api key cannot, and a status that names no label is still a status.
    if let Ok(identity) = ctx.identity().await {
        if let Ok(listing) = client
            .list_workspaces(&identity.user_id, &identity.identity_token)
            .await
        {
            if let Some(row) = listing.workspaces.iter().find(|w| w.id == workspace) {
                status.name = row.name.clone();
                status.created_at_ms = row.created_at_ms;
                status.archived_at_ms = row.archived_at_ms;
                status.parent = row.parent.clone();
                if row.archived_at_ms.is_some() {
                    status.state = "archived".to_owned();
                    status.lease = None;
                }
            }
            if let Some(limits) = listing.limits {
                status.limits = limits;
            }
        }
    }
    Ok(status)
}

/// Poll S2 until the workspace is in `target`'s bucket.
///
/// The bound is `--timeout`, EXCEPT while the workspace reports `sealing`:
/// the node's own seal budget is ten minutes and the lease only ends by TTL
/// after it stops renewing, so a wait bounded by the default ten minutes
/// would give up on a workspace that is saving correctly (trap 31, in
/// reverse). The two timeout messages are different for the same reason.
async fn wait_for(
    ctx: &Ctx,
    workspace: &str,
    held: &Held,
    target: &str,
) -> Result<api::Status, CliError> {
    let started = now_ms();
    let mut deadline = started.saturating_add(ctx.timeout_ms);
    loop {
        let status = read_status(ctx, workspace, held).await?;
        if cli::bucket(&status.state) == target {
            return Ok(status);
        }
        // A fleet with no state route reports `unknown` for everything that
        // is not archived, and `unknown` is in no target's bucket — so this
        // loop could only spend the whole timeout to end in a message that
        // reads as a fleet fault. Say what it actually is, once.
        if status.state == "unknown" {
            return Err(CliError::from_code("fleet_predates_wait", Some(workspace)));
        }
        deadline = deadline.max(wait_deadline(started, ctx.timeout_ms, &status.state));
        let now = now_ms();
        if now >= deadline {
            let waited = json!({
                "waited_s": now.saturating_sub(started) / 1_000,
                "state": status.state,
                "target": target,
            });
            let code = if status.state == "sealing" {
                "still_sealing"
            } else {
                "wait_timeout"
            };
            return Err(CliError::from_body(code, &waited, Some(workspace)));
        }
        tokio::time::sleep(std::time::Duration::from_millis(POLL_MS + jitter_ms())).await;
    }
}

/// When a `--wait` gives up, given what the workspace is doing.
///
/// `--timeout` bounds everything EXCEPT a save in progress: the node's seal
/// budget alone is ten minutes and the lease ends 30s after it stops
/// renewing, so the default ten-minute wait would give up on a workspace that
/// is saving exactly as designed. The bound a wait honors has to be at least
/// as long as the operation it is waiting for.
fn wait_deadline(started_ms: u64, timeout_ms: u64, state: &str) -> u64 {
    let asked = started_ms.saturating_add(timeout_ms);
    if state != "sealing" {
        return asked;
    }
    asked.max(
        started_ms
            .saturating_add(SEAL_BUDGET_MS)
            .saturating_add(LEASE_TTL_MS)
            .saturating_add(SEAL_MARGIN_MS),
    )
}

/// A little spread on the poll, so N `reachpad` processes watching a fan-out
/// do not all ask on the same tick.
fn jitter_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::from(d.subsec_nanos()) % 500)
        .unwrap_or(0)
}

async fn pause(ctx: &Ctx, workspace: Option<String>, wait: bool) -> Result<i32, CliError> {
    let workspace = ctx.workspace(workspace)?;
    let held = ctx.authority(&workspace).await?;
    let client = ctx.client();

    let mut status = match client.workspace_status(&workspace, held.auth()).await {
        Ok(status) => status,
        Err(e) if api::is_route_absent(&e) => {
            return pause_on_an_older_fleet(ctx, &workspace, &held, wait).await
        }
        Err(e) => return Err(CliError::from_api(&e, Some(&workspace))),
    };

    // The lease can disappear between the read and the release; when it does,
    // the server says `no_active_lease` and the honest answer is whatever the
    // next read says — once, not in a loop.
    let mut reread = false;
    let sealing = loop {
        match status.state.as_str() {
            "archived" => return Err(CliError::from_code("workspace_archived", Some(&workspace))),
            // Nothing to save, and NOT the fork sentence: a fork child that
            // has never run still has a snapshot to fork from.
            "never_started" => {
                return Err(CliError::from_code("no_active_lease", Some(&workspace)))
            }
            "paused" => break false,
            "sealing" => break true,
            _ => {}
        }
        let Some(fencing_token) = status.lease.as_ref().and_then(|l| l.fencing_token) else {
            // S2 reports the token only to a caller it also authorizes to
            // WRITE, and `release` demands exactly that — not owner. The
            // sentence names the authority that is actually missing.
            return Err(CliError::from_code("no_write_access", Some(&workspace)));
        };
        match client
            .release(&workspace, held.auth(), fencing_token, false)
            .await
        {
            Ok(_) => break true,
            Err(e) => match refused_as(&e) {
                // Something else took the lease between the two calls; the
                // refusal carries the token that is current now.
                Some(("stale_fencing_token", body)) => {
                    let Some(current) = body["current"].as_u64() else {
                        return Err(CliError::from_api(&e, Some(&workspace)));
                    };
                    client
                        .release(&workspace, held.auth(), current, false)
                        .await
                        .map_err(|e| CliError::from_api(&e, Some(&workspace)))?;
                    break true;
                }
                Some(("no_active_lease", _)) if !reread => {
                    reread = true;
                    status = read_status(ctx, &workspace, &held).await?;
                    continue;
                }
                _ => return Err(CliError::from_api(&e, Some(&workspace))),
            },
        }
    };

    if !sealing {
        ctx.emit(
            json!({ "id": workspace, "state": "paused", "sealing": false }),
            &[format!("{workspace} is already paused.")],
        );
        return Ok(EXIT_OK);
    }
    if wait {
        let status = wait_for(ctx, &workspace, &held, "paused").await?;
        ctx.emit(
            json!({ "id": workspace, "state": status.state, "sealing": false }),
            &[format!("{workspace} is saved and stopped.")],
        );
        return Ok(EXIT_OK);
    }
    ctx.emit(
        json!({ "id": workspace, "state": "sealing", "sealing": true }),
        &[
            format!("{workspace} is saving disk."),
            "  It still holds its slot until the save finishes; `--wait` blocks until it does."
                .to_owned(),
        ],
    );
    Ok(EXIT_OK)
}

/// A fleet with no state route cannot be asked for the lease, so the only
/// honest one-call pause is the one whose fencing token we already saved.
///
/// `--wait` is refused here rather than dropped: the same fleet cannot report
/// when the save finished either, so waiting would mean exiting 0 the instant
/// the seal was ORDERED — the caller's next step (an rsync, a shutdown) would
/// run ten minutes before the disk image is durable.
async fn pause_on_an_older_fleet(
    ctx: &Ctx,
    workspace: &str,
    held: &Held,
    wait: bool,
) -> Result<i32, CliError> {
    ctx.note_older_fleet();
    if wait {
        return Err(CliError::from_code("fleet_predates_wait", Some(workspace)));
    }
    let cached = state::load_workspace(&ctx.paths, workspace)?.fencing_token;
    let Some(fencing_token) = cached else {
        return Err(CliError::from_code("fleet_predates_pause", Some(workspace)));
    };
    let client = ctx.client();
    if let Err(e) = client
        .release(workspace, held.auth(), fencing_token, false)
        .await
    {
        // The cached token is written by `attach` and never invalidated, so
        // an old one is the ordinary case here — and "something else took
        // over" would be a false account of it. Retry ONCE with the token the
        // refusal says is current, exactly as the state-route path does.
        let Some(("stale_fencing_token", body)) = refused_as(&e) else {
            return Err(CliError::from_api(&e, Some(workspace)));
        };
        let Some(current) = body["current"].as_u64() else {
            return Err(CliError::from_api(&e, Some(workspace)));
        };
        client
            .release(workspace, held.auth(), current, false)
            .await
            .map_err(|e| CliError::from_api(&e, Some(workspace)))?;
    }
    ctx.emit(
        json!({ "id": workspace, "state": "sealing", "sealing": true }),
        &[format!("{workspace} is saving disk.")],
    );
    Ok(EXIT_OK)
}

/// The code and body of a refusal, when it was one.
fn refused_as(err: &api::ApiError) -> Option<(&str, &Value)> {
    match err {
        api::ApiError::Api { code, body, .. } => Some((code.as_str(), body)),
        _ => None,
    }
}

async fn fork(
    ctx: &Ctx,
    workspace: Option<String>,
    count: u32,
    snapshot: Option<String>,
    name: Option<String>,
) -> Result<i32, CliError> {
    let workspace = ctx.workspace(workspace)?;
    if count == 0 {
        return Err(CliError::usage("--count must be at least 1."));
    }
    if count > 1 && name.is_some() {
        return Err(CliError::usage(
            "--name names one workspace; with --count the server names them.",
        ));
    }
    // Either carrier: `--api-key` when one was passed (documented for fork
    // since v1, silently ignored until 2026-08-31), the workspace's own
    // token otherwise.
    let held = ctx.authority(&workspace).await?;
    let client = ctx.client();

    // ONE snapshot for all N children: resolved here, so a fan-out cannot
    // straddle two saves if the source is sealed again mid-loop.
    let snapshot = match (snapshot, count) {
        (Some(s), _) => Some(s),
        (None, 1) => None,
        (None, _) => read_status(ctx, &workspace, &held)
            .await?
            .head
            .map(|h| h.snapshot),
    };

    let mut children = Vec::new();
    let mut rows = Vec::new();
    for _ in 0..count {
        let forked = match client
            .fork(
                &workspace,
                held.auth(),
                snapshot.as_deref(),
                name.as_deref(),
            )
            .await
        {
            Ok(forked) => forked,
            // A fan-out that stops half-way has still SPENT those slots and
            // written those tokens. Returning here would leave the caller —
            // and the `xargs` reading this stdout — with no handle for
            // workspaces that now exist, so the ids go out before the
            // refusal does.
            Err(e) => {
                ctx.ids(&children);
                let mut err = CliError::from_api(&e, Some(&workspace));
                if !children.is_empty() {
                    err.message = format!(
                        "{} {} of the {count} forks were created first and still exist: {}.",
                        err.message,
                        children.len(),
                        children.join(", ")
                    );
                    err.data = Some(json!({ "workspaces": rows }));
                }
                return Err(err);
            }
        };
        ctx.remember(&forked.workspace, &forked.biscuit_b64, None)?;
        rows.push(json!({
            "id": forked.workspace,
            "name": forked.name,
            "parent": { "workspace": workspace, "snapshot": forked.origin_snapshot },
        }));
        children.push(forked.workspace);
    }
    ctx.ids(&children);
    ctx.emit(
        json!({ "workspaces": rows }),
        &children
            .iter()
            .map(|id| id.to_owned())
            .collect::<Vec<String>>(),
    );
    Ok(EXIT_OK)
}

async fn archive(ctx: &Ctx, workspace: Option<String>) -> Result<i32, CliError> {
    let workspace = ctx.workspace(workspace)?;
    let held = ctx.authority(&workspace).await?;
    let archived = ctx
        .client()
        .archive(&workspace, held.auth())
        .await
        .map_err(|e| CliError::from_api(&e, Some(&workspace)))?;
    let mut human = vec![
        format!("{workspace} is archived and its slot is free."),
        // Not "untouched": ADR-0070 makes archived state managed
        // retention, not a permanent-backup promise. Nothing goes now.
        "  Nothing is deleted now; archived state follows managed retention.".to_owned(),
    ];
    // Said out loud, because the alternative is what this used to do: leave
    // every link live and mention none of them, so the person tidying up
    // learns from whoever still has the URL.
    if !archived.ports_closed.is_empty() {
        let ports: Vec<String> = archived.ports_closed.iter().map(u64::to_string).collect();
        human.push(format!(
            "  {} port {} closed: {}. Those links are dead, and re-opening a port mints a new one.",
            ports.len(),
            if ports.len() == 1 { "share" } else { "shares" },
            ports.join(", ")
        ));
    }
    ctx.emit(
        json!({
            "id": workspace,
            "archived_at": render::time(archived.at_ms),
            "port_shares_revoked": archived.ports_closed,
        }),
        &human,
    );
    Ok(EXIT_OK)
}

// ---------------------------------------------------------------------------
// run — the byte-exact path
// ---------------------------------------------------------------------------

struct RunSpec {
    workspace: Option<String>,
    shell: Option<String>,
    cwd: Option<String>,
    env: Vec<String>,
    stdin: bool,
    argv: Vec<String>,
}

/// Characters that make one argument look like a command line somebody meant
/// a shell to read.
const SHELL_METACHARS: &[char] = &[
    ' ', '\t', '\n', '|', '&', ';', '<', '>', '(', ')', '$', '`', '*', '?', '{', '}', '[', ']',
];

async fn run_command(ctx: &Ctx, spec: RunSpec) -> Result<i32, CliError> {
    let workspace = ctx.workspace(spec.workspace)?;
    let argv = resolve_argv(&workspace, spec.shell, spec.argv)?;

    let mut envs = std::collections::BTreeMap::new();
    for pair in &spec.env {
        let Some((k, v)) = pair.split_once('=') else {
            return Err(CliError::usage(format!(
                "--env takes NAME=VALUE; {pair:?} has no `=`."
            )));
        };
        envs.insert(k.to_owned(), v.to_owned());
    }
    // Local stdin, read to EOF BEFORE the request: the exec route takes stdin
    // as one field, not a stream.
    let stdin_b64 = if spec.stdin {
        let mut buf = Vec::new();
        std::io::Read::read_to_end(&mut std::io::stdin(), &mut buf)
            .map_err(|e| CliError::usage(format!("reading stdin for --stdin: {e}")))?;
        Some(BASE64.encode(buf))
    } else {
        None
    };

    let held = ctx.authority(&workspace).await?;
    let exec = ExecSpec {
        argv: &argv,
        cwd: spec.cwd.as_deref(),
        env: &envs,
        timeout_ms: Some(ctx.timeout_ms),
        stdin_b64,
    };
    let json = ctx.json;
    let started = std::time::Instant::now();
    let end = ctx
        .client()
        .exec(&workspace, held.auth(), &exec, |item| match item {
            // stdout to stdout and stderr to stderr, unmerged all the way to
            // the terminal: a caller diffing build output against warnings
            // cannot un-merge them, and this is the last place they could be.
            ExecItem::Out { fd, bytes } if !json => {
                if fd == 2 {
                    let _ = std::io::stderr().write_all(bytes);
                    let _ = std::io::stderr().flush();
                } else {
                    let _ = std::io::stdout().write_all(bytes);
                    let _ = std::io::stdout().flush();
                }
            }
            ExecItem::Out { fd, bytes } => {
                println!(
                    "{}",
                    json!({
                        "ev": "out",
                        "workspace": workspace,
                        "fd": fd,
                        "text": String::from_utf8_lossy(bytes),
                    })
                );
            }
            ExecItem::Waiting { reason } if !json => {
                eprintln!("reachpad: the workspace is {reason}…");
            }
            ExecItem::Waiting { reason } => {
                println!(
                    "{}",
                    json!({ "ev": "waiting", "workspace": workspace, "reason": reason })
                );
            }
        })
        .await
        .map_err(|e| CliError::from_api(&e, Some(&workspace)))?;
    let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);

    if end.get("timed_out").and_then(Value::as_bool) == Some(true) && !json {
        eprintln!("reachpad: the command hit its timeout and was killed.");
    }
    if end.get("truncated").and_then(Value::as_bool) == Some(true) && !json {
        eprintln!("reachpad: output was truncated at this account's cap.");
    }
    if end.get("error").and_then(Value::as_str).is_some() {
        return Err(CliError::from_exec_end(&end, Some(&workspace)));
    }
    // WP-CP.4, the ADVISORY arm: the workspace's disk is full and the command
    // succeeded anyway. Its zero stands — a script piping this must not see a
    // failure for a command that worked — but the user is told now rather than
    // at the next build, which is the whole point of noticing early.
    if !json {
        if let Some(sentence) = CliError::workspace_condition(&end, Some(&workspace)) {
            eprintln!("reachpad: warning — {sentence}");
        }
    }
    // EXIT WITH THE COMMAND'S OWN CODE, so this composes in a script. A
    // signal is not an exit code (§42.1: a policy and a failure must not be
    // the same value), so a killed command reports 128+n the way a shell does
    // rather than inventing one.
    let (code, signal) = match end.get("exit_code").and_then(Value::as_i64) {
        Some(code) => (code as i32, Value::Null),
        None => {
            let signal = end.get("signal").and_then(Value::as_str).unwrap_or("?");
            if !json {
                eprintln!("reachpad: killed by {signal}");
            }
            (137, json!(signal))
        }
    };
    ctx.emit(
        json!({
            "exit_code": code,
            "signal": signal,
            "duration_ms": duration_ms,
            "timed_out": end.get("timed_out").and_then(Value::as_bool).unwrap_or(false),
            // The prose caller is told on stderr; the machine caller is told
            // here, or it parses a cut-off log as a complete one.
            "truncated": end.get("truncated").and_then(Value::as_bool).unwrap_or(false),
            // WP-CP.4: null when the workspace was healthy. A machine caller
            // that keys on this can tell "the build failed" from "the build
            // failed on a workspace that had run out of room", which is the
            // distinction the whole path exists to make.
            "workspace_condition": end.get("workspace_condition").cloned().unwrap_or(Value::Null),
        }),
        &[],
    );
    Ok(code)
}

/// What to run, from either spelling — and the refusal for the third thing
/// people type, which is a shell line with no shell asked for.
fn resolve_argv(
    workspace: &str,
    shell: Option<String>,
    argv: Vec<String>,
) -> Result<Vec<String>, CliError> {
    if let Some(line) = shell {
        if !argv.is_empty() {
            return Err(CliError::usage(
                "give a shell line with -s, or an argv after `--`, not both.",
            ));
        }
        return Ok(vec!["sh".to_owned(), "-lc".to_owned(), line]);
    }
    if argv.is_empty() {
        return Err(CliError::usage(format!(
            "no command given. Put it after `--`: `reachpad run {workspace} -- <command>`, \
             or pass a shell line: `reachpad run {workspace} -s '<line>'`."
        )));
    }
    // Guessing here is how `run -- "my file"` becomes a shell injection, so
    // the refusal names both corrected forms instead.
    if argv.len() == 1 && argv[0].contains(SHELL_METACHARS) {
        let line = &argv[0];
        return Err(CliError::usage(format!(
            "{line:?} is one argument, not a command line. Either pass the argv: \
             `reachpad run {workspace} -- <program> <args…>`, or ask for a shell: \
             `reachpad run {workspace} -s {line:?}`."
        )));
    }
    Ok(argv)
}

// ---------------------------------------------------------------------------
// events
// ---------------------------------------------------------------------------

async fn events(ctx: &Ctx, workspace: Option<String>, since: Option<u64>) -> Result<i32, CliError> {
    let workspace = ctx.workspace(workspace)?;
    let biscuit = ctx.biscuit(&workspace).await?;
    let token = BASE64
        .decode(biscuit.trim())
        .map_err(|_| CliError::from_code("bad_token_encoding", Some(&workspace)))?;
    let mut session = TailSession::connect_with(
        &ctx.hub,
        &workspace,
        &token,
        TailOptions {
            trust: ctx.trust.clone(),
            since,
        },
    )
    .await?;
    // A hub that predates replay echoes no `replay` capability, and a live
    // stream is not the history that was asked for (I3).
    if since.is_some() && !session.supports_replay() {
        return Err(CliError::from_code(
            "fleet_predates_replay",
            Some(&workspace),
        ));
    }
    let effective = session
        .replay_from()
        .map(|from| from.saturating_sub(1))
        .unwrap_or_else(|| since.unwrap_or(0));
    if ctx.json {
        println!(
            "{}",
            json!({ "ev": "connected", "workspace": workspace, "since": effective })
        );
    } else if !ctx.quiet {
        println!("connected to {workspace} (from event {effective}); ctrl-c to stop");
    }

    loop {
        tokio::select! {
            item = session.next_item() => match item? {
                Some(TailItem::Event(ev)) => {
                    if ctx.json {
                        println!("{}", json!({
                            "ev": ev.type_name,
                            "workspace": workspace,
                            "seq": ev.seq,
                            "ts": render::time(ev.ts_ms),
                            "text": ev.text(),
                        }));
                    } else if !ctx.quiet {
                        println!("{}  seq={:<6} {:<14} {}", render::rfc3339(ev.ts_ms), ev.seq, ev.type_name, ev.text());
                    }
                }
                // A watermark is not an event; `tail` reports it, `events`
                // is one object per event and nothing else.
                Some(TailItem::DurableThrough(_)) => {}
                None => return Ok(EXIT_OK),
            },
            _ = tokio::signal::ctrl_c() => return Ok(EXIT_OK),
        }
    }
}

// ---------------------------------------------------------------------------
// auth
// ---------------------------------------------------------------------------

async fn run_auth(ctx: &Ctx, cmd: AuthCommand) -> Result<i32, CliError> {
    match cmd {
        AuthCommand::Login {
            operator_token,
            account_url,
            no_browser,
        } => login(ctx, operator_token, account_url, no_browser).await,
        AuthCommand::Whoami => whoami(ctx).await,
        AuthCommand::Logout { all } => logout(ctx, all).await,
    }
}

/// `auth login`, both halves of it.
///
/// With no `--operator-token` this is WorkOS CLI Auth (ADR-0070): WorkOS owns
/// the device code, the browser confirmation and every authentication factor,
/// and hands back a short-lived session token that Reachpad exchanges ONCE for
/// the ordinary ADR-0034 operator credential. The two paths converge on
/// [`save_login`], so a credential from a browser and a credential from a
/// pipe land in exactly the same store with the same echo and the same
/// `auth logout` semantics.
async fn login(
    ctx: &Ctx,
    operator_token: Option<String>,
    account_url: String,
    no_browser: bool,
) -> Result<i32, CliError> {
    let Some(value) = operator_token else {
        return device_login(ctx, &account_url, no_browser).await;
    };
    let credential = conf::read_secret_arg("--operator-token", &value)?;
    save_login(ctx, credential, ctx.endpoint.clone(), None).await
}

/// The browser path. Nothing WorkOS returns is persisted: the access token
/// buys one Reachpad credential and is dropped, and the refresh token is
/// never read (`cli_auth`).
async fn device_login(ctx: &Ctx, account_url: &str, no_browser: bool) -> Result<i32, CliError> {
    let device = crate::cli_auth::start_device_authorization(account_url, &ctx.trust)
        .await
        .map_err(CliError::from)?;
    // The prompt goes to stderr so `--json` keeps one machine-readable line on
    // stdout; the code itself is not a secret and this is the whole point of
    // the flow, so it is printed even under `-q`.
    eprintln!(
        "Open {} and enter: {}",
        device.verification_uri, device.user_code
    );
    if !no_browser && crate::cli_auth::open_browser(&device.verification_uri_complete) {
        eprintln!("  Opened it in your browser.");
    }
    eprintln!("Waiting for approval...");
    let login = crate::cli_auth::complete_device_authorization(account_url, device, &ctx.trust)
        .await
        .map_err(CliError::from)?;
    // The endpoint the exchange named, not the one this invocation defaulted
    // to: a login is also how a laptop learns where its fleet is.
    let endpoint = crate::cli_auth::endpoint_from_login(&login.controld_url, &login.hub_url)
        .map_err(CliError::from)?;
    save_login(ctx, login.operator_token, endpoint, login.email).await
}

/// Exchange the credential for a session, THEN write it — a credential that
/// does not work is not one worth keeping on disk, and the failure names why.
/// This is also where the endpoint is decided, so nothing is written until the
/// endpoint that will be saved is the one that just answered.
async fn save_login(
    ctx: &Ctx,
    credential: String,
    endpoint: String,
    email: Option<String>,
) -> Result<i32, CliError> {
    let planes = ctx.planes_for(&endpoint);
    let client = Client::with_trust(&planes.controld, ctx.trust.clone());
    let session = client
        .operator_session(&credential)
        .await
        .map_err(|e| CliError::from_api(&e, None))?;
    conf::save_credential(
        &ctx.paths,
        &conf::Credential {
            operator_token: credential,
            token_id: session.token_id.clone(),
            expires_at_ms: session.token_expires_at_ms,
        },
    )?;
    conf::save_endpoint(&ctx.paths, &endpoint)?;
    state::save_identity(
        &ctx.paths,
        &state::Identity {
            user_id: session.user_id.clone(),
            principal_id: session.principal_id.clone(),
            identity_token: session.identity_token.clone(),
            expires_at_ms: session.expires_at_ms,
        },
    )?;
    let expires = session
        .token_expires_at_ms
        .map_or(Value::Null, render::time);
    let who = email.clone().unwrap_or_else(|| session.user_id.clone());
    ctx.emit(
        json!({
            "endpoint": endpoint,
            "user": session.user_id,
            "email": email,
            "credential": { "kind": "operator", "expires_at": expires },
        }),
        &[
            format!("Signed in to {endpoint} as {who}."),
            format!(
                "  Endpoint and credential saved in {}.",
                ctx.paths.config_dir().display()
            ),
        ],
    );
    Ok(EXIT_OK)
}

async fn whoami(ctx: &Ctx) -> Result<i32, CliError> {
    let credential = ctx.credential()?;
    let client = ctx.client();
    let session = client
        .operator_session(credential.bearer())
        .await
        .map_err(|e| CliError::from_api(&e, None))?;
    let listing = client
        .list_workspaces(&session.user_id, &session.identity_token)
        .await
        .map_err(|e| CliError::from_api(&e, None))?;
    let balance = client
        .credit_balance(&session.user_id, &session.identity_token)
        .await
        .map_err(|e| CliError::from_api(&e, None))?;

    let running = listing
        .workspaces
        .iter()
        .filter(|w| cli::bucket(&row_state(w)) == "running")
        .count() as u64;
    let limits = listing.limits.clone().unwrap_or_default();
    if listing.limits.is_none() {
        ctx.note_older_fleet();
    }
    // Integer arithmetic on millicredits: a balance is money, and money does
    // not go through a float on its way to a screen.
    let credits = format!(
        "{}.{:03}",
        balance.balance_millicredits / 1_000,
        balance.balance_millicredits % 1_000
    );
    let expires = session
        .token_expires_at_ms
        .map_or(Value::Null, render::time);
    ctx.emit(
        json!({
            "endpoint": ctx.endpoint,
            "user": session.user_id,
            "credential": {
                "kind": "operator",
                "id": session.token_id,
                "expires_at": expires,
            },
            "limits": render::limits_json(&limits),
            "credits": {
                "balance": credits,
                "unit": balance.unit,
                "running_workspaces": running,
                // One credit per minute per running standard workspace.
                "per_minute": running,
            },
        }),
        &[
            format!("{} at {}", session.user_id, ctx.endpoint),
            format!(
                "  credential: operator{}",
                session
                    .token_expires_at_ms
                    .map(|ms| format!(", expires {}", render::rfc3339(ms)))
                    .unwrap_or_default()
            ),
            render::limits_line(&limits).trim_start().to_owned(),
            format!("  credits: {credits} ({running} burning now, 1/minute each)"),
        ],
    );
    Ok(EXIT_OK)
}

/// Sign this machine out, and with `--all` every machine.
///
/// Two rules this function is written around:
///
/// - **The local files always go.** A user who ran `logout` to clear a laptop
///   must not be left with the credential still on it because the network was
///   down. A failed server-side revoke is reported afterwards, with a nonzero
///   exit and the sentence saying which half happened.
/// - **`--all` revokes only the credentials you sign in with.** A SCOPED row
///   is not one of those: the `identity`-scoped row is the front door
///   reachpad.dev itself presents to mint a new laptop credential (ADR-0066),
///   so revoking it would leave the account with no self-serve way back to a
///   CLI at all.
async fn logout(ctx: &Ctx, all: bool) -> Result<i32, CliError> {
    let stored = conf::load_credential(&ctx.paths, now_ms())?;
    let mut revoked: Vec<String> = Vec::new();
    let mut note = None;
    let mut failure: Option<CliError> = None;
    if let conf::Stored::Present(credential) = &stored {
        let client = ctx.client();
        let own = credential.token_id.clone();
        let mut others: Vec<String> = Vec::new();
        if all {
            match client.operator_tokens(credential.bearer()).await {
                Ok(rows) => {
                    others = rows
                        .iter()
                        .filter(|r| r.scopes.is_empty())
                        .filter(|r| Some(&r.id) != own.as_ref())
                        .map(|r| r.id.clone())
                        .collect()
                }
                Err(e) => failure = Some(CliError::from_api(&e, None)),
            }
        }
        // Own row LAST: every call above authenticates with it.
        for id in others.into_iter().chain(own.clone()) {
            match client.revoke_operator_token(credential.bearer(), &id).await {
                Ok(()) => {
                    if !ctx.quiet {
                        // Listed by id as they go: a user revoking machines
                        // they are not sitting at should see which rows died.
                        eprintln!("reachpad: revoked {id}");
                    }
                    revoked.push(id);
                }
                Err(e) => failure = failure.or_else(|| Some(CliError::from_api(&e, None))),
            }
        }
        if own.is_none() {
            note = Some(
                "this credential predates the id echo, so only this machine forgot it \
                 — revoke it at https://reachpad.dev/connect"
                    .to_owned(),
            );
        }
    } else {
        note = Some(match stored {
            conf::Stored::Expired => "the saved credential had already expired".to_owned(),
            _ => "there was no credential on this machine".to_owned(),
        });
    }
    // Unconditional, and before anything can return: this is the half of
    // logout that only this machine can do.
    conf::forget_credential(&ctx.paths)?;
    state::forget_all(&ctx.paths)?;

    if let Some(mut failure) = failure {
        failure.message = format!(
            "{} This machine forgot its credential and its cached tokens, but the server-side \
             revoke did not happen and still has to be — the credential is gone from here, so \
             retry it at https://reachpad.dev/connect.",
            failure.message
        );
        return Err(failure);
    }
    let mut human = vec![match revoked.len() {
        0 => "Signed out on this machine.".to_owned(),
        1 => "Signed out; the credential is revoked.".to_owned(),
        n => format!("Signed out; {n} credentials revoked, including your other machines."),
    }];
    if let Some(note) = &note {
        human.push(format!("  {note}"));
    }
    ctx.emit(json!({ "revoked": revoked, "note": note }), &human);
    Ok(EXIT_OK)
}

// ---------------------------------------------------------------------------
// budget + kill-switch (creds milestone C5, design §9)
// ---------------------------------------------------------------------------

/// An `Idempotency-Key` for ONE invocation of a mutating command.
///
/// Unique per invocation rather than random: this CLI has no RNG dependency,
/// and it does not need one — the key must be stable across the retries of
/// one logical request (this client makes none inside an invocation) and
/// different between two. Process id plus nanoseconds gives that, and the
/// server's body hash turns any conceivable collision into a refusal rather
/// than into somebody else's answer.
fn idempotency_key(verb: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    format!("cli-{verb}-{}-{nanos}", std::process::id())
}

/// Micros as dollars, exactly: `12_500_000` renders `$12.50`. No floating
/// point on the way out either.
fn usd(micros: u64) -> String {
    format!("${}.{:06}", micros / 1_000_000, micros % 1_000_000)
        .trim_end_matches('0')
        .trim_end_matches('.')
        .to_owned()
}

fn scope_line(label: &str, s: &api::BudgetScope) -> String {
    match (s.cap_micros, s.remaining_micros) {
        (Some(cap), Some(left)) => format!(
            "  {label} {}: {} left of {} ({} spent, {} held)",
            s.scope_id,
            usd(left),
            usd(cap),
            usd(s.spent_micros),
            usd(s.reserved_micros),
        ),
        _ => format!(
            "  {label} {}: {} spent, no ceiling",
            s.scope_id,
            usd(s.spent_micros)
        ),
    }
}

fn scope_json(s: &api::BudgetScope) -> Value {
    json!({
        "scope": s.scope,
        "id": s.scope_id,
        "cap_micros": s.cap_micros,
        "spent_micros": s.spent_micros,
        "reserved_micros": s.reserved_micros,
        "remaining_micros": s.remaining_micros,
        "tokens_in": s.tokens_in,
        "tokens_out": s.tokens_out,
        "period_end": render::time(s.period_end_ms),
    })
}

async fn run_budget(ctx: &Ctx, cmd: BudgetCommand) -> Result<i32, CliError> {
    match cmd {
        BudgetCommand::Show { workspace } => {
            let identity = ctx.identity().await?;
            let workspace = workspace.or_else(|| ctx.workspaces.first().cloned());
            let budget = ctx
                .client()
                .budget(
                    &identity.user_id,
                    &identity.identity_token,
                    workspace.as_deref(),
                )
                .await
                .map_err(|e| budget_error(&e, workspace.as_deref()))?;
            let mut lines = Vec::new();
            if budget.kill_switch_engaged {
                lines.push(
                    "KILL SWITCH ENGAGED: nothing on this account spends until it is \
                     released (`reachpad kill-switch release`)."
                        .to_owned(),
                );
            }
            match &budget.pool {
                Some(pool) => lines.push(format!(
                    "pool: {} spent this period",
                    usd(pool.spent_micros)
                )),
                None => lines.push("pool: not reported".to_owned()),
            }
            for c in &budget.connections {
                lines.push(scope_line("connection", c));
            }
            for l in &budget.links {
                lines.push(scope_line("link", l));
            }
            if budget.connections.is_empty() && budget.links.is_empty() {
                lines.push("  no connections yet.".to_owned());
            }
            ctx.emit(
                json!({
                    "pool": budget.pool.as_ref().map(scope_json),
                    "connections": budget.connections.iter().map(scope_json).collect::<Vec<_>>(),
                    "links": budget.links.iter().map(scope_json).collect::<Vec<_>>(),
                    "kill_switch_engaged": budget.kill_switch_engaged,
                }),
                &lines,
            );
            Ok(EXIT_OK)
        }
        BudgetCommand::Ceiling { connection, amount } => {
            let identity = ctx.identity().await?;
            let affected = ctx
                .client()
                .set_connection_ceiling(
                    &connection,
                    &identity.user_id,
                    &identity.identity_token,
                    amount,
                    &idempotency_key("ceiling"),
                )
                .await
                .map_err(|e| budget_error(&e, None))?;
            ctx.emit(
                json!({
                    "connection": connection,
                    "ceiling_micros": amount,
                    "affected_workspaces": affected,
                }),
                &[
                    format!(
                        "{connection}: ceiling set to {} per 30-day period.",
                        usd(amount)
                    ),
                    format!(
                        "  {} workspace(s) hold a live link to it and will re-read it.",
                        affected.len()
                    ),
                ],
            );
            Ok(EXIT_OK)
        }
        BudgetCommand::Cap {
            workspace,
            link,
            amount,
        } => {
            let workspace = ctx.workspace(workspace)?;
            let biscuit = ctx.authority(&workspace).await?;
            let echoed = ctx
                .client()
                .set_link_budget(
                    &workspace,
                    &link,
                    match biscuit.auth() {
                        Auth::Biscuit(b) => b,
                        // The route takes the workspace's own capability in
                        // the body; an API key authenticates by header and
                        // this route has no header path, so say so rather
                        // than sending an empty capability and reading
                        // `not_owner` as if it were about the workspace.
                        Auth::ApiKey(_) => {
                            return Err(CliError::usage(
                                "setting a link's cap needs your own credential, not an API \
                                 key. Run `reachpad auth login` on this machine.",
                            ))
                        }
                    },
                    amount,
                    &idempotency_key("cap"),
                )
                .await
                .map_err(|e| budget_error(&e, Some(&workspace)))?;
            // ADR-0079 §4: where a route echoes what it changed, the CLI
            // CHECKS the echo. A fleet that accepted the call and ignored the
            // number would otherwise look like a success.
            if echoed != amount {
                return Err(CliError::from_code("cap_not_applied", Some(&workspace)));
            }
            ctx.emit(
                json!({ "workspace": workspace, "link": link, "budget_micros": amount }),
                &[format!(
                    "{link}: cap set to {} per 30-day period.",
                    usd(amount)
                )],
            );
            Ok(EXIT_OK)
        }
    }
}

/// Trap 41's posture, applied to every C5 verb: against a fleet that predates
/// these routes, REFUSE and name the redeploy. A `budget` that printed zeroes
/// against an older controld would be a client inventing a number, and a
/// `kill-switch` that answered `ok` against one would be a safety feature
/// reporting success while nothing stopped.
fn budget_error(err: &api::ApiError, workspace: Option<&str>) -> CliError {
    if api::is_route_absent(err) {
        return CliError::from_code("fleet_predates_budgets", workspace);
    }
    CliError::from_api(err, workspace)
}

async fn run_kill_switch(ctx: &Ctx, cmd: KillSwitchCommand) -> Result<i32, CliError> {
    let identity = ctx.identity().await?;
    let client = ctx.client();
    match cmd {
        KillSwitchCommand::Status => {
            let budget = client
                .budget(&identity.user_id, &identity.identity_token, None)
                .await
                .map_err(|e| budget_error(&e, None))?;
            ctx.emit(
                json!({ "engaged": budget.kill_switch_engaged }),
                &[if budget.kill_switch_engaged {
                    "ENGAGED: nothing on this account spends or starts.".to_owned()
                } else {
                    "not engaged.".to_owned()
                }],
            );
            Ok(EXIT_OK)
        }
        KillSwitchCommand::Engage { reason } => {
            let out = client
                .kill_switch(
                    &identity.user_id,
                    &identity.identity_token,
                    true,
                    reason.as_deref().unwrap_or_default(),
                )
                .await
                .map_err(|e| budget_error(&e, None))?;
            ctx.emit(
                json!({
                    "engaged": out.engaged,
                    "links_cut": out.links_cut,
                    "paused": out.paused,
                }),
                &[
                    format!(
                        "KILL SWITCH ENGAGED: {} connection link(s) cut, {} workspace(s) \
                         pausing.",
                        out.links_cut,
                        out.paused.len()
                    ),
                    "  Releasing it allows spend again; it does not re-link what it cut."
                        .to_owned(),
                ],
            );
            Ok(EXIT_OK)
        }
        KillSwitchCommand::Release => {
            let out = client
                .kill_switch(&identity.user_id, &identity.identity_token, false, "")
                .await
                .map_err(|e| budget_error(&e, None))?;
            ctx.emit(
                json!({ "engaged": false, "was_engaged": out.was_engaged }),
                &[
                    if out.was_engaged {
                        "Kill switch released: this account can spend again.".to_owned()
                    } else {
                        "The kill switch was not engaged.".to_owned()
                    },
                    "  Connections it cut stay cut — re-link what you want back.".to_owned(),
                ],
            );
            Ok(EXIT_OK)
        }
    }
}

// ---------------------------------------------------------------------------
// keys
// ---------------------------------------------------------------------------

async fn run_keys(ctx: &Ctx, cmd: KeysCommand) -> Result<i32, CliError> {
    let credential = ctx.credential()?;
    let client = ctx.client();
    match cmd {
        KeysCommand::Mint { label, role, ttl } => {
            let workspace_ids = &ctx.workspaces;
            let scope = (!workspace_ids.is_empty()).then_some(workspace_ids.as_slice());
            let minted = client
                .create_api_key(
                    credential.body_value(),
                    label.as_deref(),
                    role.as_str(),
                    scope,
                    ttl,
                )
                .await
                .map_err(|e| CliError::from_api(&e, None))?;
            if ctx.json {
                println!(
                    "{}",
                    errors::ok_envelope(
                        ctx.command,
                        json!({
                            "id": minted.id,
                            "role": minted.role,
                            "expires_at": render::time(minted.expires_at_ms),
                            "workspaces": workspace_ids,
                            "key": minted.key,
                        })
                    )
                );
                return Ok(EXIT_OK);
            }
            if !ctx.quiet {
                println!(
                    "key {} ({}), valid until {}",
                    minted.id,
                    minted.role,
                    render::rfc3339(minted.expires_at_ms)
                );
                match scope {
                    Some(ids) => println!("  it may act on: {}", ids.join(" ")),
                    None => println!("  it may act on: every workspace on this account"),
                }
                println!("  the value below is shown ONCE and is not recoverable:");
            }
            // ALONE on the last line, so `reachpad keys mint | tail -1` is
            // exactly the secret. A command that mints a credential must
            // print what it minted (trap 36).
            println!("{}", minted.key);
            Ok(EXIT_OK)
        }
        KeysCommand::List => {
            let rows = client
                .list_api_keys(credential.body_value())
                .await
                .map_err(|e| CliError::from_api(&e, None))?;
            let data: Vec<Value> = rows
                .iter()
                .map(|k| {
                    json!({
                        "id": k.id,
                        "label": k.label,
                        "role": k.role,
                        "workspaces": k.workspace_ids,
                        "expires_at": render::time(k.expires_at_ms),
                        "usable": k.usable,
                    })
                })
                .collect();
            let mut human: Vec<String> = rows
                .iter()
                .map(|k| {
                    let scope = if k.workspace_ids.is_empty() {
                        "the whole account".to_owned()
                    } else {
                        k.workspace_ids.join(",")
                    };
                    let state = match (k.usable, k.revoked_at_ms) {
                        (true, _) => "usable",
                        (false, Some(_)) => "revoked",
                        (false, None) => "expired",
                    };
                    format!(
                        "{}  {:<16} {:<13} {scope} [{state}]",
                        k.id,
                        render::label(&k.label),
                        k.role
                    )
                })
                .collect();
            if human.is_empty() {
                human.push("no keys".to_owned());
            }
            ctx.emit(json!({ "keys": data }), &human);
            Ok(EXIT_OK)
        }
        KeysCommand::Revoke { id } => {
            client
                .revoke_api_key(credential.body_value(), &id)
                .await
                .map_err(|e| CliError::from_api(&e, None))?;
            ctx.emit(
                json!({ "id": id, "revoked": true }),
                &[format!(
                    "{id} is revoked; commands presenting it are refused."
                )],
            );
            Ok(EXIT_OK)
        }
    }
}

// ---------------------------------------------------------------------------
// ports — a port inside the guest, opened to the web (ADR-0103)
// ---------------------------------------------------------------------------

/// The refusal a port-share call renders.
///
/// Two fleet-age shapes collapse into one sentence: a fleet with no such route
/// at all (a bare 404, [`api::is_route_absent`]) and a fleet that answered
/// without echoing the port it acted on ([`api::is_port_echo_missing`], trap
/// 41). ADR-0079 §4 makes that a refusal rather than a degraded success —
/// there is no half of this verb worth printing, because what it prints is a
/// link somebody is about to send to another person.
fn port_share_refusal(err: &api::ApiError, workspace: &str) -> CliError {
    if api::is_route_absent(err) || api::is_port_echo_missing(err) {
        return CliError::from_code("fleet_predates_port_shares", Some(workspace));
    }
    // The generic `not_owner` sentence advises `--role owner` without saying
    // what else that grants, and these verbs are the ones somebody automates.
    if matches!(refused_as(err), Some(("not_owner", _))) {
        return CliError::from_code("not_owner_port_share", Some(workspace));
    }
    CliError::from_api(err, Some(workspace))
}

/// After minting a link: is anything actually there?
///
/// A share is a row, and `expose` will hand out a confident link for a port
/// nothing has ever listened on — `ports expose 1` and `ports expose 3000` on
/// a workspace that has never started both print a URL and the "anyone with
/// this link" blurb, with nothing to say the link goes nowhere. The person
/// who finds out is the one it was sent to.
///
/// **It never resumes the workspace.** The state read is a GET; the dial only
/// happens when the workspace is already running. Waking a paused VM as a
/// side effect of naming a port would put a billable resume behind a command
/// nobody thought was billable — the same property ADR-0103 §5 protects on
/// the visitor's side, for the same reason.
///
/// Returns `None` when there is nothing worth saying, including every case
/// where the check itself could not run: a probe that did not execute is not
/// evidence that a port is dead, and saying so would send somebody to restart
/// a server that was serving.
async fn port_reality_check(ctx: &Ctx, workspace: &str, held: &Held, port: u32) -> Option<String> {
    let state = ctx
        .client()
        .workspace_status(workspace, held.auth())
        .await
        .ok()?
        .state;
    if state != "running" {
        return Some(format!(
            "  {workspace} is {state}, so nothing is listening yet — the link works once it is running and something is on {port}"
        ));
    }
    // The dial hub itself makes: a TCP connect to 127.0.0.1:<port> in the
    // guest. `ss` is the fallback for an image without python3.
    let script = format!(
        "if command -v python3 >/dev/null 2>&1; then \
python3 -c 'import socket,sys; s=socket.socket(); s.settimeout(2); \
sys.exit(0 if s.connect_ex((\"127.0.0.1\",{port}))==0 else 1)'; \
else ss -ltn 2>/dev/null | grep -q \":{port} \"; fi"
    );
    let argv = ["/bin/sh".to_owned(), "-lc".to_owned(), script];
    let env = std::collections::BTreeMap::new();
    let spec = api::ExecSpec {
        argv: &argv,
        cwd: None,
        env: &env,
        timeout_ms: Some(15_000),
        stdin_b64: None,
    };
    let end = ctx
        .client()
        .exec(workspace, held.auth(), &spec, |_| {})
        .await
        .ok()?;
    // 1 is the dial's own "connected to nothing". Anything else — 127 for a
    // shell that could not run it, a timeout, a refusal — is unknown, and
    // unknown says nothing.
    (end.get("exit_code").and_then(Value::as_i64) == Some(1)).then(|| {
        format!("  NOTHING IS LISTENING on {port} yet — the link resolves, and a visitor gets an error page rather than your app")
    })
}

async fn run_ports(ctx: &Ctx, cmd: PortsCommand) -> Result<i32, CliError> {
    match cmd {
        PortsCommand::Expose { port, workspace } => {
            let workspace = ctx.workspace(workspace)?;
            let held = ctx.authority(&workspace).await?;
            let share = ctx
                .client()
                .create_port_share(&workspace, held.auth(), port)
                .await
                .map_err(|e| port_share_refusal(&e, &workspace))?;
            // The link is the FIRST line and it is alone on it, so
            // `reachpad ports expose 3000 | head -1` is exactly the thing a
            // person pastes into a message — the same property `keys mint`
            // gives its secret on the last line (trap 36).
            let mut human = vec![render::port_share_target(&share)];
            if let Some(said) = render::port_share_no_origin(&share) {
                human.push(said);
            }
            human.push(format!(
                "  anyone with this link who signs in to Reachpad reaches port {} in {workspace}",
                share.port
            ));
            if let Some(said) = port_reality_check(ctx, &workspace, &held, share.port).await {
                human.push(said);
            }
            human.push(format!(
                "  close it with `reachpad ports revoke {} {workspace}`",
                share.port
            ));
            ctx.emit(render::port_share_json(&share), &human);
            Ok(EXIT_OK)
        }
        PortsCommand::List { workspace } => {
            let workspace = ctx.workspace(workspace)?;
            let held = ctx.authority(&workspace).await?;
            let shares = ctx
                .client()
                .list_port_shares(&workspace, held.auth())
                .await
                .map_err(|e| port_share_refusal(&e, &workspace))?;
            let now = now_ms();
            let data: Vec<Value> = shares.iter().map(render::port_share_json).collect();
            let mut human: Vec<String> = shares
                .iter()
                .map(|s| render::port_share_line(s, now))
                .collect();
            if human.is_empty() {
                human.push(format!("no ports are open in {workspace}"));
            }
            ctx.emit(json!({ "port_shares": data }), &human);
            Ok(EXIT_OK)
        }
        PortsCommand::Revoke { port, workspace } => {
            let workspace = ctx.workspace(workspace)?;
            let held = ctx.authority(&workspace).await?;
            let share = ctx
                .client()
                .revoke_port_share(&workspace, held.auth(), port)
                .await
                .map_err(|e| port_share_refusal(&e, &workspace))?;
            ctx.emit(
                render::port_share_json(&share),
                &[
                    format!("port {} is closed in {workspace}.", share.port),
                    // Said here because it is the one thing about this feature
                    // a person can get wrong twice: the old link is dead for
                    // good, and re-opening the port hands out a different one.
                    "  the link that reached it stops working at the next request; re-opening \
                     this port mints a NEW link."
                        .to_owned(),
                ],
            );
            Ok(EXIT_OK)
        }
    }
}

// ---------------------------------------------------------------------------
// Outside accounts (INT-171)
// ---------------------------------------------------------------------------

async fn run_connect(ctx: &Ctx, cmd: ConnectCommand) -> Result<i32, CliError> {
    match cmd {
        ConnectCommand::Github => connect_github(ctx).await,
    }
}

/// `connect github`: say what is connected, and if nothing is, wait for the
/// browser half to make it so.
///
/// The ceremony itself belongs to the web app — App install, account picker,
/// GitHub's confirmation — so this command owns exactly two things: the link,
/// and the patience. It writes nothing to disk: the connection lives on the
/// account, so the answer is the same from any machine and a second laptop
/// needs no second install.
async fn connect_github(ctx: &Ctx) -> Result<i32, CliError> {
    let identity = ctx.identity().await?;
    let client = ctx.client();
    // Both borrowed OUTSIDE the closure, so each poll's future holds a plain
    // `&Client` rather than a borrow of the closure itself. That is what lets
    // the polling loop below stay a bare `Fn() -> Future` — and a loop with
    // that shape can be driven by a fixture instead of a fleet.
    let (client, identity) = (&client, &identity);
    let ask = move || async move {
        client
            .github_connection(&identity.user_id, &identity.identity_token)
            .await
    };

    let connection = match ask().await {
        Ok(connection) => connection,
        // ADR-0079 §4: this verb ships with its route. A fleet without it says
        // 404 with no code, which would otherwise render as "the fleet refused
        // this: unknown" — a sentence whose remedy nobody could guess.
        Err(e) if api::is_route_absent(&e) => {
            return Err(CliError::from_code("fleet_predates_github", None))
        }
        Err(e) => return Err(CliError::from_api(&e, None)),
    };
    if connection.connected {
        emit_github_connection(ctx, &connection);
        return Ok(EXIT_OK);
    }

    // The link and the waiting go to stderr, the way the device-flow prompt
    // does: `--json` keeps ONE machine-readable line on stdout, and the link
    // is not a secret, so it is printed even under `-q`.
    eprintln!("Connect GitHub: {CONNECT_GITHUB_URL}");
    if crate::cli_auth::open_browser(CONNECT_GITHUB_URL) {
        eprintln!("  Opened it in your browser.");
    }
    eprintln!("Waiting for GitHub…");
    let started = now_ms();
    let connection =
        poll_for_github(started, started.saturating_add(CONNECT_DEADLINE_MS), ask).await?;
    emit_github_connection(ctx, &connection);
    Ok(EXIT_OK)
}

/// Ask until the answer is `connected`, the deadline passes, or the fleet says
/// something that waiting cannot fix.
///
/// The pacing is the device-flow shape (`cli_auth`): a fixed interval, longer
/// after a poll that could not be answered, and a deadline that a slow answer
/// does not extend. `ask` is a parameter rather than a client so this is
/// testable without a fleet — the loop is the part with the bugs in it.
async fn poll_for_github<F, Fut>(
    started_ms: u64,
    deadline_ms: u64,
    ask: F,
) -> Result<api::GithubConnection, CliError>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Result<api::GithubConnection, api::ApiError>>,
{
    let mut interval_ms = CONNECT_POLL_MS;
    loop {
        tokio::time::sleep(std::time::Duration::from_millis(interval_ms + jitter_ms())).await;
        match ask().await {
            Ok(connection) if connection.connected => return Ok(connection),
            // Answered, just not yet: back to the ordinary interval, whatever
            // the last failure had stretched it to.
            Ok(_) => interval_ms = CONNECT_POLL_MS,
            Err(e) if worth_waiting_out(&e) => {
                interval_ms = interval_ms.saturating_mul(2).min(CONNECT_POLL_MAX_MS);
            }
            Err(e) => return Err(CliError::from_api(&e, None)),
        }
        let now = now_ms();
        if now >= deadline_ms {
            let waited = json!({ "waited_s": now.saturating_sub(started_ms) / 1_000 });
            return Err(CliError::from_body("github_connect_timeout", &waited, None));
        }
    }
}

/// Is this a reason to keep waiting, or an answer?
///
/// A wait that is watching for something to HAPPEN treats a dropped connection
/// and a control plane that is restarting as noise. A refusal the fleet meant
/// — a credential it will not accept, a route it does not have — is an answer,
/// and polling over it for ten minutes is how somebody waits out a typo.
fn worth_waiting_out(err: &api::ApiError) -> bool {
    match err {
        api::ApiError::Transport(_) | api::ApiError::Deadline => true,
        api::ApiError::Api { status, .. } => *status >= 500,
        api::ApiError::Shape(_) => false,
    }
}

/// What `connect github` prints once it has an answer.
fn emit_github_connection(ctx: &Ctx, connection: &api::GithubConnection) {
    let rows: Vec<Value> = connection
        .installations
        .iter()
        .map(|i| {
            json!({
                "installation_id": i.installation_id,
                "account_login": i.account_login,
                "account_type": i.account_type,
                "state": i.state,
                "repository_selection": i.repository_selection,
                "granted_at_ms": i.granted_at_ms,
            })
        })
        .collect();
    let mut human = vec![if connection.connected {
        "GitHub is connected.".to_owned()
    } else {
        "GitHub is not connected.".to_owned()
    }];
    human.extend(connection.installations.iter().map(github_coverage_line));
    // Coverage grows one GitHub account at a time, and the only way to add one
    // is to install the App again — so the link is worth saying even on the
    // success path, where a person is looking at a list that is missing an org.
    if let Some(url) = &connection.install_url {
        human.push(format!("  add another GitHub account at {url}"));
    }
    ctx.emit(
        json!({
            "connected": connection.connected,
            "install_url": connection.install_url,
            "installations": rows,
        }),
        &human,
    );
}

/// One line per GitHub account, saying what it reaches — or why it does not.
///
/// A non-live installation is LISTED rather than hidden: "suspended" is the
/// answer to "why can it not see my repositories", and a list that silently
/// dropped it would send somebody to reinstall an App that is already there.
fn github_coverage_line(i: &api::GithubInstallation) -> String {
    // A pending installation is recorded before the webhook that names it
    // arrives, so it has no login yet. The id is public and is what GitHub's
    // own settings page shows.
    let who = if i.account_login.is_empty() {
        format!("installation {}", i.installation_id)
    } else {
        i.account_login.clone()
    };
    let reaches = match (i.state.as_str(), i.repository_selection.as_str()) {
        ("live", "all") => "every repository".to_owned(),
        ("live", "selected") => "the repositories you picked".to_owned(),
        // A state or a selection this CLI has not heard of is printed as the
        // server said it (I13), not flattened into "unknown".
        ("live", other) => other.to_owned(),
        (state, _) => state.to_owned(),
    };
    format!("  {who} — {reaches}")
}

// ---------------------------------------------------------------------------
// The v0.1.0 tree
// ---------------------------------------------------------------------------

async fn run_ws(ctx: &Ctx, cmd: WsCommand) -> Result<i32, CliError> {
    match cmd {
        WsCommand::Create {
            name,
            user,
            principal,
            idp_assertion,
        } => {
            create(
                ctx,
                name,
                // The v0.1.0 spelling never grew a `--repo`, and it is not
                // going to: it is kept working, not extended.
                None,
                Some(Claimed {
                    user,
                    principal,
                    idp_assertion,
                }),
            )
            .await
        }
        WsCommand::List {
            user,
            principal,
            idp_assertion,
        } => {
            list(
                ctx,
                Some(StateFilter::All),
                Some(Claimed {
                    user,
                    principal,
                    idp_assertion,
                }),
            )
            .await
        }
        WsCommand::Attach { id } => attach_lease(ctx, &id).await,
        WsCommand::Exec {
            id,
            cwd,
            env,
            stdin,
            argv,
        } => {
            run_command(
                ctx,
                RunSpec {
                    workspace: id,
                    shell: None,
                    cwd,
                    env,
                    stdin,
                    argv,
                },
            )
            .await
        }
        WsCommand::Fork { id, snapshot, name } => fork(ctx, id, 1, snapshot, name).await,
        WsCommand::Rewind {
            id,
            snapshot,
            preserved_name,
        } => {
            let biscuit = ctx.biscuit(&id).await?;
            let rewound = ctx
                .client()
                .rewind(&id, &biscuit, &snapshot, preserved_name.as_deref())
                .await
                .map_err(|e| CliError::from_api(&e, Some(&id)))?;
            ctx.emit(
                json!({
                    "id": id,
                    "head": { "snapshot": rewound.head_snapshot },
                    "preserved_fork": { "workspace": rewound.preserved_fork, "name": rewound.preserved_fork_name },
                }),
                &[
                    format!("{id} now resumes from {}.", rewound.head_snapshot),
                    format!(
                        "  the forward history is preserved as {} ({}).",
                        rewound.preserved_fork, rewound.preserved_fork_name
                    ),
                ],
            );
            Ok(EXIT_OK)
        }
        WsCommand::Release {
            id,
            fencing_token,
            discard,
        } => {
            let workspace = ctx.workspace(id)?;
            let held = ctx.authority(&workspace).await?;
            let fencing_token = match fencing_token {
                Some(t) => t,
                None => resolve_fencing_token(ctx, &workspace, &held).await?,
            };
            let released = ctx
                .client()
                .release(&workspace, held.auth(), fencing_token, discard)
                .await
                .map_err(|e| CliError::from_api(&e, Some(&workspace)))?;
            let human = if released.released {
                format!("{workspace} stopped; everything since the last save is gone.")
            } else {
                format!("{workspace} is saving disk, then it stops.")
            };
            ctx.emit(
                json!({
                    "id": workspace,
                    "released": released.released,
                    "sealing": released.sealing,
                }),
                &[human],
            );
            Ok(EXIT_OK)
        }
        WsCommand::Lineage { id } => {
            let workspace = ctx.workspace(id)?;
            let held = ctx.authority(&workspace).await?;
            let lineage = ctx
                .client()
                .lineage(&workspace, held.auth())
                .await
                .map_err(|e| CliError::from_api(&e, Some(&workspace)))?;
            let head_id = lineage.head.as_ref().map(|h| h.id.clone());
            let mut human = vec![format!("workspace={workspace}")];
            match &lineage.head {
                Some(head) => human.push(format!(
                    "  resumes from: {} (log_seq={})",
                    head.id, head.log_seq
                )),
                None => {
                    human.push("  resumes from: nothing (never saved — a fresh boot)".to_owned())
                }
            }
            for s in &lineage.snapshots {
                human.push(format!(
                    "    {}  log_seq={} sealed_at_ms={}{}",
                    s.id,
                    s.log_seq,
                    s.sealed_at_ms,
                    if Some(&s.id) == head_id.as_ref() {
                        "  <- head"
                    } else {
                        ""
                    }
                ));
            }
            if !lineage.forks.is_empty() {
                human.push(format!("  forks: {}", lineage.forks.join(" ")));
            }
            ctx.emit(
                json!({
                    "id": workspace,
                    "head": lineage.head.as_ref().map(|h| json!({ "snapshot": h.id })),
                    "snapshots": lineage.snapshots.iter().map(|s| json!({
                        "snapshot": s.id, "sealed_at": render::time(s.sealed_at_ms),
                    })).collect::<Vec<_>>(),
                    "forks": lineage.forks,
                }),
                &human,
            );
            Ok(EXIT_OK)
        }
        WsCommand::Archive { id } => archive(ctx, id).await,
        WsCommand::Token {
            id,
            user,
            principal,
            idp_assertion,
        } => {
            let (user, identity) = user_identity(
                ctx,
                Some(Claimed {
                    user,
                    principal,
                    idp_assertion,
                }),
            )
            .await?;
            let (biscuit, expires_at_ms) = ctx
                .client()
                .workspace_token(&id, &user, &identity)
                .await
                .map_err(|e| CliError::from_api(&e, Some(&id)))?;
            ctx.remember(&id, &biscuit, Some(expires_at_ms))?;
            ctx.emit(
                json!({ "id": id, "expires_at": render::time(expires_at_ms) }),
                &[format!(
                    "{id}: access refreshed, valid until {}.",
                    render::rfc3339(expires_at_ms)
                )],
            );
            Ok(EXIT_OK)
        }
    }
}

/// The fencing token a v0.1.0 `ws release` needs: the saved one, else the one
/// the state route reports to a caller authorized to write.
async fn resolve_fencing_token(ctx: &Ctx, workspace: &str, held: &Held) -> Result<u64, CliError> {
    if let Some(token) = state::load_workspace(&ctx.paths, workspace)?.fencing_token {
        return Ok(token);
    }
    let status = read_status(ctx, workspace, held).await?;
    status
        .lease
        .as_ref()
        .and_then(|l| l.fencing_token)
        .ok_or_else(|| CliError::from_code("no_active_lease", Some(workspace)))
}

/// `ws attach`: place the lease, then say where it landed.
async fn attach_lease(ctx: &Ctx, workspace: &str) -> Result<i32, CliError> {
    let presented = ctx.biscuit(workspace).await?;
    let attach = ctx
        .client()
        .attach(workspace, &presented)
        .await
        .map_err(|e| CliError::from_api(&e, Some(workspace)))?;
    ctx.remember(workspace, &attach.biscuit_b64, None)?;
    let mut cache = state::load_workspace(&ctx.paths, workspace)?;
    cache.node = Some(attach.node.clone());
    cache.fencing_token = Some(attach.fencing_token);
    state::save_workspace(&ctx.paths, workspace, &cache)?;
    ctx.emit(
        json!({
            "id": workspace,
            "lease": { "node": attach.node, "expires_at": render::time(attach.expires_at_ms) },
        }),
        &[
            format!("attached: workspace={workspace}"),
            format!("  node:          {}", attach.node),
            format!("  fencing_token: {}", attach.fencing_token),
        ],
    );
    Ok(EXIT_OK)
}

struct AttachSpec {
    workspace: Option<String>,
    pty: u32,
    new: bool,
    list: bool,
    no_place: bool,
    linger_ms: u64,
    no_raw: bool,
    wait_for_node_ms: u64,
}

async fn attach_command(ctx: &Ctx, spec: AttachSpec) -> Result<i32, CliError> {
    let workspace = ctx.workspace(spec.workspace)?;
    if !spec.no_place {
        attach_lease(ctx, &workspace).await?;
    }
    let token = BASE64
        .decode(ctx.biscuit(&workspace).await?.trim())
        .map_err(|_| CliError::from_code("bad_token_encoding", Some(&workspace)))?;
    let options = crate::attach::AttachOptions {
        pty: spec.pty,
        open_new: spec.new,
        trust: ctx.trust.clone(),
        linger: std::time::Duration::from_millis(spec.linger_ms),
        no_raw: spec.no_raw,
        wait_for_node: std::time::Duration::from_millis(spec.wait_for_node_ms),
    };
    if spec.list {
        let roster = crate::attach::list_ptys(&ctx.hub, &workspace, &token, &options).await?;
        match roster.as_slice() {
            [] => println!("no live PTYs (the guest reported an empty roster)"),
            ptys => {
                for p in ptys {
                    println!("pty {p}");
                }
            }
        }
        return Ok(EXIT_OK);
    }
    let summary = crate::attach::attach(&ctx.hub, &workspace, &token, &options).await?;
    // stderr, so a scripted run can pipe the workspace's own output on stdout
    // without this getting mixed in.
    eprintln!(
        "detached: {} byte(s) sent, {} byte(s) received in {} ms; durable through seq={}",
        summary.bytes_sent, summary.bytes_received, summary.duration_ms, summary.durable_through,
    );
    Ok(EXIT_OK)
}

async fn tail_command(ctx: &Ctx, workspace: Option<String>) -> Result<i32, CliError> {
    let workspace = ctx.workspace(workspace)?;
    let token = BASE64
        .decode(ctx.biscuit(&workspace).await?.trim())
        .map_err(|_| CliError::from_code("bad_token_encoding", Some(&workspace)))?;
    let mut session = TailSession::connect_with(
        &ctx.hub,
        &workspace,
        &token,
        TailOptions {
            trust: ctx.trust.clone(),
            since: None,
        },
    )
    .await?;
    eprintln!(
        "tailing {workspace} (protocol v{}, hub incarnation {}, durable watermarks {}; ctrl-c to stop)",
        session.version(),
        session.incarnation().unwrap_or("<unreported>"),
        if session.watermarks() { "on" } else { "off" },
    );
    loop {
        tokio::select! {
            item = session.next_item() => match item? {
                Some(TailItem::Event(ev)) => println!("{ev}"),
                Some(TailItem::DurableThrough(seq)) => {
                    println!("-- durable through seq={seq} (everything at or below this survives a hub crash) --");
                }
                None => {
                    eprintln!("hub closed the stream");
                    return Ok(EXIT_OK);
                }
            },
            _ = tokio::signal::ctrl_c() => return Ok(EXIT_OK),
        }
    }
}

// `share()` lived here (ADR-0075). It posted `POST /v1/grants` and then
// printed the same narrowing recomputed offline with `authz::attenuate`,
// presenting the two as equivalent ways to hand a workspace to someone. They
// were never equivalent: an appended block cannot rebind `principal`, so the
// offline half handed out the OWNER's own authority — a bearer credential the
// server never saw, attributed to the wrong person, and cuttable by nothing.
// `Client::grant` stays (`bins/reach/tests/no_privileged_interface.rs` proves
// I6 through it), and the server surface it calls is unchanged.

async fn credits(ctx: &Ctx) -> Result<i32, CliError> {
    let identity = ctx.identity().await?;
    let balance = ctx
        .client()
        .credit_balance(&identity.user_id, &identity.identity_token)
        .await
        .map_err(|e| CliError::from_api(&e, None))?;
    let credits = format!(
        "{}.{:03}",
        balance.balance_millicredits / 1_000,
        balance.balance_millicredits % 1_000
    );
    ctx.emit(
        json!({ "balance": credits, "unit": balance.unit }),
        &[
            format!("{credits} compute credits"),
            "1 credit = 1 active standard-workspace minute".to_owned(),
        ],
    );
    Ok(EXIT_OK)
}

fn print_inspection(i: &crate::inspect::Inspection) {
    let show = |v: &Option<String>| v.clone().unwrap_or_else(|| "<absent>".to_owned());
    println!("token facts (offline print — parsed, NOT verified):");
    println!("  principal: {}", show(&i.principal));
    println!("  workspace: {}", show(&i.workspace));
    println!("  role:      {}", show(&i.role));
    match i.exp_ms {
        Some(ms) => println!("  exp:       {ms} (ms since epoch)"),
        None => println!("  exp:       <absent>"),
    }
    println!("  attenuation blocks: {}", i.attenuation_blocks);
    for (n, source) in i.block_sources.iter().enumerate().skip(1) {
        println!("  block {n} (checks only — §7.2 narrowing):");
        for line in source.lines().filter(|l| !l.trim().is_empty()) {
            println!("    {line}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_shell_line_is_wrapped_and_an_argv_is_not() {
        assert_eq!(
            resolve_argv("ws-1", Some("cd /repo && make".to_owned()), Vec::new()).unwrap(),
            vec!["sh", "-lc", "cd /repo && make"]
        );
        assert_eq!(
            resolve_argv("ws-1", None, vec!["cargo".into(), "test".into()]).unwrap(),
            vec!["cargo", "test"]
        );
        // One argument that is not a program: refused, naming BOTH corrected
        // forms rather than guessing which was meant.
        let err = resolve_argv("ws-1", None, vec!["echo hi".into()]).unwrap_err();
        assert_eq!(err.exit_code, EXIT_USAGE);
        assert!(
            err.message.contains("reachpad run ws-1 --"),
            "{}",
            err.message
        );
        assert!(err.message.contains("-s \"echo hi\""), "{}", err.message);
        // A single program with no arguments is a program.
        assert_eq!(
            resolve_argv("ws-1", None, vec!["/bin/true".into()]).unwrap(),
            vec!["/bin/true"]
        );
        // Nothing at all names both forms too.
        let err = resolve_argv("ws-1", None, Vec::new()).unwrap_err();
        assert!(err.message.contains("-s"), "{}", err.message);
        // Both spellings at once is a question nobody should have to answer.
        assert!(resolve_argv("ws-1", Some("x".into()), vec!["y".into()]).is_err());
    }

    /// A wait must outlast the thing it waits for: a workspace still sealing
    /// gets the server's own bound, not the user's ten minutes.
    #[test]
    fn a_save_in_progress_outranks_the_users_timeout() {
        let started = 1_000_000;
        assert_eq!(wait_deadline(started, 1_000, "running"), started + 1_000);
        let sealing = wait_deadline(started, 1_000, "sealing");
        assert_eq!(
            sealing,
            started + SEAL_BUDGET_MS + LEASE_TTL_MS + SEAL_MARGIN_MS
        );
        assert!(sealing > started + 600_000, "shorter than the seal budget");
        // A longer timeout is still honored: the extension is a floor.
        assert_eq!(
            wait_deadline(started, 3_600_000, "sealing"),
            started + 3_600_000
        );
    }

    /// The two timeouts say different things, because they mean different
    /// things: one workspace is working, the other is not.
    #[test]
    fn the_two_wait_refusals_are_told_apart() {
        let sealing =
            CliError::from_body("still_sealing", &json!({ "waited_s": 700 }), Some("ws-1"));
        assert!(
            sealing.message.contains("still saving"),
            "{}",
            sealing.message
        );
        assert!(sealing.message.contains("700s"), "{}", sealing.message);
        let gave_up = CliError::from_body(
            "wait_timeout",
            &json!({ "waited_s": 10, "state": "running", "target": "paused" }),
            Some("ws-1"),
        );
        assert!(gave_up.message.contains("Gave up"), "{}", gave_up.message);
        assert!(
            gave_up.message.contains("not paused"),
            "{}",
            gave_up.message
        );
        assert_eq!(sealing.exit_code, errors::EXIT_UNAVAILABLE);
        assert_eq!(gave_up.exit_code, errors::EXIT_UNAVAILABLE);
    }

    /// The safety property of first-run onboarding, stated exactly: a BROWSER
    /// SIGN-IN is the side effect nobody typed, so only a terminal may trigger
    /// one. It is not a rule about the command as a whole — a listing needs no
    /// terminal, and refusing one to a signed-in pipe was the bug.
    #[test]
    fn only_a_terminal_ever_starts_a_browser_sign_in() {
        assert_eq!(
            onboarding_action(false, false),
            Onboarding::RefuseNoCredential,
            "a pipe with no credential must not open a browser; it is told how \
             to sign in without one"
        );
        assert_eq!(onboarding_action(true, false), Onboarding::SignInThenList);
    }

    /// Signed in, a bare `reachpad` lists — terminal or not. This is the
    /// command the installer's final line names, and an agent, a CI step and a
    /// `reachpad | tee` all reach it without a tty.
    #[test]
    fn a_signed_in_bare_reachpad_lists_with_or_without_a_terminal() {
        assert_eq!(onboarding_action(true, true), Onboarding::List);
        assert_eq!(onboarding_action(false, true), Onboarding::List);
    }

    /// A bare invocation is rendered as a listing, so `reachpad --json` on a
    /// signed-in terminal emits the same envelope `reachpad list --json` does
    /// rather than a second, undocumented shape.
    #[test]
    fn onboarding_reports_itself_as_the_list_command() {
        assert_eq!(
            command_name(&Command::List { state: None }),
            "workspace.list"
        );
    }

    fn connection(connected: bool) -> api::GithubConnection {
        api::GithubConnection {
            connected,
            install_url: None,
            installations: if connected {
                vec![api::GithubInstallation {
                    installation_id: 7,
                    account_login: "acme".to_owned(),
                    account_type: "org".to_owned(),
                    state: "live".to_owned(),
                    repository_selection: "all".to_owned(),
                    granted_at_ms: 1_000,
                }]
            } else {
                Vec::new()
            },
        }
    }

    /// The wait ends when the browser half finishes, not before: a `connected:
    /// false` answer is an answer, and the loop asks again rather than
    /// reporting it as the outcome.
    #[tokio::test(start_paused = true)]
    async fn the_connect_wait_ends_when_github_says_connected() {
        let asked = std::sync::atomic::AtomicUsize::new(0);
        let asked = &asked;
        let now = now_ms();
        let got = poll_for_github(now, now + CONNECT_DEADLINE_MS, move || async move {
            let n = asked.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(connection(n >= 2))
        })
        .await
        .expect("the third answer connects");
        assert!(got.connected);
        assert_eq!(asked.load(std::sync::atomic::Ordering::SeqCst), 3);
    }

    /// A poll that could not be answered is not an answer. The browser half
    /// may be finishing at that exact moment, so a hiccup on one request must
    /// not make somebody start the ceremony over — the wait backs off and
    /// keeps waiting.
    #[tokio::test(start_paused = true)]
    async fn a_transient_failure_extends_the_wait_instead_of_ending_it() {
        let asked = std::sync::atomic::AtomicUsize::new(0);
        let asked = &asked;
        let started = tokio::time::Instant::now();
        let now = now_ms();
        let got = poll_for_github(now, now + CONNECT_DEADLINE_MS, move || async move {
            match asked.fetch_add(1, std::sync::atomic::Ordering::SeqCst) {
                0 => Err(api::ApiError::Transport("connection reset".to_owned())),
                1 => Err(api::ApiError::Api {
                    status: 503,
                    code: "control_upstream_unavailable".to_owned(),
                    detail: None,
                    body: json!({}),
                }),
                _ => Ok(connection(true)),
            }
        })
        .await
        .expect("a hiccup is not an outcome");
        assert!(got.connected);
        // 3s, then 6s, then 12s: each failure lengthens the next pause, so a
        // fleet that is restarting is not also being hammered.
        let waited = started.elapsed();
        assert!(
            waited >= std::time::Duration::from_secs(21),
            "backed off too little: {waited:?}"
        );
    }

    /// A refusal the fleet MEANT ends the wait immediately. Polling over a
    /// credential the fleet will not accept is how somebody waits out a typo
    /// for ten minutes and learns nothing.
    #[tokio::test(start_paused = true)]
    async fn a_refusal_the_fleet_meant_is_not_waited_out() {
        let asked = std::sync::atomic::AtomicUsize::new(0);
        let asked = &asked;
        let now = now_ms();
        let err = poll_for_github(now, now + CONNECT_DEADLINE_MS, move || async move {
            asked.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(api::ApiError::Api {
                status: 401,
                code: "operator_token_expired".to_owned(),
                detail: None,
                body: json!({}),
            })
        })
        .await
        .expect_err("an expired credential is an answer");
        assert_eq!(err.code, "operator_token_expired");
        assert_eq!(err.exit_code, errors::EXIT_CREDENTIAL);
        assert_eq!(asked.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    /// The deadline is the client's own, and what it produces is a sentence
    /// about waiting — not a claim that GitHub or the fleet failed.
    #[tokio::test(start_paused = true)]
    async fn the_connect_wait_gives_up_on_its_own_deadline() {
        let now = now_ms();
        let err = poll_for_github(now, now, || async { Ok(connection(false)) })
            .await
            .expect_err("a deadline already past ends the first pass");
        assert_eq!(err.code, "github_connect_timeout");
        assert_eq!(err.exit_code, errors::EXIT_UNAVAILABLE);
        assert!(err.retriable);
        assert!(err.message.contains("Gave up waiting"), "{}", err.message);
    }

    /// A non-live installation is LISTED, not hidden: "suspended" is the
    /// answer to "why can it not see my repositories", and dropping the row
    /// would send somebody to reinstall an App that is already there.
    #[test]
    fn coverage_lines_name_what_each_account_reaches_or_why_it_does_not() {
        let mut i = api::GithubInstallation {
            installation_id: 42,
            account_login: "acme".to_owned(),
            account_type: "org".to_owned(),
            state: "live".to_owned(),
            repository_selection: "all".to_owned(),
            granted_at_ms: 0,
        };
        assert_eq!(github_coverage_line(&i), "  acme — every repository");
        i.repository_selection = "selected".to_owned();
        assert_eq!(
            github_coverage_line(&i),
            "  acme — the repositories you picked"
        );
        i.state = "suspended".to_owned();
        assert_eq!(github_coverage_line(&i), "  acme — suspended");
        // A grant recorded before the webhook that names it: the id is public
        // and is what GitHub's own settings page shows.
        i.state = "pending".to_owned();
        i.account_login = String::new();
        assert_eq!(github_coverage_line(&i), "  installation 42 — pending");
    }
}
