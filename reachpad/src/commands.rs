//! Command dispatch. All wall-clock reads and printing live here, at the
//! outermost shell layer (I12 discipline even in a CLI).

use anyhow::Context;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use clap::CommandFactory as _;
use clap::Parser as _;
use std::io::IsTerminal as _;

use crate::api::Client;
use crate::attach;
use crate::cli::{Cli, Command, TokenCommand, WsCommand};
use crate::inspect;
use crate::tail::{TailItem, TailOptions, TailSession};
use crate::tokenfile;
use crate::SPEC;

/// Entry point for `main`: returns the process exit code.
///
/// `--check-config` is handled by `runtime::run_startup` before clap sees
/// the argv (§15: every binary supports it; reach's Spec is empty — a pure
/// client holds no platform secrets, so the check trivially passes).
pub async fn run(argv: Vec<String>) -> anyhow::Result<i32> {
    let cfg = match runtime::run_startup(&SPEC, argv.iter())? {
        runtime::Startup::CheckConfigDone { ok } => return Ok(i32::from(!ok)),
        runtime::Startup::Run(cfg) => cfg,
    };

    let mut cli = match Cli::try_parse_from(&argv) {
        Ok(cli) => cli,
        Err(e) => {
            // --help/--version exit 0; usage errors exit 2. clap renders.
            let code = if e.use_stderr() { 2 } else { 0 };
            e.print().context("rendering clap output")?;
            return Ok(code);
        }
    };
    // ADR-0040: `--endpoint <host>` is both planes on one host and one port.
    cli.resolve_endpoint();

    // A successful WorkOS CLI login stores the authenticated endpoint pair.
    // Explicit command-line configuration always wins; saved configuration is
    // only the missing default that makes the next `reachpad ws list` work.
    let token_path = cli.token_path();
    if cli.endpoint.is_none() {
        match tokenfile::read_connection_config(&token_path) {
            Ok(Some(saved)) => {
                crate::cli_auth::validate_connection_urls(&saved.controld, &saved.hub)
                    .context("saved Reachpad connection configuration is unsafe")?;
                if cli.controld == crate::cli::DEFAULT_CONTROLD {
                    cli.controld = saved.controld;
                }
                if cli.hub == crate::cli::DEFAULT_HUB {
                    cli.hub = saved.hub;
                }
            }
            Ok(None) => {}
            Err(_) if matches!(cli.command.as_ref(), Some(Command::Doctor)) => {
                // Doctor reports the malformed file by name. Letting the
                // ordinary startup path fail here would make the diagnostic
                // command unable to diagnose the state it exists for.
            }
            Err(error) => return Err(error),
        }
    }

    tracing::info!(mode = cfg.mode().as_str(), "reachpad ready");

    let Some(command) = cli.command.take() else {
        let interactive = std::io::stdin().is_terminal() && std::io::stderr().is_terminal();
        return run_onboarding(&cli, token_path, interactive).await;
    };

    match command {
        Command::Doctor => {
            return crate::doctor::run(&cli.controld, &cli.hub, cli.trust(), &cli.token_path())
                .await;
        }
        Command::Update => return crate::self_update::run(),
        Command::Completions { shell } => {
            let generator = match shell {
                crate::cli::CompletionShell::Bash => clap_complete::Shell::Bash,
                crate::cli::CompletionShell::Zsh => clap_complete::Shell::Zsh,
                crate::cli::CompletionShell::Fish => clap_complete::Shell::Fish,
            };
            let mut stdout = std::io::stdout();
            clap_complete::generate(generator, &mut Cli::command(), "reachpad", &mut stdout);
        }
        Command::Credits => {
            let credential = tokenfile::read_operator_token(&cli.token_path())?;
            let client = Client::with_trust(&cli.controld, cli.trust());
            let session = client.operator_session(&credential).await?;
            let balance = client
                .credit_balance(&session.user_id, &session.identity_token)
                .await?;
            let whole = balance.balance_millicredits / 1000;
            let fraction = balance.balance_millicredits % 1000;
            println!("{whole}.{fraction:03} compute credits");
            println!("1 credit = 1 active standard-workspace minute");
            if balance.balance_millicredits <= 50_000 {
                eprintln!("reachpad: low compute-credit balance");
            } else if balance.balance_millicredits <= 200_000 {
                eprintln!("reachpad: compute-credit balance is below 200");
            }
        }
        Command::Ws(ws) => {
            // `ws exec` exits with the COMMAND's exit code so it composes in
            // a script; every other `ws` verb returns 0. The code travels as a
            // return value rather than a `process::exit` so the normal
            // teardown still runs.
            return run_ws(&cli.controld, cli.trust(), cli.token_path(), ws).await;
        }
        Command::Share {
            workspace,
            role,
            expires_in,
            grantee,
        } => {
            let token_b64 = resolve_token(&cli)?;
            let expires_at_ms = wall_now_ms().saturating_add(expires_in);
            run_share(
                &cli.controld,
                cli.trust(),
                &token_b64,
                &workspace,
                role,
                expires_at_ms,
                &grantee,
            )
            .await?;
        }
        Command::Tail { workspace } => {
            let token_b64 = resolve_token(&cli)?;
            let token = BASE64
                .decode(token_b64.trim())
                .context("token is not valid base64")?;
            let options = TailOptions { trust: cli.trust() };
            run_tail_command(&cli.hub, &workspace, &token, options).await?;
        }
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
            let token_path = cli.token_path();
            // §8 flow 3: placement first (lease + fencing token), then the
            // hub session. `--no-place` re-attaches to a workspace whose
            // lease is already held — the VM keeps running across detaches.
            if !no_place {
                let presented = tokenfile::read_token(&token_path)?;
                let client = Client::with_trust(&cli.controld, cli.trust());
                let placed = client.attach(&workspace, &presented).await?;
                tokenfile::write_token(&token_path, &placed.biscuit_b64)?;
                tokenfile::save_attach_state(
                    &token_path,
                    &workspace,
                    tokenfile::AttachState {
                        node: placed.node.clone(),
                        fencing_token: placed.fencing_token,
                        principal: String::new(),
                    },
                )?;
                eprintln!(
                    "placed: workspace={workspace} node={} fencing_token={}",
                    placed.node, placed.fencing_token
                );
                if let Some(millicredits) = placed.credits_remaining_millicredits {
                    eprintln!(
                        "compute credits remaining: {}.{:03}",
                        millicredits / 1000,
                        millicredits % 1000
                    );
                }
            }
            let token_b64 = resolve_token(&cli)?;
            let token = BASE64
                .decode(token_b64.trim())
                .context("token is not valid base64")?;
            let options = attach::AttachOptions {
                pty,
                open_new: new,
                trust: cli.trust(),
                linger: std::time::Duration::from_millis(linger_ms),
                no_raw,
                wait_for_node: std::time::Duration::from_millis(wait_for_node_ms),
            };
            if list {
                let roster = attach::list_ptys(&cli.hub, &workspace, &token, &options).await?;
                match roster.as_slice() {
                    [] => println!("no live PTYs (the guest reported an empty roster)"),
                    ptys => {
                        for p in ptys {
                            println!("pty {p}");
                        }
                    }
                }
                return Ok(0);
            }
            let summary = attach::attach(&cli.hub, &workspace, &token, &options).await?;
            // stderr, so a scripted run can pipe the workspace's own output
            // on stdout without this getting mixed in.
            eprintln!(
                "detached: {} byte(s) sent, {} byte(s) received in {} ms; \
                 durable through seq={} (everything at or below that is in the store)",
                summary.bytes_sent,
                summary.bytes_received,
                summary.duration_ms,
                summary.durable_through,
            );
        }
        Command::Auth(auth) => {
            run_auth(&cli.controld, &cli.hub, cli.trust(), cli.token_path(), auth).await?;
        }
        Command::Key(key) => {
            run_key(&cli.controld, cli.trust(), cli.token_path(), key).await?;
        }
        Command::Token(TokenCommand::Inspect) => {
            let token_b64 = resolve_token(&cli)?;
            print_inspection(&inspect::inspect_b64(&token_b64)?);
        }
    }
    Ok(0)
}

#[derive(Debug, PartialEq, Eq)]
enum OnboardingAction {
    RefuseNonInteractive,
    SignInThenList,
    List,
}

fn onboarding_action(interactive: bool, operator_token_exists: bool) -> OnboardingAction {
    match (interactive, operator_token_exists) {
        (false, _) => OnboardingAction::RefuseNonInteractive,
        (true, false) => OnboardingAction::SignInThenList,
        (true, true) => OnboardingAction::List,
    }
}

async fn run_onboarding(
    cli: &Cli,
    token_path: std::path::PathBuf,
    interactive: bool,
) -> anyhow::Result<i32> {
    let action = onboarding_action(interactive, tokenfile::operator_token_exists(&token_path)?);
    if action == OnboardingAction::RefuseNonInteractive {
        anyhow::bail!("no command given (try `reachpad --help`)");
    }

    let mut controld = cli.controld.clone();
    if action == OnboardingAction::SignInThenList {
        eprintln!("No saved Reachpad sign-in was found. Starting browser sign-in.");
        run_auth(
            &controld,
            &cli.hub,
            cli.trust(),
            token_path.clone(),
            crate::cli::AuthCommand::Login {
                operator_token: None,
                account_url: crate::cli_auth::DEFAULT_ACCOUNT_URL.to_owned(),
                no_browser: false,
            },
        )
        .await?;

        let saved = tokenfile::read_connection_config(&token_path)?
            .context("browser sign-in did not save the Reachpad endpoints")?;
        crate::cli_auth::validate_connection_urls(&saved.controld, &saved.hub)
            .context("browser sign-in saved unsafe Reachpad endpoints")?;
        controld = saved.controld;
    }

    println!();
    println!("Your workspaces:");
    run_ws(
        &controld,
        cli.trust(),
        token_path,
        WsCommand::List {
            user: None,
            principal: "dev-principal".to_owned(),
            idp_assertion: None,
        },
    )
    .await?;
    println!();
    println!("Next commands:");
    println!("  Create a workspace: reachpad ws create --name <name>");
    println!("  Open a workspace:   reachpad ws token <workspace-id>");
    println!("                      reachpad attach <workspace-id>");
    Ok(0)
}

impl Cli {
    fn token_path(&self) -> std::path::PathBuf {
        self.token_file
            .clone()
            .unwrap_or_else(tokenfile::default_token_path)
    }
}

/// The user's Biscuit: `--token` wins, else the token file.
fn resolve_token(cli: &Cli) -> anyhow::Result<String> {
    if let Some(token) = &cli.token {
        return Ok(token.trim().to_owned());
    }
    let path = cli.token_path();
    tokenfile::read_token(&path).with_context(|| {
        format!(
            "no --token given and no token at {} (run `reachpad ws attach <id>` first)",
            path.display()
        )
    })
}

/// Wall clock, read at the shell layer only (I12).
fn wall_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// `reachpad auth …` — the operator-credential half of ADR-0034.
async fn run_auth(
    controld: &str,
    hub: &str,
    trust: crate::transport::TlsTrust,
    token_path: std::path::PathBuf,
    cmd: crate::cli::AuthCommand,
) -> anyhow::Result<()> {
    use crate::cli::AuthCommand;
    let client = Client::with_trust(controld, trust.clone());
    match cmd {
        AuthCommand::Login {
            operator_token,
            account_url,
            no_browser,
        } => {
            if let Some(operator_token) = operator_token {
                let credential = if operator_token.trim() == "-" {
                    let mut buf = String::new();
                    std::io::Read::read_to_string(&mut std::io::stdin(), &mut buf)
                        .context("reading the operator credential from stdin")?;
                    buf
                } else {
                    operator_token
                };
                let credential = credential.trim().to_owned();
                // Exchange BEFORE saving: a credential that does not work is
                // not one worth keeping on disk, and the failure names why.
                let session = client.operator_session(&credential).await?;
                crate::cli_auth::validate_connection_urls(controld, hub)
                    .context("refusing to save unsafe Reachpad endpoints")?;
                tokenfile::write_operator_token(&token_path, &credential)?;
                tokenfile::write_connection_config(
                    &token_path,
                    &tokenfile::ConnectionConfig {
                        controld: controld.to_owned(),
                        hub: hub.to_owned(),
                    },
                )?;
                println!(
                    "logged in: user={} principal={}",
                    session.user_id, session.principal_id
                );
                println!(
                    "  operator credential saved: {} (0600)",
                    tokenfile::operator_path(&token_path).display()
                );
                println!(
                    "  endpoints saved: {} (0600)",
                    tokenfile::connection_path(&token_path).display()
                );
                println!(
                    "  identity token valid until {} (ms since epoch); renew with `reachpad auth session`",
                    session.expires_at_ms
                );
                return Ok(());
            }

            let device = crate::cli_auth::start_device_authorization(&account_url, &trust).await?;
            println!("Open {}", device.verification_uri);
            println!("Enter code: {}", device.user_code);
            if !no_browser && crate::cli_auth::open_browser(&device.verification_uri_complete) {
                eprintln!("Opened WorkOS sign-in in your browser.");
            }
            eprintln!("Waiting for WorkOS approval...");
            let login =
                crate::cli_auth::complete_device_authorization(&account_url, device, &trust)
                    .await?;

            // Validate the new credential against the endpoint that issued it
            // before either value reaches disk. A forged or skewed exchange
            // response cannot replace a known-good login.
            let login_client = Client::with_trust(&login.controld_url, trust.clone());
            let session = login_client.operator_session(&login.operator_token).await?;
            tokenfile::write_operator_token(&token_path, &login.operator_token)?;
            tokenfile::write_connection_config(
                &token_path,
                &tokenfile::ConnectionConfig {
                    controld: login.controld_url,
                    hub: login.hub_url,
                },
            )?;

            match login.email {
                Some(email) => println!("signed in as {email}"),
                None => println!("signed in: user={}", session.user_id),
            }
            println!(
                "  operator credential saved: {} (0600)",
                tokenfile::operator_path(&token_path).display()
            );
            println!(
                "  credential valid until {} (ms since epoch)",
                login.operator_expires_at_ms
            );
        }
        AuthCommand::Session => {
            let credential = tokenfile::read_operator_token(&token_path)?;
            let session = client.operator_session(&credential).await?;
            println!(
                "session: user={} principal={} expires_at_ms={}",
                session.user_id, session.principal_id, session.expires_at_ms
            );
        }
    }
    Ok(())
}

/// `reachpad key …` — API keys (ADR-0059 §4). Every verb presents the saved
/// operator credential: a key cannot mint, list, or revoke keys.
async fn run_key(
    controld: &str,
    trust: crate::transport::TlsTrust,
    token_path: std::path::PathBuf,
    cmd: crate::cli::KeyCommand,
) -> anyhow::Result<()> {
    use crate::cli::KeyCommand;
    let client = Client::with_trust(controld, trust);
    let credential = tokenfile::read_operator_token(&token_path)?;
    match cmd {
        KeyCommand::Mint {
            label,
            role,
            workspace_ids,
            ttl,
        } => {
            let scope = (!workspace_ids.is_empty()).then_some(workspace_ids.as_slice());
            let minted = client
                .create_api_key(&credential, label.as_deref(), &role, scope, ttl)
                .await?;
            println!("api key minted: id={} role={}", minted.id, minted.role);
            println!("  valid until {} (ms since epoch)", minted.expires_at_ms);
            match scope {
                Some(ids) => println!("  scope: {}", ids.join(" ")),
                None => println!("  scope: the whole account"),
            }
            println!("  the value below is shown ONCE and is not recoverable:");
            // stdout, alone on its line, so `reachpad key mint … | tail -1`
            // captures exactly the secret and nothing else.
            println!("{}", minted.key);
        }
        KeyCommand::List => {
            let rows = client.list_api_keys(&credential).await?;
            if rows.is_empty() {
                println!("no api keys");
            }
            for k in rows {
                let scope = if k.workspace_ids.is_empty() {
                    "account".to_owned()
                } else {
                    k.workspace_ids.join(",")
                };
                let state = match (k.usable, k.revoked_at_ms) {
                    (true, _) => "usable",
                    (false, Some(_)) => "revoked",
                    (false, None) => "expired",
                };
                println!(
                    "{}  {}  role={} scope={} expires_at_ms={} [{}]",
                    k.id, k.label, k.role, scope, k.expires_at_ms, state
                );
            }
        }
        KeyCommand::Revoke { id } => {
            client.revoke_api_key(&credential, &id).await?;
            println!("revoked: {id}");
            println!("  exec calls presenting it are refused from now; nothing else changed");
        }
    }
    Ok(())
}

/// Resolve the user-scoped identity token every user-level operation needs
/// (create, list — I6: naming a principal is never enough).
///
/// Both paths end at the SAME token: an IdP assertion exchanged for one, or
/// the saved operator credential exchanged for one (ADR-0034). The operator
/// credential names its own user, so `--user` is only ever a claim to check.
async fn user_identity(
    client: &Client,
    token_path: &std::path::Path,
    user: Option<String>,
    principal: &str,
    idp_assertion: Option<String>,
) -> anyhow::Result<(String, String)> {
    match idp_assertion {
        Some(assertion) => {
            // clap's `requires = "user"` guarantees the pair.
            let user = user.context("--idp-assertion requires --user")?;
            let identity = client.identity_token(&user, principal, &assertion).await?;
            Ok((user, identity))
        }
        None => {
            let credential = tokenfile::read_operator_token(token_path)?;
            let session = client.operator_session(&credential).await?;
            if let Some(claimed) = &user {
                anyhow::ensure!(
                    claimed == &session.user_id,
                    "--user {claimed} does not match the operator credential's user {}",
                    session.user_id
                );
            }
            Ok((session.user_id, session.identity_token))
        }
    }
}

async fn run_ws(
    controld: &str,
    trust: crate::transport::TlsTrust,
    token_path: std::path::PathBuf,
    cmd: WsCommand,
) -> anyhow::Result<i32> {
    let client = Client::with_trust(controld, trust);
    match cmd {
        WsCommand::Create {
            name,
            user,
            principal,
            idp_assertion,
        } => {
            let (user, identity) =
                user_identity(&client, &token_path, user, &principal, idp_assertion).await?;
            let created = client.create_workspace(&user, &identity, &name).await?;
            // The owner Biscuit authorizes every later call for this
            // workspace; without saving it, attach has nothing to present.
            tokenfile::write_token(&token_path, &created.biscuit_b64)?;
            println!(
                "workspace created: {} (name={name} user={user})",
                created.workspace
            );
            println!("  owner biscuit saved: {} (0600)", token_path.display());
        }
        WsCommand::List {
            user,
            principal,
            idp_assertion,
        } => {
            let (user, identity) =
                user_identity(&client, &token_path, user, &principal, idp_assertion).await?;
            let rows = client.list_workspaces(&user, &identity).await?;
            if rows.is_empty() {
                println!("no workspaces for {user}");
            }
            for ws in &rows {
                let forks = if ws.forks == 0 {
                    String::new()
                } else {
                    format!("  ({} fork(s))", ws.forks)
                };
                println!("{}  {}{forks}", ws.id, ws.name);
            }
        }
        WsCommand::Attach { id } => {
            // Attach presents the Biscuit saved by `ws create` (or by a share
            // link): the acting principal comes from the token, never from a
            // flag (I5/I6).
            let presented = tokenfile::read_token(&token_path)?;
            let attach = client.attach(&id, &presented).await?;
            tokenfile::write_token(&token_path, &attach.biscuit_b64)?;
            tokenfile::save_attach_state(
                &token_path,
                &id,
                tokenfile::AttachState {
                    node: attach.node.clone(),
                    fencing_token: attach.fencing_token,
                    principal: String::new(),
                },
            )?;
            println!("attached: workspace={id}");
            println!("  node:          {}", attach.node);
            println!("  fencing_token: {}", attach.fencing_token);
            println!("  lease expires: {} (ms since epoch)", attach.expires_at_ms);
            println!("  biscuit saved: {} (0600)", token_path.display());
        }
        WsCommand::Fork { id, snapshot, name } => {
            let presented = tokenfile::read_token(&token_path)?;
            let forked = client
                .fork(&id, &presented, snapshot.as_deref(), name.as_deref())
                .await?;
            tokenfile::write_token(&token_path, &forked.biscuit_b64)?;
            println!(
                "forked: {} (name={} from={id} snapshot={} log_seq={})",
                forked.workspace, forked.name, forked.origin_snapshot, forked.origin_log_seq
            );
            println!("  both histories preserved; the fork spends a workspace slot");
            println!(
                "  the fork's owner biscuit saved: {} (0600)",
                token_path.display()
            );
        }
        WsCommand::Rewind {
            id,
            snapshot,
            preserved_name,
        } => {
            let presented = tokenfile::read_token(&token_path)?;
            let rewound = client
                .rewind(&id, &presented, &snapshot, preserved_name.as_deref())
                .await?;
            println!(
                "rewound: {id} now resumes from {} (log_seq={})",
                rewound.head_snapshot, rewound.head_log_seq
            );
            println!(
                "  forward history preserved as {} ({})",
                rewound.preserved_fork, rewound.preserved_fork_name
            );
        }
        WsCommand::Exec {
            id,
            cwd,
            env,
            timeout_ms,
            api_key,
            stdin,
            argv,
        } => {
            let mut envs = std::collections::BTreeMap::new();
            for pair in &env {
                let (k, v) = pair
                    .split_once('=')
                    .with_context(|| format!("--env expects NAME=VALUE, got {pair:?}"))?;
                envs.insert(k.to_owned(), v.to_owned());
            }
            // The saved Biscuit is read ONLY when no key was given, so a
            // caller on a machine with no token file — which is every API
            // caller — never trips over a missing one.
            let presented;
            let auth = match api_key.as_deref() {
                Some(k) => crate::api::ExecAuth::ApiKey(k),
                None => {
                    presented = tokenfile::read_token(&token_path)?;
                    crate::api::ExecAuth::Biscuit(&presented)
                }
            };
            // Local stdin, read to EOF BEFORE the request: the exec route
            // takes stdin as one field, not a stream.
            let stdin_b64 = if stdin {
                let mut buf = Vec::new();
                std::io::Read::read_to_end(&mut std::io::stdin(), &mut buf)
                    .context("reading stdin for --stdin")?;
                Some(BASE64.encode(buf))
            } else {
                None
            };
            use std::io::Write as _;
            let spec = crate::api::ExecSpec {
                argv: &argv,
                cwd: cwd.as_deref(),
                env: &envs,
                timeout_ms,
                stdin_b64,
            };
            let end = client
                .exec(&id, auth, &spec, |fd, bytes| {
                    // stdout to stdout and stderr to stderr, unmerged all
                    // the way to the terminal: a caller diffing build
                    // output against warnings cannot un-merge them, and
                    // this is the last place they could be merged.
                    if fd == 2 {
                        let _ = std::io::stderr().write_all(bytes);
                        let _ = std::io::stderr().flush();
                    } else {
                        let _ = std::io::stdout().write_all(bytes);
                        let _ = std::io::stdout().flush();
                    }
                })
                .await?;

            if end.get("timed_out").and_then(|v| v.as_bool()) == Some(true) {
                eprintln!("reachpad: the command TIMED OUT and was killed");
            }
            if end.get("truncated").and_then(|v| v.as_bool()) == Some(true) {
                eprintln!("reachpad: output was TRUNCATED at the entitlement cap");
            }
            if let Some(err) = end.get("error").and_then(|v| v.as_str()) {
                let detail = end.get("detail").and_then(|v| v.as_str()).unwrap_or("");
                eprintln!("reachpad: exec did not produce a result: {err} {detail}");
                return Ok(70); // EX_SOFTWARE: not the command's code
            }
            // EXIT WITH THE COMMAND'S OWN CODE, so this composes in a script.
            // A signal is NOT an exit code (§42.1: a policy and a failure must
            // not be the same value), so a killed command reports 128+n the
            // way a shell does rather than inventing one.
            return Ok(match end.get("exit_code").and_then(|v| v.as_i64()) {
                Some(code) => code as i32,
                None => {
                    let sig = end.get("signal").and_then(|v| v.as_str()).unwrap_or("?");
                    eprintln!("reachpad: killed by {sig}");
                    137
                }
            });
        }
        WsCommand::Release {
            id,
            fencing_token,
            discard,
        } => {
            let saved = tokenfile::load_attach_state(&token_path, &id);
            let fencing_token = fencing_token
                .or(saved.as_ref().map(|s| s.fencing_token))
                .context("no --fencing-token given and no saved attach state for this workspace")?;
            let presented = tokenfile::read_token(&token_path)?;
            let released = client
                .release(&id, &presented, fencing_token, discard)
                .await?;
            if released {
                println!(
                    "released: workspace={id} fencing_token={fencing_token} \
                     (DISCARDED: everything since the last seal is gone)"
                );
            } else {
                println!("release ordered: workspace={id} fencing_token={fencing_token}");
                println!(
                    "  the node seals first (disk; memory when cleanly pausable), then \
                     stops the VM; the lease ends when it stops renewing. The next \
                     attach resumes from that seal. Use --discard to skip the seal."
                );
            }
        }
        WsCommand::Lineage { id } => {
            let presented = tokenfile::read_token(&token_path)?;
            let lineage = client.lineage(&id, &presented).await?;
            println!("workspace={id}");
            match &lineage.head {
                Some(head) => {
                    println!(
                        "  resumes from: {} (kind={}{} log_seq={})",
                        head.id,
                        head.kind,
                        head.pool_id
                            .as_ref()
                            .map(|p| format!(" pool={p}"))
                            .unwrap_or_default(),
                        head.log_seq
                    );
                }
                None => println!("  resumes from: nothing (never sealed — a fresh boot)"),
            }
            if lineage.snapshots.is_empty() {
                println!("  snapshots: none");
            } else {
                // Oldest first, head marked — this list is what `ws rewind
                // --snapshot` is driven from.
                println!("  snapshots (oldest first; pick one for `ws rewind --snapshot`):");
                let head_id = lineage.head.as_ref().map(|h| h.id.as_str());
                for s in &lineage.snapshots {
                    println!(
                        "    {}  kind={} log_seq={} sealed_at_ms={}{}",
                        s.id,
                        s.kind,
                        s.log_seq,
                        s.sealed_at_ms,
                        if Some(s.id.as_str()) == head_id {
                            "  <- head"
                        } else {
                            ""
                        }
                    );
                }
            }
            if !lineage.forks.is_empty() {
                println!("  forks: {}", lineage.forks.join(" "));
            }
        }
        WsCommand::Archive { id } => {
            let presented = tokenfile::read_token(&token_path)?;
            let at = client.archive(&id, &presented).await?;
            println!("archived: workspace={id} archived_at_ms={at}");
            println!("  no data is deleted immediately; archived state follows managed retention");
        }
        WsCommand::Token {
            id,
            user,
            principal,
            idp_assertion,
        } => {
            let (user, identity) =
                user_identity(&client, &token_path, user, &principal, idp_assertion).await?;
            let (biscuit, expires_at_ms) = client.workspace_token(&id, &user, &identity).await?;
            // Saved, because a token nobody stored is a token that has to be
            // fetched again for the very next command.
            tokenfile::write_token(&token_path, &biscuit)?;
            println!("workspace token: {id} (user={user})");
            println!("  owner biscuit saved: {} (0600)", token_path.display());
            println!("  valid until {expires_at_ms} (ms since epoch)");
        }
    }
    // Every `ws` verb but `exec` exits 0; `exec` returned the command's OWN
    // exit code above, which is what makes it composable in a script — a
    // wrapper that always exits 0 turns every failure into a silent success.
    Ok(0)
}

async fn run_share(
    controld: &str,
    trust: crate::transport::TlsTrust,
    token_b64: &str,
    workspace: &str,
    role: crate::cli::RoleArg,
    expires_at_ms: u64,
    grantee: &str,
) -> anyhow::Result<()> {
    // Server-side: the grant row + server-minted share token (§8 flow 7).
    let client = Client::with_trust(controld, trust);
    let share = client
        .grant(workspace, token_b64, grantee, role.as_str(), expires_at_ms)
        .await?;
    println!(
        "grant created: workspace={workspace} grantee={grantee} role={} expires_at_ms={}",
        share.role, share.expires_at_ms
    );
    println!("server share token:");
    println!("  {}", share.share_token_b64);

    // Offline: the SAME narrowing computed locally with authz::attenuate —
    // no server, no root key (§7.2: a share link IS an attenuated token;
    // appended blocks carry only checks, so narrowing is all they can do).
    let local = authz::TokenBytes::from_vec(
        BASE64
            .decode(token_b64.trim())
            .context("local token is not valid base64")?,
    );
    let narrowed = authz::attenuate(&local, role.as_authz(), expires_at_ms)
        .context("offline attenuation failed")?;
    println!("offline attenuated token (authz::attenuate on your local token — §7.2:");
    println!("attenuation can only narrow; no server mint is needed for narrowing):");
    println!("  {}", BASE64.encode(narrowed.as_bytes()));
    Ok(())
}

async fn run_tail_command(
    hub: &str,
    workspace: &str,
    token: &[u8],
    options: TailOptions,
) -> anyhow::Result<()> {
    let mut session = TailSession::connect_with(hub, workspace, token, options).await?;
    // M0 debt 5 closed: the negotiated ServerHello is consumed, not
    // ignored — version, capabilities, incarnation, watermarks.
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
                    return Ok(());
                }
            },
            _ = tokio::signal::ctrl_c() => return Ok(()),
        }
    }
}

fn print_inspection(i: &inspect::Inspection) {
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
mod onboarding_tests {
    use super::*;

    #[test]
    fn bare_command_only_onboards_an_interactive_terminal() {
        assert_eq!(
            onboarding_action(false, false),
            OnboardingAction::RefuseNonInteractive
        );
        assert_eq!(
            onboarding_action(false, true),
            OnboardingAction::RefuseNonInteractive
        );
        assert_eq!(
            onboarding_action(true, false),
            OnboardingAction::SignInThenList
        );
        assert_eq!(onboarding_action(true, true), OnboardingAction::List);
    }
}
