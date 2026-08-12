//! The clap surface. Defaults match the loopback listen addresses of the
//! servers this CLI talks to: controld (`bins/controld`, `DEV_LISTEN =
//! 127.0.0.1:7401`) and hub (`bins/hub`, `DEFAULT_LISTEN = 127.0.0.1:7420`,
//! WebSocket route `/ws`).
//!
//! Against a real deployment there is ONE endpoint and one port (ADR-0040):
//! `--endpoint <host>` sets both `--controld https://<host>` (control, TLS on
//! 443) and `--hub quic://<host>` (data, QUIC on 443). Nothing else is needed
//! from a laptop, and nothing beyond 443 is reachable.

use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

/// Default controld base URL (matches `controld::DEV_LISTEN`).
pub const DEFAULT_CONTROLD: &str = "http://127.0.0.1:7401";
/// Default hub WebSocket URL (matches hub's `DEFAULT_LISTEN` + `/ws` route).
pub const DEFAULT_HUB: &str = "ws://127.0.0.1:7420/ws";

#[derive(Parser, Debug)]
#[command(
    name = "reachpad",
    version,
    about = "reachpad — run coding agents in durable cloud workspaces (§5.8)"
)]
pub struct Cli {
    /// The reachpad endpoint, e.g. `m1.reachpad.dev` — the ONE public host
    /// and the ONE public port (443). Sets `--controld https://<host>` and
    /// `--hub quic://<host>` together, which is everything a laptop needs
    /// (ADR-0040). Either explicit flag overrides its half.
    #[arg(long, global = true)]
    pub endpoint: Option<String>,

    /// controld base URL: `https://host[:port]` (the public control plane,
    /// port 443 by default) or `http://127.0.0.1:7401` for a controld on this
    /// machine. Plain `http://` to any other host is REFUSED — every control
    /// call carries a credential (ADR-0040).
    #[arg(long, global = true, default_value = DEFAULT_CONTROLD)]
    pub controld: String,

    /// hub URL: `ws://` / `wss://` (WebSocket fallback) or
    /// `quic://host[:port]` (ADR-0026; port defaults to 443).
    #[arg(long, global = true, default_value = DEFAULT_HUB)]
    pub hub: String,

    /// For quic:// — trust the hub's deterministic pinned dev certificate
    /// instead of the OS trust store. DEV ONLY: that key is public
    /// knowledge; never use this against a hub you don't run yourself.
    #[arg(long, global = true)]
    pub quic_dev_pin: bool,

    /// For `quic://` and `https://` — trust EXACTLY these PEM anchors instead
    /// of the OS trust store. Required against a hub on a Let's Encrypt
    /// *staging* certificate, whose hierarchy deliberately roots in no OS
    /// trust store. Repeatable. Narrower than the default, never wider — and
    /// there is deliberately no flag that disables verification.
    #[arg(long = "hub-ca", global = true)]
    pub hub_ca: Vec<PathBuf>,

    /// Biscuit token (base64). Overrides --token-file.
    #[arg(long, global = true)]
    pub token: Option<String>,

    /// Token file path (default ~/.config/reachpad/token; written 0600).
    #[arg(long, global = true)]
    pub token_file: Option<PathBuf>,

    /// Print per-variable config status (names only, never values) and exit.
    #[arg(long)]
    pub check_config: bool,

    #[command(subcommand)]
    pub command: Option<Command>,
}

impl Cli {
    /// Expand `--endpoint <host>` into the two URLs it stands for (ADR-0040):
    /// `https://<host>` for control and `quic://<host>` for data — one host,
    /// one port, both planes.
    ///
    /// An explicit `--controld` / `--hub` wins. "Explicit" is judged by
    /// comparison with the default, which means passing the default value
    /// literally is indistinguishable from passing nothing — harmless, since
    /// both name the same thing.
    pub fn resolve_endpoint(&mut self) {
        let Some(endpoint) = self.endpoint.clone() else {
            return;
        };
        let host = endpoint
            .trim()
            .trim_end_matches('/')
            .strip_prefix("https://")
            .unwrap_or_else(|| endpoint.trim().trim_end_matches('/'))
            .to_owned();
        if self.controld == DEFAULT_CONTROLD {
            self.controld = format!("https://{host}");
        }
        if self.hub == DEFAULT_HUB {
            self.hub = format!("quic://{host}");
        }
    }

    /// The TLS trust posture for both planes — one decision, applied to the
    /// control connection and the data connection alike.
    pub fn trust(&self) -> crate::transport::TlsTrust {
        crate::transport::TlsTrust {
            dev_pin: self.quic_dev_pin,
            ca_files: self.hub_ca.clone(),
        }
    }
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Workspace lifecycle (create / attach / release).
    #[command(subcommand)]
    Ws(WsCommand),
    /// Share a workspace: server grant + offline attenuation (§7.2).
    Share {
        /// Workspace id.
        workspace: String,
        /// Role for the guest (grants are viewer/collaborator; §7.4).
        #[arg(long, value_enum)]
        role: RoleArg,
        /// Grant lifetime, e.g. 90s / 30m / 12h / 7d.
        #[arg(long, value_parser = parse_duration_ms)]
        expires_in: u64,
        /// Principal id the grant is for.
        #[arg(long, default_value = "dev-principal")]
        grantee: String,
    },
    /// Stream a workspace's live event tail from hub (frozen §6 framing).
    Tail {
        /// Workspace id.
        workspace: String,
    },
    /// Attach an interactive terminal to a workspace (§8 flow 3, ADR-0033).
    ///
    /// Places the lease through controld (so the node boots the VM), then
    /// opens a PTY session over hub. Ctrl-] detaches; Ctrl-C goes to the
    /// workspace. Detaching leaves the workspace running.
    Attach {
        /// Workspace id.
        workspace: String,
        /// Attach to `pty/<n>`.
        #[arg(long, default_value_t = 0, conflicts_with_all = ["new", "list"])]
        pty: u32,
        /// Open a NEW terminal in the workspace and attach to it (ADR-0063)
        /// — the same operation the browser's "+" tab performed.
        #[arg(long, conflicts_with = "list")]
        new: bool,
        /// Print the roster of live PTYs and exit (ADR-0063).
        #[arg(long)]
        list: bool,
        /// Skip the controld attach call and go straight to hub (the lease
        /// is already placed — e.g. re-attaching to a running workspace).
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
        /// before sending the first keystroke (0 disables the wait). Input
        /// sent before the node is listening reaches no shell: the live
        /// channel is best-effort transport (§4.2).
        #[arg(long, default_value_t = 30_000)]
        wait_for_node_ms: u64,
    },
    /// Present an operator credential (ADR-0034): the way a laptop gets into
    /// the capability chain without holding a platform secret.
    #[command(subcommand)]
    Auth(AuthCommand),
    /// API keys (`rpak1.…`, ADR-0059): the credential an agent or CI runner
    /// holds. Minting requires the saved operator credential — a key cannot
    /// mint another key.
    #[command(subcommand)]
    Key(KeyCommand),
    /// Token utilities.
    #[command(subcommand)]
    Token(TokenCommand),
}

#[derive(Subcommand, Debug)]
pub enum KeyCommand {
    /// Mint an API key (POST /v1/api-keys). The value is shown ONCE and is
    /// not recoverable. Default scope is the whole account; name workspaces
    /// with `--workspace` to narrow it.
    Mint {
        /// Free-form label ("ci runner"). Never a secret.
        #[arg(long)]
        label: Option<String>,
        /// `owner` or `collaborator` (default: collaborator, the narrower).
        #[arg(long, default_value = "collaborator")]
        role: String,
        /// Workspace id this key may act on. Repeatable; absent = the whole
        /// account.
        #[arg(long = "workspace")]
        workspace_ids: Vec<String>,
        /// Key lifetime, e.g. 30d (server default 90d, max 365d).
        #[arg(long, value_parser = parse_duration_ms)]
        ttl: Option<u64>,
    },
    /// List your keys: metadata only, secrets are never readable again.
    List,
    /// Revoke a key by id (`key list` shows ids). Idempotent.
    Revoke {
        /// The key id (the middle of `rpak1.<id>.<secret>`).
        id: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum AuthCommand {
    /// Save an operator credential and exchange it for an identity token.
    ///
    /// Get the credential from your account page (reachpad.dev/connect,
    /// shown once at mint), or on the controld host with
    /// `controld mint-operator-token --user-id U --principal-id P`.
    /// `-` reads it from stdin so it never reaches a shell history or a
    /// process listing.
    Login {
        /// The credential (`rpop1.…`), or `-` to read it from stdin.
        #[arg(long)]
        operator_token: String,
    },
    /// Exchange the saved operator credential for a fresh identity token and
    /// print who it says you are. Identity tokens are short-lived (an hour);
    /// this is how you renew one.
    Session,
}

#[derive(Subcommand, Debug)]
pub enum WsCommand {
    /// Create a workspace (POST /v1/workspaces — creation is metadata, §8.2).
    ///
    /// Two ways to authenticate, both landing on the same user-scoped
    /// identity token (I6): a saved operator credential (`reachpad auth login`,
    /// ADR-0034) — the default — or an explicit `--idp-assertion`, which is
    /// what dev and the IdP integration use.
    Create {
        /// Workspace name.
        #[arg(long)]
        name: String,
        /// Owning user id. Optional with an operator credential: the exchange
        /// says which user it acts for, and a mismatch is refused.
        #[arg(long)]
        user: Option<String>,
        /// Principal that will act for the user (`--idp-assertion` path only;
        /// an operator credential names its own principal).
        #[arg(long, default_value = "dev-principal")]
        principal: String,
        /// What your IdP vouches for, exchanged for a user-scoped identity
        /// token. In dev, controld logs the deterministic assertion at boot.
        /// Requires `--user`.
        #[arg(long, requires = "user")]
        idp_assertion: Option<String>,
    },
    /// List your workspaces and their forks (GET /v1/workspaces — §8.5).
    ///
    /// Authorized by the same user-scoped identity token creation needs (I6):
    /// a saved operator credential by default, or `--idp-assertion --user`.
    List {
        /// Owning user id. Optional with an operator credential, which names
        /// its own user; a mismatch is refused.
        #[arg(long)]
        user: Option<String>,
        /// Principal that will act for the user (`--idp-assertion` path only).
        #[arg(long, default_value = "dev-principal")]
        principal: String,
        /// What your IdP vouches for. Requires `--user`.
        #[arg(long, requires = "user")]
        idp_assertion: Option<String>,
    },
    /// Attach to a workspace (POST /v1/workspaces/:id/attach — §8.3).
    /// Prints node + fencing token and saves the returned Biscuit to the
    /// token file (0600).
    Attach {
        /// Workspace id.
        id: String,
    },
    /// Run ONE command in a workspace and print what happened to it
    /// (POST /v1/workspaces/:id/exec — ADR-0059).
    ///
    /// No PTY and no shell. Everything after `--` is ARGV, passed to the
    /// guest as a list: `reachpad ws exec ws-1 -- ls -la /mnt`. A caller that
    /// genuinely wants a shell asks for one — `-- sh -lc 'a | b'` — and owns
    /// that in its own audit trail.
    ///
    /// stdout and stderr are printed to stdout and stderr respectively, and
    /// **this command exits with the command's own exit code**, so it composes
    /// in a script the way any other program does.
    Exec {
        /// Workspace id.
        id: String,
        /// Working directory inside the guest.
        #[arg(long)]
        cwd: Option<String>,
        /// `NAME=VALUE`, repeatable. Additive on top of the guest's own
        /// environment, never a replacement for it.
        #[arg(long = "env", value_name = "NAME=VALUE")]
        env: Vec<String>,
        /// Give up after this long. Clamped to the entitlement server-side.
        #[arg(long)]
        timeout_ms: Option<u64>,
        /// An API key (`rpak1.…`) instead of the saved Biscuit. This is how a
        /// caller that is not this laptop runs a command.
        #[arg(long)]
        api_key: Option<String>,
        /// Read local stdin to EOF and feed it to the command's stdin.
        #[arg(long)]
        stdin: bool,
        /// The command and its arguments.
        #[arg(last = true, required = true)]
        argv: Vec<String>,
    },
    /// Fork a workspace at a sealed snapshot (POST /v1/workspaces/:id/fork —
    /// §8 flow 5).
    ///
    /// The child is a new workspace rooted at the snapshot; both histories
    /// are preserved. A fork spends a `max_workspaces` slot. The child's
    /// owner Biscuit replaces the saved one, so `ws attach` lands in the
    /// fork straight afterwards.
    Fork {
        /// SOURCE workspace id.
        id: String,
        /// Sealed snapshot of the source to root at (see `ws lineage`).
        /// Defaults to the current head — "fork what I am looking at".
        #[arg(long)]
        snapshot: Option<String>,
        /// Name for the child.
        #[arg(long)]
        name: Option<String>,
    },
    /// Rewind a workspace to an earlier sealed snapshot
    /// (POST /v1/workspaces/:id/rewind — §8 flow 6).
    ///
    /// The forward history is never destroyed: it is preserved as an
    /// auto-created fork. Refused while a node holds the lease — release
    /// the workspace first.
    Rewind {
        /// Workspace id.
        id: String,
        /// The earlier sealed snapshot of THIS workspace to resume from
        /// (pick one off `ws lineage`).
        #[arg(long)]
        snapshot: String,
        /// Name for the fork that preserves the forward history.
        #[arg(long)]
        preserved_name: Option<String>,
    },
    /// Release a workspace (POST /v1/workspaces/:id/release).
    ///
    /// By default this SEALS FIRST: the node captures the workspace's disk
    /// (and memory, when cleanly pausable), registers the snapshot, and only
    /// then stops the VM; the lease ends once the node stops renewing. The
    /// next attach resumes from that seal.
    Release {
        /// Workspace id.
        id: String,
        /// Fencing token; defaults to the one saved by `ws attach`.
        #[arg(long)]
        fencing_token: Option<u64>,
        /// Skip the seal: end the lease and kill the VM immediately.
        /// EVERYTHING SINCE THE LAST SEAL IS LOST — a workspace that never
        /// paused loses its whole session. This is the explicit opt-out of
        /// the seal-first default.
        #[arg(long)]
        discard: bool,
    },
    /// Show what a workspace resumes from (GET /v1/workspaces/:id/lineage).
    ///
    /// Prints the head snapshot's kind — `disk+mem` means the workspace can
    /// resume mid-thought within its pool; `disk` means it boots (§4.3).
    Lineage {
        /// Workspace id.
        id: String,
    },
    /// Archive a workspace (POST /v1/workspaces/:id/archive).
    ///
    /// Frees the entitlement slot it holds. Nothing is deleted: the snapshot
    /// chain and the event log are untouched (I4, I5) — the workspace simply
    /// stops counting as live and can no longer be attached.
    Archive {
        /// Workspace id.
        id: String,
    },
    /// Get back into a workspace you own whose token has expired
    /// (POST /v1/workspaces/:id/token — ADR-0060).
    ///
    /// A workspace Biscuit lives an hour. Until this existed, the only ways to
    /// get one were creating the workspace or already holding one for it, so
    /// coming back the next day left the workspace unusable AND unarchivable —
    /// holding its entitlement slot with no way to free it.
    ///
    /// Authorized by the same credential `ws create` and `ws list` use: a saved
    /// operator credential (`reachpad auth login`) or `--idp-assertion --user`.
    /// The new Biscuit is saved to the token file, so `ws archive`, `ws attach`
    /// and the rest work straight afterwards.
    Token {
        /// Workspace id.
        id: String,
        /// Owning user id. Optional with an operator credential, which names
        /// its own user; a mismatch is refused.
        #[arg(long)]
        user: Option<String>,
        /// Principal that will act for the user (`--idp-assertion` path only).
        #[arg(long, default_value = "dev-principal")]
        principal: String,
        /// What your IdP vouches for. Requires `--user`.
        #[arg(long, requires = "user")]
        idp_assertion: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum TokenCommand {
    /// Print the token's facts (principal/workspace/role/exp) offline —
    /// parse only, no verification, no root key involved.
    Inspect,
}

/// Grantable roles (§7.4; `owner` is not grantable, `harness` is a token
/// profile, not a grant role).
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum RoleArg {
    Viewer,
    Collaborator,
}

impl RoleArg {
    pub fn as_authz(self) -> authz::Role {
        match self {
            RoleArg::Viewer => authz::Role::Viewer,
            RoleArg::Collaborator => authz::Role::Collaborator,
        }
    }

    pub fn as_str(self) -> &'static str {
        self.as_authz().as_str()
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

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Cli {
        Cli::try_parse_from(args).expect("args should parse")
    }

    #[test]
    fn defaults_point_at_the_dev_listen_addresses() {
        let cli = parse(&["reachpad", "tail", "ws-1"]);
        assert_eq!(cli.controld, DEFAULT_CONTROLD);
        assert_eq!(cli.hub, DEFAULT_HUB);
        assert!(cli.token.is_none());
        assert!(cli.token_file.is_none());
        assert!(!cli.quic_dev_pin);
    }

    /// ADR-0040: one host, one port, both planes.
    #[test]
    fn endpoint_expands_into_both_planes() {
        let mut cli = parse(&["reachpad", "--endpoint", "m1.reachpad.dev", "ws", "list"]);
        cli.resolve_endpoint();
        assert_eq!(cli.controld, "https://m1.reachpad.dev");
        assert_eq!(cli.hub, "quic://m1.reachpad.dev");

        // A pasted scheme and a trailing slash are tolerated.
        let mut cli = parse(&[
            "reachpad",
            "--endpoint",
            "https://m1.reachpad.dev/",
            "ws",
            "list",
        ]);
        cli.resolve_endpoint();
        assert_eq!(cli.controld, "https://m1.reachpad.dev");

        // An explicit flag wins over the endpoint shorthand.
        let mut cli = parse(&[
            "reachpad",
            "--endpoint",
            "m1.reachpad.dev",
            "--controld",
            "http://127.0.0.1:9",
            "ws",
            "list",
        ]);
        cli.resolve_endpoint();
        assert_eq!(cli.controld, "http://127.0.0.1:9");
        assert_eq!(cli.hub, "quic://m1.reachpad.dev");

        // No endpoint: the loopback defaults stand.
        let mut cli = parse(&["reachpad", "ws", "list"]);
        cli.resolve_endpoint();
        assert_eq!(cli.controld, DEFAULT_CONTROLD);
        assert_eq!(cli.hub, DEFAULT_HUB);
    }

    #[test]
    fn trust_is_one_decision_for_both_planes() {
        let cli = parse(&["reachpad", "--hub-ca", "/tmp/staging.pem", "ws", "list"]);
        let trust = cli.trust();
        assert!(!trust.dev_pin);
        assert_eq!(trust.ca_files.len(), 1);
        // The default is the OS trust store, and there is no third option.
        let cli = parse(&["reachpad", "ws", "list"]);
        assert_eq!(cli.trust().describe(), "the OS trust store");
    }

    #[test]
    fn quic_hub_url_and_dev_pin_parse() {
        let cli = parse(&[
            "reachpad",
            "--hub",
            "quic://127.0.0.1:7443",
            "--quic-dev-pin",
            "tail",
            "ws-1",
        ]);
        assert_eq!(cli.hub, "quic://127.0.0.1:7443");
        assert!(cli.quic_dev_pin);
    }

    #[test]
    fn ws_create_requires_name_user_and_assertion() {
        let cli = parse(&[
            "reachpad",
            "ws",
            "create",
            "--name",
            "scratch",
            "--user",
            "u-1",
            "--idp-assertion",
            "vouched",
        ]);
        match cli.command {
            Some(Command::Ws(WsCommand::Create {
                name,
                user,
                principal,
                idp_assertion,
            })) => {
                assert_eq!(name, "scratch");
                assert_eq!(user.as_deref(), Some("u-1"));
                assert_eq!(principal, "dev-principal");
                assert_eq!(idp_assertion.as_deref(), Some("vouched"));
            }
            other => panic!("wrong parse: {other:?}"),
        }
        assert!(Cli::try_parse_from(["reachpad", "ws", "create"]).is_err());
        // The operator-credential path (ADR-0034/0039): no assertion, no
        // user — the saved credential names both. Still authenticated: the
        // credential is exchanged for the same identity token (I6).
        let cli = parse(&["reachpad", "ws", "create", "--name", "x"]);
        match cli.command {
            Some(Command::Ws(WsCommand::Create {
                user,
                idp_assertion,
                ..
            })) => {
                assert!(user.is_none());
                assert!(idp_assertion.is_none());
            }
            other => panic!("wrong parse: {other:?}"),
        }
        // An IdP assertion still needs the user it vouches for.
        assert!(Cli::try_parse_from([
            "reachpad",
            "ws",
            "create",
            "--name",
            "x",
            "--idp-assertion",
            "v"
        ])
        .is_err());
    }

    #[test]
    fn ws_attach_and_release_parse() {
        let cli = parse(&["reachpad", "ws", "attach", "ws-7"]);
        match cli.command {
            Some(Command::Ws(WsCommand::Attach { id })) => {
                assert_eq!(id, "ws-7");
            }
            other => panic!("wrong parse: {other:?}"),
        }
        let cli = parse(&["reachpad", "ws", "release", "ws-7", "--fencing-token", "3"]);
        match cli.command {
            Some(Command::Ws(WsCommand::Release {
                id, fencing_token, ..
            })) => {
                assert_eq!(id, "ws-7");
                assert_eq!(fencing_token, Some(3));
            }
            other => panic!("wrong parse: {other:?}"),
        }
    }

    #[test]
    fn share_parses_role_and_duration() {
        let cli = parse(&[
            "reachpad",
            "share",
            "ws-1",
            "--role",
            "viewer",
            "--expires-in",
            "30m",
        ]);
        match cli.command {
            Some(Command::Share {
                workspace,
                role,
                expires_in,
                grantee,
            }) => {
                assert_eq!(workspace, "ws-1");
                assert_eq!(role, RoleArg::Viewer);
                assert_eq!(expires_in, 30 * 60_000);
                assert_eq!(grantee, "dev-principal");
            }
            other => panic!("wrong parse: {other:?}"),
        }
        // owner is not a grantable role (§7.4).
        assert!(Cli::try_parse_from([
            "reachpad",
            "share",
            "ws-1",
            "--role",
            "owner",
            "--expires-in",
            "1h",
        ])
        .is_err());
    }

    #[test]
    fn token_inspect_and_global_flags_parse() {
        let cli = parse(&[
            "reachpad",
            "--controld",
            "http://127.0.0.1:1",
            "--token",
            "abc",
            "token",
            "inspect",
        ]);
        assert_eq!(cli.controld, "http://127.0.0.1:1");
        assert_eq!(cli.token.as_deref(), Some("abc"));
        assert!(matches!(
            cli.command,
            Some(Command::Token(TokenCommand::Inspect))
        ));
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
}
