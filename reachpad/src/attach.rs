//! `reach attach` — an interactive terminal in a real workspace (§8 flow 3,
//! ADR-0033). This is the felt test: a human types, and a process inside a
//! Firecracker VM on some node answers.
//!
//! # The path a keystroke takes
//!
//! ```text
//! your terminal
//!   → reach: raw-mode stdin → PtyData{pty,data} on a §6 `pty/<n>` channel
//!   → hub:   records it as `pty.in` under YOUR principal (I5) and fans it
//!            out LIVE (§4.2 — transport, no Event.seq)
//!   → noded: the lease holder's node session picks the live payload up
//!   → workspaced: writes it into the guest's PTY (ADR-0031 `pty.input`)
//!   → the shell
//! ```
//!
//! and back the other way as `pty.out`, which additionally becomes a record:
//! noded ingests it on its events channel, hub sequences it at durable commit
//! and it lands in an R2 segment (ADR-0022). Everything you see on screen is
//! therefore *live* (immediate, tentative); everything at or below the durable
//! watermark this session prints on detach is *recorded* (survives a SIGKILL).
//!
//! # Terminal handling
//!
//! - **Raw mode** via `stty`, not a termios crate: ADR-0031 set the precedent
//!   (`pty.resize` shells out rather than reach for `unsafe`), the workspace
//!   forbids `unsafe` outside blockd/UFFD (§12), and this keeps `reach` free
//!   of a libc dependency for something that runs twice per session.
//! - **Ctrl-C passes through** — in raw mode the terminal generates no local
//!   SIGINT, so `\x03` travels to the guest and interrupts the *remote*
//!   process, which is the only sane behavior for a remote shell.
//! - **Detach is [`DETACH_KEY`] (Ctrl-])**, telnet-style, precisely because
//!   Ctrl-C is spoken for. Detaching never touches the workspace: the shell,
//!   the harness and the VM keep running (§0 product truth #1 — a workspace is
//!   not a session).
//! - **SIGWINCH** re-sends the window size. §6 defines no control message hub
//!   relays and hub interprets no payload (§5.2), so a resize travels as an
//!   ordinary pty payload at the reserved index [`PTY_CONTROL`] — the same
//!   encoding `bins/noded/src/hubclient.rs` decodes, pinned byte-for-byte by
//!   the tests in both files.
//!
//! # Non-interactive use (what the e2e drives)
//!
//! With a non-tty stdin, no terminal is touched: stdin is forwarded verbatim
//! until EOF, output keeps streaming for [`AttachOptions::linger`], and the
//! session detaches. The wire path is IDENTICAL — the e2e proves the same code
//! a human drives, not a second implementation of it.

use std::io::{IsTerminal as _, Write as _};
use std::time::{Duration, Instant};

use anyhow::Context as _;
use proto::framing::{channel, PROTOCOL_VERSION};
use proto::handshake::{self, ChannelKind, ChannelMap};
use proto::{codec, events, wire};
use tokio::io::AsyncReadExt as _;
use tokio::sync::mpsc;

use crate::tail::{parse_durable_through, DURABLE_WATERMARK_CAP, INCARNATION_CAP_PREFIX};
use crate::transport::{ClientTransport, TlsTrust};

/// Detach key: Ctrl-] (`0x1d`). Ctrl-C is passed through to the guest, so the
/// escape has to be something else; Ctrl-] is what telnet trained everyone on.
pub const DETACH_KEY: u8 = 0x1d;

/// Reserved `PtyData.pty` index marking a pty-channel payload as CONTROL
/// rather than terminal bytes.
///
/// **Mirrors `noded::hubclient::PTY_CONTROL`.** The two are pinned to each
/// other by [`tests::resize_encoding_is_pinned`] here and
/// `control_frames_round_trip_and_reject_noise` there — the same
/// duplicate-and-pin discipline ADR-0031 uses for the guest control plane,
/// for the same reason: neither binary should have to link the other.
pub const PTY_CONTROL: u32 = u32::MAX;

/// The one control verb v1 defines.
pub const CONTROL_RESIZE: &str = "resize";

/// `Presence.display` a NODE session reports (hub's `SessionRole::Node`).
/// A client waits for this before typing — see [`AttachOptions::wait_for_node`].
pub const NODE_PRESENCE_DISPLAY: &str = "node";

/// Build the resize control payload: `resize <pty> <cols> <rows>`, ASCII, so
/// it reads plainly in a captured segment.
#[must_use]
pub fn encode_resize(pty: u32, cols: u16, rows: u16) -> wire::PtyData {
    wire::PtyData {
        data: format!("{CONTROL_RESIZE} {pty} {cols} {rows}").into_bytes(),
        pty: PTY_CONTROL,
    }
}

/// Terminal input payload for `pty`.
#[must_use]
pub fn encode_input(pty: u32, data: Vec<u8>) -> wire::PtyData {
    wire::PtyData { data, pty }
}

/// `open <cols> <rows>` (ADR-0063): ask the node for another PTY running the
/// workspace's own command. The reply arrives as a `PtyData{pty: control}`
/// frame: `opened <n> <cols> <rows>`.
pub const CONTROL_OPEN: &str = "open";

/// `list` (ADR-0063): the roster of live PTYs. Reply: `ptys <n> <n> ...`.
pub const CONTROL_LIST: &str = "list";

/// Build the open control payload (pinned to noded's parser by tests on
/// both sides, exactly as `encode_resize` is).
#[must_use]
pub fn encode_open(cols: u16, rows: u16) -> wire::PtyData {
    wire::PtyData {
        data: format!("{CONTROL_OPEN} {cols} {rows}").into_bytes(),
        pty: PTY_CONTROL,
    }
}

/// Build the list control payload.
#[must_use]
pub fn encode_list() -> wire::PtyData {
    wire::PtyData {
        data: CONTROL_LIST.as_bytes().to_vec(),
        pty: PTY_CONTROL,
    }
}

/// Parse the node's reply to an `open` (ADR-0063): `opened <n> <cols> <rows>`
/// is `Some(Ok(n))`, `open-refused <reason>` is `Some(Err(reason))`, anything
/// else is `None` (another control text — skipped, never fatal, §6).
///
/// Pinned to `noded::hubclient::open_requested_pty`'s exact wording by
/// [`tests::open_and_list_replies_parse_the_nodes_exact_wording`].
#[must_use]
pub fn parse_open_reply(data: &[u8]) -> Option<Result<u32, String>> {
    let text = std::str::from_utf8(data).ok()?;
    if let Some(rest) = text.strip_prefix("opened ") {
        let n = rest.split_whitespace().next()?.parse().ok()?;
        return Some(Ok(n));
    }
    if let Some(rest) = text.strip_prefix("open-refused") {
        return Some(Err(rest.trim().to_owned()));
    }
    None
}

/// Parse the node's reply to a `list`: `ptys <n> <n> …` (bare `ptys` is an
/// empty roster — a guest with no listable terminals answers exactly that).
/// Pinned to `noded::hubclient::list_ptys`'s wording alongside
/// [`parse_open_reply`].
#[must_use]
pub fn parse_ptys_reply(data: &[u8]) -> Option<Vec<u32>> {
    let text = std::str::from_utf8(data).ok()?;
    let rest = text.strip_prefix("ptys")?;
    Some(
        rest.split_whitespace()
            .filter_map(|t| t.parse().ok())
            .collect(),
    )
}

/// Options for [`attach`].
#[derive(Debug, Clone)]
pub struct AttachOptions {
    /// Which `pty/<n>` to attach to.
    pub pty: u32,
    /// Open a NEW terminal (ADR-0063 `open`) and attach to the index the
    /// node answers with, instead of attaching to `pty`.
    pub open_new: bool,
    /// What the `quic://` dial trusts (OS roots, explicit anchors, dev pin).
    pub trust: TlsTrust,
    /// Non-interactive only: keep streaming output this long after stdin EOF,
    /// so a scripted command's output is actually observed.
    pub linger: Duration,
    /// Force non-interactive behavior even on a tty (tests).
    pub no_raw: bool,
    /// Wait up to this long for the lease-holding node to join the session
    /// before forwarding the first keystroke. See [`attach`].
    pub wait_for_node: Duration,
}

impl Default for AttachOptions {
    fn default() -> Self {
        AttachOptions {
            pty: 0,
            open_new: false,
            trust: TlsTrust::default(),
            linger: Duration::from_secs(2),
            no_raw: false,
            wait_for_node: Duration::from_secs(30),
        }
    }
}

/// What a finished attach saw. Printed on detach and asserted by the e2e.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AttachSummary {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    /// Highest `durable through seq N` hub reported: everything at or below
    /// it is in an R2 segment (ADR-0022).
    pub durable_through: u64,
    /// Wall time the session lasted.
    pub duration_ms: u64,
    /// Did the user press the detach key (vs stdin EOF / hub closing)?
    pub detached_by_key: bool,
}

/// Run one interactive attach. Returns when the user detaches, stdin ends
/// (plus linger), or hub closes the session.
pub async fn attach(
    hub_url: &str,
    workspace: &str,
    token: &[u8],
    options: &AttachOptions,
) -> anyhow::Result<AttachSummary> {
    let started = Instant::now();
    let interactive = !options.no_raw && std::io::stdin().is_terminal();

    let mut session = PtySession::connect(hub_url, workspace, token, options).await?;
    eprintln!(
        "attached to {workspace} (protocol v{}, hub incarnation {}, pty {}, trusting {})",
        session.version,
        session.incarnation.as_deref().unwrap_or("<unreported>"),
        options.pty,
        options.trust.describe(),
    );
    if interactive {
        eprintln!("  detach with Ctrl-]  ·  Ctrl-C goes to the workspace");
    }

    // Raw mode LAST, so every message above is still line-formatted, and via
    // a guard so the terminal is restored on any exit path including a panic.
    let _raw = if interactive {
        Some(RawMode::enter()?)
    } else {
        None
    };

    // Tell the guest how big we are before anything is drawn. With
    // `--new` the size travels inside the `open` itself instead.
    let mut active_pty = options.pty;
    if !options.open_new {
        if let Some((cols, rows)) = terminal_size() {
            session.send_resize(active_pty, cols, rows).await?;
        }
    }

    // §4.2: the live channel is best-effort TRANSPORT. A keystroke sent
    // before the lease-holding node has opened its own session is fanned out
    // to nobody and is simply gone — it is recorded as `pty.in` (so the log is
    // honest about what was typed) but no shell ever sees it. So wait for the
    // node to join before forwarding the first byte. This only ever DELAYS
    // input; it never drops any, and it is bounded.
    if !options.wait_for_node.is_zero() {
        match session.await_node(options.wait_for_node).await? {
            true => eprintln!("  the workspace's node is listening"),
            false => eprintln!(
                "  WARNING: no node joined within {:?} — early keystrokes may reach no shell",
                options.wait_for_node
            ),
        }
    }

    // ADR-0063: ask the node for a fresh terminal, then attach to the index
    // it answers with. After the node join above, because the node is what
    // answers control verbs — an `open` sent to nobody opens nothing.
    if options.open_new {
        let (cols, rows) = terminal_size().unwrap_or((80, 24));
        session.send_payload(&encode_open(cols, rows)).await?;
        active_pty = session
            .await_open_reply(Duration::from_secs(15))
            .await
            .context("opening a new pty (ADR-0063)")?;
        eprintln!("  opened pty {active_pty}");
    }

    let mut stdin_rx = spawn_stdin_reader();
    let mut winch = window_change_stream(interactive);
    let mut summary = AttachSummary::default();
    let mut stdout = std::io::stdout();
    let mut stdin_done = false;
    let mut deadline: Option<tokio::time::Instant> = None;

    loop {
        tokio::select! {
            // Local keystrokes → the workspace.
            chunk = stdin_rx.recv(), if !stdin_done => match chunk {
                Some(bytes) => {
                    // The detach key never reaches the wire: it is a local
                    // decision about this session, not input for the guest.
                    if interactive {
                        if let Some(cut) = bytes.iter().position(|b| *b == DETACH_KEY) {
                            if cut > 0 {
                                summary.bytes_sent += session
                                    .send_input(active_pty, bytes[..cut].to_vec())
                                    .await? as u64;
                            }
                            summary.detached_by_key = true;
                            break;
                        }
                    }
                    summary.bytes_sent += session.send_input(active_pty, bytes).await? as u64;
                }
                None => {
                    // EOF. An interactive session ends; a scripted one keeps
                    // reading output for `linger` so the command's reply is
                    // actually seen.
                    stdin_done = true;
                    if interactive {
                        break;
                    }
                    deadline = Some(tokio::time::Instant::now() + options.linger);
                }
            },
            // The workspace → our screen.
            frame = session.recv() => match frame? {
                Some(PtyItem::Output { pty, data }) if pty == active_pty => {
                    summary.bytes_received += data.len() as u64;
                    stdout.write_all(&data).context("writing to stdout")?;
                    stdout.flush().context("flushing stdout")?;
                }
                Some(PtyItem::Output { .. }) => {}
                Some(PtyItem::DurableThrough(seq)) => {
                    summary.durable_through = summary.durable_through.max(seq);
                }
                Some(PtyItem::Joined { .. }) => {}
                Some(PtyItem::Refused(error)) => {
                    anyhow::bail!("hub closed the pty channel: {error}");
                }
                None => break, // hub closed the session
            },
            _ = winch.recv() => {
                if let Some((cols, rows)) = terminal_size() {
                    session.send_resize(active_pty, cols, rows).await?;
                }
            }
            () = sleep_until(deadline), if deadline.is_some() => break,
        }
    }

    summary.duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    Ok(summary)
}

/// `reachpad attach <ws> --list` (ADR-0063): connect, ask the node for the
/// roster of live PTYs, return it. Uses the same session path as an attach —
/// including the node-join wait, because the node is what answers.
pub async fn list_ptys(
    hub_url: &str,
    workspace: &str,
    token: &[u8],
    options: &AttachOptions,
) -> anyhow::Result<Vec<u32>> {
    let mut session = PtySession::connect(hub_url, workspace, token, options).await?;
    if !options.wait_for_node.is_zero() && !session.await_node(options.wait_for_node).await? {
        anyhow::bail!(
            "no node joined within {:?} — nothing is listening to answer a list",
            options.wait_for_node
        );
    }
    session.send_payload(&encode_list()).await?;
    session
        .await_roster(Duration::from_secs(15))
        .await
        .context("listing PTYs (ADR-0063)")
}

/// `tokio::time::sleep_until` for an `Option` deadline; never resolves when
/// the deadline is absent (the branch is disabled by its `if` guard anyway,
/// but a future must still exist to build the select).
async fn sleep_until(deadline: Option<tokio::time::Instant>) {
    match deadline {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
    }
}

/// One item off the attached session.
enum PtyItem {
    Output {
        pty: u32,
        data: Vec<u8>,
    },
    DurableThrough(u64),
    /// A principal joined the session. `display` carries its role, and the
    /// lease-holding node reports `node` (hub's `SessionRole::Node`).
    Joined {
        display: String,
    },
    Refused(String),
}

/// The §6 session behind an attach: ctl + one pty channel + the events
/// channel (watermarks only).
struct PtySession {
    transport: ClientTransport,
    pty_channel: u16,
    events_channel: u16,
    presence_channel: u16,
    version: u32,
    incarnation: Option<String>,
    watermarks: bool,
    out_seq: u64,
    last_recv: u64,
}

impl PtySession {
    async fn connect(
        hub_url: &str,
        workspace: &str,
        token: &[u8],
        options: &AttachOptions,
    ) -> anyhow::Result<Self> {
        let mut transport = ClientTransport::connect_with(hub_url, &options.trust).await?;

        let hello = handshake::client_hello(
            PROTOCOL_VERSION,
            PROTOCOL_VERSION,
            ["live-tail", DURABLE_WATERMARK_CAP],
            token.to_vec(),
            workspace.as_bytes().to_vec(),
        );
        transport
            .send_frame(codec::frame_message(channel::CTL, 1, 0, &hello)?)
            .await?;

        let first = transport
            .recv_frame()
            .await?
            .context("hub closed the connection during the handshake")?;
        anyhow::ensure!(
            first.channel == channel::CTL,
            "handshake reply arrived on channel {} instead of ctl",
            first.channel
        );
        let server: wire::ServerHello = codec::decode_message(&first)?;
        anyhow::ensure!(
            server.error.is_empty(),
            "hub refused the session: {}",
            server.error
        );
        let incarnation = server
            .capabilities
            .iter()
            .find_map(|c| c.strip_prefix(INCARNATION_CAP_PREFIX))
            .map(str::to_owned);
        let watermarks = server
            .capabilities
            .iter()
            .any(|c| c == DURABLE_WATERMARK_CAP);

        let mut channels = ChannelMap::new();
        let mut session = PtySession {
            transport,
            pty_channel: 0,
            events_channel: 0,
            presence_channel: 0,
            version: server.version,
            incarnation,
            watermarks,
            out_seq: 1,
            last_recv: first.seq,
        };

        let (pty_channel, open) = channels
            .open(ChannelKind::Pty(options.pty))
            .map_err(|e| anyhow::anyhow!("pty channel allocation failed: {e}"))?;
        session.open_channel(pty_channel, &open).await?;
        session.pty_channel = pty_channel;

        let (events_channel, open) = channels
            .open(ChannelKind::Events)
            .map_err(|e| anyhow::anyhow!("events channel allocation failed: {e}"))?;
        session.open_channel(events_channel, &open).await?;
        session.events_channel = events_channel;

        // Presence is how a client learns the lease-holding node is actually
        // listening (see `wait_for_node` in `attach`).
        let (presence_channel, open) = channels
            .open(ChannelKind::Presence)
            .map_err(|e| anyhow::anyhow!("presence channel allocation failed: {e}"))?;
        session.open_channel(presence_channel, &open).await?;
        session.presence_channel = presence_channel;

        // §6/ADR-0026: the pty channel gets its own QUIC stream, so a burst of
        // committed events can never delay a keystroke.
        session.transport.bind_channel_stream(pty_channel).await?;
        session
            .transport
            .bind_channel_stream(events_channel)
            .await?;
        Ok(session)
    }

    async fn open_channel(&mut self, id: u16, open: &wire::ChannelOpen) -> anyhow::Result<()> {
        self.out_seq += 1;
        let frame = codec::frame_message(channel::CTL, self.out_seq, self.last_recv, open)?;
        self.transport.send_frame(frame).await?;
        loop {
            let frame = self
                .transport
                .recv_frame()
                .await?
                .context("hub closed the connection before acking a channel")?;
            self.last_recv = frame.seq;
            if frame.channel != channel::CTL {
                continue;
            }
            let Ok(ack) = codec::decode_message::<wire::ChannelAck>(&frame) else {
                continue; // other ctl traffic: skipped, never fatal (§6)
            };
            if ack.channel == u32::from(id) {
                anyhow::ensure!(ack.accepted, "hub refused channel {id}: {}", ack.error);
                return Ok(());
            }
        }
    }

    /// Wait until the lease-holding node joins this workspace's session, or
    /// `budget` elapses. `true` = a node is present.
    ///
    /// Output that arrives while waiting is printed, because it is the
    /// workspace's boot chatter and a user should see it.
    async fn await_node(&mut self, budget: Duration) -> anyhow::Result<bool> {
        let deadline = tokio::time::Instant::now() + budget;
        let mut stdout = std::io::stdout();
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Ok(false);
            }
            match tokio::time::timeout(remaining, self.recv()).await {
                Err(_) => return Ok(false),
                Ok(Err(e)) => return Err(e),
                Ok(Ok(None)) => anyhow::bail!("hub closed the session while waiting for the node"),
                Ok(Ok(Some(PtyItem::Joined { display }))) if display == NODE_PRESENCE_DISPLAY => {
                    return Ok(true)
                }
                Ok(Ok(Some(PtyItem::Refused(e)))) => {
                    anyhow::bail!("hub closed the pty channel: {e}")
                }
                Ok(Ok(Some(PtyItem::Output { data, .. }))) => {
                    stdout.write_all(&data).context("writing to stdout")?;
                    stdout.flush().context("flushing stdout")?;
                }
                Ok(Ok(Some(_))) => {}
            }
        }
    }

    /// Wait for the node's answer to an `open` (ADR-0063): the new pty index,
    /// or the refusal it worded. Non-control output that arrives meanwhile is
    /// dropped — the caller is about to switch terminals anyway.
    async fn await_open_reply(&mut self, budget: Duration) -> anyhow::Result<u32> {
        let deadline = tokio::time::Instant::now() + budget;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            anyhow::ensure!(
                !remaining.is_zero(),
                "the node answered nothing within {budget:?}"
            );
            match tokio::time::timeout(remaining, self.recv()).await {
                Err(_) => anyhow::bail!("the node answered nothing within {budget:?}"),
                Ok(Err(e)) => return Err(e),
                Ok(Ok(None)) => {
                    anyhow::bail!("hub closed the session before the open was answered")
                }
                Ok(Ok(Some(PtyItem::Output { pty, data }))) if pty == PTY_CONTROL => {
                    match parse_open_reply(&data) {
                        Some(Ok(n)) => return Ok(n),
                        Some(Err(reason)) => anyhow::bail!("the node refused the open: {reason}"),
                        None => {} // another control text: skipped, never fatal (§6)
                    }
                }
                Ok(Ok(Some(_))) => {}
            }
        }
    }

    /// Wait for the node's answer to a `list`: the roster of live PTYs.
    async fn await_roster(&mut self, budget: Duration) -> anyhow::Result<Vec<u32>> {
        let deadline = tokio::time::Instant::now() + budget;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            anyhow::ensure!(
                !remaining.is_zero(),
                "the node answered nothing within {budget:?}"
            );
            match tokio::time::timeout(remaining, self.recv()).await {
                Err(_) => anyhow::bail!("the node answered nothing within {budget:?}"),
                Ok(Err(e)) => return Err(e),
                Ok(Ok(None)) => {
                    anyhow::bail!("hub closed the session before the list was answered")
                }
                Ok(Ok(Some(PtyItem::Output { pty, data }))) if pty == PTY_CONTROL => {
                    if let Some(roster) = parse_ptys_reply(&data) {
                        return Ok(roster);
                    }
                }
                Ok(Ok(Some(_))) => {}
            }
        }
    }

    async fn send_payload(&mut self, data: &wire::PtyData) -> anyhow::Result<usize> {
        self.out_seq += 1;
        let frame = codec::frame_message(self.pty_channel, self.out_seq, self.last_recv, data)?;
        let len = data.data.len();
        self.transport.send_frame(frame).await?;
        Ok(len)
    }

    async fn send_input(&mut self, pty: u32, bytes: Vec<u8>) -> anyhow::Result<usize> {
        let payload = encode_input(pty, bytes);
        self.send_payload(&payload).await
    }

    async fn send_resize(&mut self, pty: u32, cols: u16, rows: u16) -> anyhow::Result<()> {
        let payload = encode_resize(pty, cols, rows);
        self.send_payload(&payload).await.map(|_| ())
    }

    /// Next item; `None` on clean EOF. Frames we do not understand are
    /// skipped, never fatal (§6).
    async fn recv(&mut self) -> anyhow::Result<Option<PtyItem>> {
        loop {
            let Some(frame) = self.transport.recv_frame().await? else {
                return Ok(None);
            };
            self.last_recv = frame.seq;

            if frame.channel == channel::CTL {
                if let Ok(ack) = codec::decode_message::<wire::ChannelAck>(&frame) {
                    if !ack.accepted && ack.channel == u32::from(self.pty_channel) {
                        return Ok(Some(PtyItem::Refused(ack.error)));
                    }
                }
                continue;
            }

            if frame.channel == self.pty_channel {
                let Ok(event) = codec::decode_message::<wire::Event>(&frame) else {
                    continue;
                };
                // Only the workspace's OUTPUT is drawn. Our own `pty.in` is
                // fanned back to us (hub broadcasts live payloads to every
                // subscriber) and printing it would double every keystroke
                // the guest also echoes.
                if event.r#type != events::PTY_OUT {
                    continue;
                }
                let Ok(data) = codec::decode_payload::<wire::PtyData>(event.payload.clone()) else {
                    continue;
                };
                return Ok(Some(PtyItem::Output {
                    pty: data.pty,
                    data: data.data,
                }));
            }

            if frame.channel == self.presence_channel {
                let Ok(event) = codec::decode_message::<wire::Event>(&frame) else {
                    continue;
                };
                if event.r#type != events::PRESENCE_JOIN {
                    continue;
                }
                if let Ok(p) = codec::decode_payload::<wire::Presence>(event.payload.clone()) {
                    return Ok(Some(PtyItem::Joined { display: p.display }));
                }
                continue;
            }

            if frame.channel == self.events_channel && self.watermarks {
                if let Ok(note) = codec::decode_message::<wire::WsLifecycle>(&frame) {
                    if let Some(seq) = parse_durable_through(&note.transition) {
                        return Ok(Some(PtyItem::DurableThrough(seq)));
                    }
                }
            }
        }
    }
}

/// Read stdin on its own task: `tokio::io::Stdin` reads on a blocking pool
/// and is not cancel-safe, so it must never sit in a `select!` arm directly.
fn spawn_stdin_reader() -> mpsc::Receiver<Vec<u8>> {
    let (tx, rx) = mpsc::channel::<Vec<u8>>(64);
    tokio::spawn(async move {
        let mut stdin = tokio::io::stdin();
        let mut buf = [0u8; 4096];
        loop {
            match stdin.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if tx.send(buf[..n].to_vec()).await.is_err() {
                        break;
                    }
                }
            }
        }
    });
    rx
}

/// SIGWINCH stream; a never-firing one when not interactive.
fn window_change_stream(interactive: bool) -> WinchStream {
    if !interactive {
        return WinchStream(None);
    }
    match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change()) {
        Ok(sig) => WinchStream(Some(sig)),
        Err(e) => {
            tracing::debug!(error = %e, "SIGWINCH unavailable; resizes will not be forwarded");
            WinchStream(None)
        }
    }
}

struct WinchStream(Option<tokio::signal::unix::Signal>);

impl WinchStream {
    async fn recv(&mut self) {
        match &mut self.0 {
            Some(sig) => {
                sig.recv().await;
            }
            None => std::future::pending().await,
        }
    }
}

/// Current terminal size as `(cols, rows)` via `stty size`.
fn terminal_size() -> Option<(u16, u16)> {
    let out = std::process::Command::new("stty")
        .arg("size")
        .stdin(std::process::Stdio::inherit())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    parse_stty_size(&String::from_utf8_lossy(&out.stdout))
}

/// `stty size` prints `<rows> <cols>`; we speak `(cols, rows)`.
fn parse_stty_size(text: &str) -> Option<(u16, u16)> {
    let mut parts = text.split_whitespace();
    let rows: u16 = parts.next()?.parse().ok()?;
    let cols: u16 = parts.next()?.parse().ok()?;
    (rows > 0 && cols > 0).then_some((cols, rows))
}

/// Raw mode, entered with `stty` and restored on drop — including on a panic
/// or an error return, which is the whole reason it is a guard.
struct RawMode {
    saved: String,
}

impl RawMode {
    fn enter() -> anyhow::Result<Self> {
        let saved = std::process::Command::new("stty")
            .arg("-g")
            .stdin(std::process::Stdio::inherit())
            .output()
            .context("running `stty -g` (is stdin a terminal?)")?;
        anyhow::ensure!(
            saved.status.success(),
            "`stty -g` failed: {}",
            String::from_utf8_lossy(&saved.stderr).trim()
        );
        let saved = String::from_utf8_lossy(&saved.stdout).trim().to_owned();
        let set = std::process::Command::new("stty")
            .args(["raw", "-echo"])
            .stdin(std::process::Stdio::inherit())
            .status()
            .context("running `stty raw -echo`")?;
        anyhow::ensure!(set.success(), "`stty raw -echo` failed");
        Ok(RawMode { saved })
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        let _ = std::process::Command::new("stty")
            .arg(&self.saved)
            .stdin(std::process::Stdio::inherit())
            .status();
        // The guest's last output may have left the cursor mid-line.
        let mut stdout = std::io::stdout();
        let _ = stdout.write_all(b"\r\n");
        let _ = stdout.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message as _;

    /// The REPLY half of the ADR-0063 control contract, pinned to the exact
    /// strings `noded::hubclient::{open_requested_pty, list_ptys}` produce —
    /// the same duplicate-and-pin discipline as the encoding tests below.
    #[test]
    fn open_and_list_replies_parse_the_nodes_exact_wording() {
        // noded: format!("opened {index} {cols} {rows}")
        assert_eq!(parse_open_reply(b"opened 3 120 40"), Some(Ok(3)));
        // noded: format!("open-refused pty-limit {MAX_WORKSPACE_PTYS}")
        assert_eq!(
            parse_open_reply(b"open-refused pty-limit 8"),
            Some(Err("pty-limit 8".to_owned()))
        );
        assert_eq!(
            parse_open_reply(b"open-refused guest-unavailable"),
            Some(Err("guest-unavailable".to_owned()))
        );
        // Other control texts (a roster, a resize echo) are not open replies.
        assert_eq!(parse_open_reply(b"ptys 0 1"), None);
        assert_eq!(parse_open_reply(b"resize 0 80 24"), None);
        assert_eq!(parse_open_reply(b"opened"), None); // truncated

        // noded: format!("ptys {}", indices.join(" ")) — and bare "ptys" for
        // an empty roster (guest unavailable).
        assert_eq!(parse_ptys_reply(b"ptys 0 1 2"), Some(vec![0, 1, 2]));
        assert_eq!(parse_ptys_reply(b"ptys"), Some(vec![]));
        assert_eq!(parse_ptys_reply(b"opened 3 80 24"), None);
    }

    /// The control encoding is a WIRE CONTRACT with
    /// `bins/noded/src/hubclient.rs`, which decodes these exact bytes. Both
    /// sides pin them (ADR-0031's duplicate-and-pin discipline): change one
    /// and the other's test fails.
    #[test]
    fn resize_encoding_is_pinned() {
        let msg = encode_resize(0, 120, 40);
        assert_eq!(
            msg.pty, PTY_CONTROL,
            "control frames use the reserved index"
        );
        assert_eq!(msg.data, b"resize 0 120 40".to_vec());
        assert_eq!(PTY_CONTROL, u32::MAX);
        assert_eq!(CONTROL_RESIZE, "resize");

        // And the encoded protobuf, byte for byte.
        let msg = encode_resize(3, 80, 24);
        assert_eq!(
            msg.encode_to_vec(),
            {
                let mut expected = vec![0x0a, 14];
                expected.extend_from_slice(b"resize 3 80 24");
                expected.extend_from_slice(&[0x10, 0xff, 0xff, 0xff, 0xff, 0x0f]);
                expected
            },
            "PtyData{{data=\"resize 3 80 24\", pty=u32::MAX}}"
        );
    }

    /// Terminal bytes that happen to spell a control message are still just
    /// terminal bytes: the reserved pty index is what discriminates.
    #[test]
    fn input_is_never_encoded_as_control() {
        let typed = encode_input(0, b"resize 0 120 40".to_vec());
        assert_eq!(typed.pty, 0);
        assert_ne!(typed.pty, PTY_CONTROL);
    }

    #[test]
    fn stty_size_parses_rows_then_cols() {
        assert_eq!(parse_stty_size("40 120\n"), Some((120, 40)));
        assert_eq!(parse_stty_size("  24   80  "), Some((80, 24)));
        assert_eq!(parse_stty_size("0 0"), None, "a sizeless tty is no size");
        assert_eq!(parse_stty_size(""), None);
        assert_eq!(parse_stty_size("garbage"), None);
        assert_eq!(parse_stty_size("40"), None);
    }

    /// Ctrl-C must NOT be the detach key: it belongs to the guest (that is
    /// the point of raw mode), so detaching needs its own key.
    #[test]
    fn detach_key_is_not_ctrl_c() {
        assert_eq!(DETACH_KEY, 0x1d);
        assert_ne!(DETACH_KEY, 0x03, "Ctrl-C passes through to the workspace");
    }
}
