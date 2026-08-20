//! The ONE place wire spellings become the ones the surface promises.
//!
//! controld speaks `head_snapshot`, `origin.workspace_id` and milliseconds
//! since the epoch; the design speaks `head.snapshot`, `parent.workspace` and
//! RFC 3339. Doing that translation in each verb is how two verbs come to
//! disagree about what a field is called, so every verb renders through here.

use serde_json::{json, Value};

use crate::api::{DeviceSize, GuestDisk, Head, Limits, Parent, PortShare, Status, Workspace};

/// Epoch milliseconds as RFC 3339 UTC — the only timestamp spelling on this
/// surface. `0` means "not set", which renders as JSON null.
#[must_use]
pub fn time(ms: u64) -> Value {
    if ms == 0 {
        return Value::Null;
    }
    json!(rfc3339(ms))
}

/// Epoch milliseconds as `YYYY-MM-DDTHH:MM:SSZ`.
#[must_use]
pub fn rfc3339(ms: u64) -> String {
    let secs = ms / 1_000;
    let (y, m, d) = civil_from_days(secs / 86_400);
    let day = secs % 86_400;
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        day / 3_600,
        (day % 3_600) / 60,
        day % 60
    )
}

/// Days since 1970-01-01 → (year, month, day). Howard Hinnant's civil-from-
/// days, which is exact for every date this CLI can be handed and needs no
/// calendar crate.
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z % 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// A rough, readable "how long ago" for a human line.
#[must_use]
pub fn ago(then_ms: u64, now_ms: u64) -> String {
    if then_ms == 0 || now_ms <= then_ms {
        return "just now".to_owned();
    }
    let secs = (now_ms - then_ms) / 1_000;
    match secs {
        0..=59 => format!("{secs}s ago"),
        60..=3_599 => format!("{}m ago", secs / 60),
        3_600..=86_399 => format!("{}h ago", secs / 3_600),
        _ => format!("{}d ago", secs / 86_400),
    }
}

/// A label a person can read. An empty one is a workspace nobody named, and
/// the id is the handle anyway.
#[must_use]
pub fn label(name: &str) -> &str {
    if name.is_empty() {
        "—"
    } else {
        name
    }
}

pub fn head_json(head: Option<&Head>) -> Value {
    match head {
        None => Value::Null,
        Some(h) => {
            let mut v = json!({ "snapshot": h.snapshot, "kind": h.kind });
            if let Some(sealed) = h.sealed_at_ms {
                v["sealed_at"] = time(sealed);
            }
            v
        }
    }
}

pub fn parent_json(parent: Option<&Parent>) -> Value {
    match parent {
        None => Value::Null,
        Some(p) => json!({ "workspace": p.workspace, "snapshot": p.snapshot }),
    }
}

pub fn limits_json(limits: &Limits) -> Value {
    json!({
        "max_workspaces": limits.max_workspaces,
        "max_concurrent": limits.max_concurrent,
        "live_workspaces": limits.live_workspaces,
    })
}

/// One `list` row.
pub fn workspace_json(ws: &Workspace) -> Value {
    json!({
        "id": ws.id,
        "name": ws.name,
        "state": ws.state.clone().unwrap_or_else(|| "unknown".to_owned()),
        "created_at": time(ws.created_at_ms),
        "archived_at": ws.archived_at_ms.map_or(Value::Null, time),
        "head": head_json(ws.head.as_ref()),
        "parent": parent_json(ws.parent.as_ref()),
    })
}

/// One port share (ADR-0103) as `--json` renders it.
///
/// `url` is a `null` rather than a missing key when the fleet composed none:
/// a caller that keys on it can tell "this fleet has no preview origin" from
/// "this token has no link", and there is only ever the first.
pub fn port_share_json(share: &PortShare) -> Value {
    json!({
        "port": share.port,
        "workspace": share.workspace,
        "token": share.token,
        "url": share.url,
        "created_at": time(share.created_at_ms),
        // `null` on every verb but `revoke`, where it is the outcome: a
        // scripted caller reads the fleet's own stamp rather than its own
        // clock.
        "revoked_at": share.revoked_at_ms.map_or(Value::Null, time),
    })
}

/// What to hand a person for one share: the link the fleet composed, or — when
/// it composed none — the bare token, said as the incomplete thing it is.
///
/// The alternative was to build the URL here from a default origin. That would
/// print a link that resolves nowhere for every deployment whose preview plane
/// is not `app.reachpad.dev`, and a link that does not work is worse than a
/// token plus a sentence naming the variable an operator has to set.
pub fn port_share_target(share: &PortShare) -> String {
    match &share.url {
        Some(url) => url.clone(),
        // No "see below": this string is also a `ports list` row, where there
        // is no below. The sentence that explains it is
        // [`port_share_no_origin`], printed once by the verb that has room.
        None => format!("token {} — no link", share.token),
    }
}

/// The sentence for a fleet that minted the share and cannot say where it is
/// reachable. `None` when the fleet composed a link, which is the ordinary
/// case and needs no explanation.
pub fn port_share_no_origin(share: &PortShare) -> Option<String> {
    share.url.is_none().then(|| {
        "  this fleet has no preview origin set, so it cannot compose the link: an operator \
         sets REACHPAD_PREVIEW_ORIGIN on controld (and the preview plane on hub)"
            .to_owned()
    })
}

/// One `ports list` row: the port, then where it is reachable.
pub fn port_share_line(share: &PortShare, now_ms: u64) -> String {
    format!(
        "{:<6} {}  (opened {})",
        share.port,
        port_share_target(share),
        ago(share.created_at_ms, now_ms)
    )
}

/// The `status` payload.
pub fn status_json(status: &Status) -> Value {
    json!({
        "id": status.id,
        "name": status.name,
        "state": status.state,
        // A lease with no node is the one an older fleet cannot report at
        // all: it says `unknown`, which is neither "none" nor a node name.
        "lease": match &status.lease {
            None => Value::Null,
            Some(l) if l.node.is_empty() => json!("unknown"),
            Some(l) => json!({ "node": l.node, "expires_at": time(l.expires_at_ms) }),
        },
        "head": head_json(status.head.as_ref()),
        "parent": parent_json(status.parent.as_ref()),
        "snapshots": status.snapshots,
        "forks": status.forks,
        "idle_pause_seconds": status.idle_pause_seconds,
        "limits": limits_json(&status.limits),
        // WP-CP.4, null against a fleet that does not report it. A machine
        // caller can tell "no such field" from a number; it must never be
        // handed a zero it would read as an empty disk.
        "guest_disk": match &status.guest_disk {
            None => Value::Null,
            Some(g) => json!({
                "free_bytes": g.free_bytes,
                "total_bytes": g.total_bytes,
            }),
        },
        // Null against a fleet that does not report it (WP-CP.3): a script
        // that keys on this can tell "no such field" from a number.
        "disk": match &status.device {
            None => Value::Null,
            Some(d) => json!({
                "device_bytes": d.workspace_bytes,
                "new_workspace_device_bytes": d.new_workspace_bytes,
            }),
        },
        "created_at": time(status.created_at_ms),
        "archived_at": status.archived_at_ms.map_or(Value::Null, time),
    })
}

/// The human `status` block.
pub fn status_lines(status: &Status, now_ms: u64) -> Vec<String> {
    let mut out = vec![
        format!("{}  {}", status.id, label(&status.name)),
        format!("  state:     {}", status.state),
    ];
    match &status.lease {
        Some(l) if l.node.is_empty() => out.push("  lease:     unknown".to_owned()),
        Some(l) => out.push(format!(
            "  lease:     {} (renewed {})",
            l.node,
            ago(l.heartbeat_at_ms, now_ms)
        )),
        None => out.push("  lease:     none".to_owned()),
    }
    match &status.head {
        Some(h) => out.push(format!(
            "  last save: {} ({}{})",
            h.snapshot,
            h.kind,
            h.sealed_at_ms
                .map(|s| format!(", {}", ago(s, now_ms)))
                .unwrap_or_default()
        )),
        None => out.push("  last save: none — it has never been saved".to_owned()),
    }
    if let Some(p) = &status.parent {
        out.push(format!("  forked from: {}", p.workspace));
    }
    out.push(format!(
        "  saves: {}   forks: {}   idle pause: {}s",
        status.snapshots, status.forks, status.idle_pause_seconds
    ));
    if let Some(d) = &status.device {
        out.push(disk_line(d));
    }
    // WP-CP.4: the condition, visible BEFORE it bites. Its own line rather
    // than a clause on the disk line, because the two are different facts
    // from different sources — the size is a row in Postgres, the free space
    // is the guest's own `statvfs` — and a fleet can report either without
    // the other.
    if let Some(g) = &status.guest_disk {
        out.push(free_line(g));
    }
    out.push(limits_line(&status.limits));
    out
}

/// Binary units, the units a `df` inside the guest will agree with. Whole
/// numbers where the value is a whole number of units (a 20 GiB disk is not
/// "20.0 GiB", and 4.5 GiB is not "4 GiB").
pub fn gib(bytes: u64) -> String {
    const GIB: u64 = 1024 * 1024 * 1024;
    const MIB: u64 = 1024 * 1024;
    if bytes >= GIB {
        let whole = bytes / GIB;
        let tenths = (bytes % GIB) * 10 / GIB;
        if tenths == 0 {
            format!("{whole} GiB")
        } else {
            format!("{whole}.{tenths} GiB")
        }
    } else {
        format!("{} MiB", bytes.div_ceil(MIB))
    }
}

/// The disk line, and the one sentence that stops "disks are 20 GB now" from
/// being read as fleet-wide (WP-CP.3).
///
/// A workspace keeps the size it was created with: there is no in-place grow
/// anywhere in the platform, because the ext4 superblock lives inside the
/// workspace's own image and was written once. So when this workspace is
/// smaller than what a new one gets, the CLI says both numbers and says what
/// the difference means — the alternative is a customer reading a release
/// note and looking at a disk that disagrees with it.
pub fn disk_line(d: &DeviceSize) -> String {
    if d.workspace_bytes >= d.new_workspace_bytes {
        format!("  disk:      {}", gib(d.workspace_bytes))
    } else {
        format!(
            "  disk:      {} — new workspaces get {}; existing disks are not grown, so a \
             bigger one means `reachpad create` (a fork inherits this size)",
            gib(d.workspace_bytes),
            gib(d.new_workspace_bytes)
        )
    }
}

/// The free-space line (WP-CP.4), and a warning when the workspace is close
/// enough to full that the next build is the one that finds out.
///
/// The threshold mirrors `workspaced::disk::is_full` — the guest's own
/// judgement, restated here because this line is rendered from figures rather
/// than from the guest's verdict. They must move together: a `status` that
/// looks calm right up to the moment a build fails with `workspace_disk_full`
/// is the confusion this work package exists to end, one step earlier.
pub fn free_line(g: &GuestDisk) -> String {
    const FLOOR: u64 = 64 * 1024 * 1024;
    let full = g.total_bytes > 0 && g.free_bytes <= FLOOR.max(g.total_bytes / 100);
    format!(
        "  free:      {} of {}{}",
        gib(g.free_bytes),
        gib(g.total_bytes),
        if full {
            " — this workspace is out of room; commands will start failing"
        } else {
            ""
        }
    )
}

pub fn limits_line(limits: &Limits) -> String {
    let cap = |v: Option<u64>| v.map_or_else(|| "?".to_owned(), |n| n.to_string());
    format!(
        "  limits: {} of {} running, {} workspaces allowed",
        limits.live_workspaces,
        cap(limits.max_concurrent),
        cap(limits.max_workspaces)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps_render_as_one_spelling() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(1_755_108_131_000), "2025-08-13T18:02:11Z");
        // Leap day, and a second that is not a whole minute.
        assert_eq!(rfc3339(1_709_209_845_000), "2024-02-29T12:30:45Z");
        assert_eq!(time(0), Value::Null);
    }

    #[test]
    fn an_unnamed_workspace_renders_as_a_dash_and_the_id_is_the_handle() {
        assert_eq!(label(""), "—");
        assert_eq!(label("trial-1"), "trial-1");
    }

    #[test]
    fn elapsed_time_reads_like_a_person_wrote_it() {
        let now = 100 * 86_400_000;
        assert_eq!(ago(now - 30_000, now), "30s ago");
        assert_eq!(ago(now - 600_000, now), "10m ago");
        assert_eq!(ago(now - 7_200_000, now), "2h ago");
        assert_eq!(ago(now - 3 * 86_400_000, now), "3d ago");
        assert_eq!(ago(0, now), "just now");
    }

    #[test]
    fn the_json_uses_the_designs_names_not_the_wires() {
        let ws = Workspace {
            id: "ws-601".into(),
            name: String::new(),
            forks: 0,
            state: Some("running".into()),
            head: Some(Head {
                snapshot: "snap-9d1".into(),
                kind: "disk+mem".into(),
                sealed_at_ms: None,
            }),
            parent: Some(Parent {
                workspace: "ws-500".into(),
                snapshot: Some("snap-8a0".into()),
            }),
            created_at_ms: 1_755_108_131_000,
            archived_at_ms: None,
        };
        let v = workspace_json(&ws);
        assert_eq!(v["head"]["snapshot"], "snap-9d1");
        assert_eq!(v["parent"]["workspace"], "ws-500");
        assert_eq!(v["created_at"], "2025-08-13T18:02:11Z");
        assert_eq!(v["archived_at"], Value::Null);
        // No `_ms` field survives the rendering layer.
        assert!(!v.to_string().contains("_ms"), "{v}");
    }

    /// A share the fleet composed a link for, and the same one it did not.
    fn port_share(url: Option<&str>) -> PortShare {
        PortShare {
            token: "11111111-2222-4333-8444-555555555555".into(),
            workspace: "ws-601".into(),
            port: 3000,
            created_at_ms: 1_755_108_131_000,
            url: url.map(str::to_owned),
            revoked_at_ms: None,
        }
    }

    /// The link comes off the wire or it does not exist. A CLI that composed
    /// one from a default origin would print a working-looking link that
    /// resolves nowhere on every deployment but ours.
    #[test]
    fn a_link_the_fleet_did_not_compose_is_never_invented() {
        let with = port_share(Some(
            "https://app.reachpad.dev/11111111-2222-4333-8444-555555555555",
        ));
        assert_eq!(
            port_share_target(&with),
            "https://app.reachpad.dev/11111111-2222-4333-8444-555555555555"
        );
        assert!(port_share_no_origin(&with).is_none());
        assert_eq!(port_share_json(&with)["created_at"], "2025-08-13T18:02:11Z");

        let without = port_share(None);
        let target = port_share_target(&without);
        assert!(
            target.contains("11111111-2222-4333-8444-555555555555"),
            "{target}"
        );
        assert!(!target.contains("http"), "no invented origin: {target}");
        let said = port_share_no_origin(&without).expect("the missing variable is named");
        assert!(said.contains("REACHPAD_PREVIEW_ORIGIN"), "{said}");
        // A null, not a missing key: a caller can tell the two states apart.
        assert_eq!(port_share_json(&without)["url"], Value::Null);
        assert!(!port_share_json(&without).to_string().contains("_ms"));

        let line = port_share_line(&with, 1_755_108_131_000 + 7_200_000);
        assert!(line.starts_with("3000"), "{line}");
        assert!(line.contains("2h ago"), "{line}");

        // The revoke answer's own field: `null` everywhere else, and a
        // rendered time where the fleet stamped one. The verb whose whole
        // outcome is a timestamp has to hand it to a scripted caller.
        assert_eq!(port_share_json(&with)["revoked_at"], Value::Null);
        let mut revoked = port_share(None);
        revoked.revoked_at_ms = Some(1_755_108_131_000 + 3_600_000);
        assert_eq!(
            port_share_json(&revoked)["revoked_at"],
            "2025-08-13T19:02:11Z"
        );
        assert!(!port_share_json(&revoked).to_string().contains("_ms"));
    }

    /// A `Status` with nothing interesting in it but the disk (WP-CP.3).
    fn status_with(device: Option<DeviceSize>) -> Status {
        status_with_free(device, None)
    }

    /// …and the same with WP-CP.4's guest measurement.
    fn status_with_free(device: Option<DeviceSize>, guest_disk: Option<GuestDisk>) -> Status {
        Status {
            id: "ws-601".into(),
            name: "demo".into(),
            state: "paused".into(),
            lease: None,
            head: None,
            parent: None,
            snapshots: 0,
            forks: 0,
            idle_pause_seconds: 900,
            limits: Limits::default(),
            device,
            guest_disk,
            created_at_ms: 1_755_108_131_000,
            archived_at_ms: None,
        }
    }

    #[test]
    fn sizes_read_in_the_units_a_guest_df_will_agree_with() {
        assert_eq!(gib(20 * 1024 * 1024 * 1024), "20 GiB");
        assert_eq!(gib(4 * 1024 * 1024 * 1024), "4 GiB");
        // Not a whole number of GiB, and not rounded into one.
        assert_eq!(gib(4 * 1024 * 1024 * 1024 + 512 * 1024 * 1024), "4.5 GiB");
        assert_eq!(gib(256 * 1024 * 1024), "256 MiB");
    }

    #[test]
    fn a_workspace_smaller_than_the_current_default_is_told_why() {
        // The 4 GiB workspace: it must not read a 20 GiB release note and
        // conclude the platform lied to it. Both numbers, and what the
        // difference means.
        let line = disk_line(&DeviceSize {
            workspace_bytes: 4 * 1024 * 1024 * 1024,
            new_workspace_bytes: 20 * 1024 * 1024 * 1024,
        });
        assert!(line.contains("4 GiB"), "{line}");
        assert!(line.contains("20 GiB"), "{line}");
        assert!(line.contains("not grown"), "{line}");
        assert!(line.contains("reachpad create"), "{line}");

        // The 20 GiB workspace: one number, no lecture. A sentence every
        // customer sees on every status read is noise, and noise is how the
        // sentence that matters stops being read.
        let line = disk_line(&DeviceSize {
            workspace_bytes: 20 * 1024 * 1024 * 1024,
            new_workspace_bytes: 20 * 1024 * 1024 * 1024,
        });
        assert_eq!(line, "  disk:      20 GiB");
    }

    #[test]
    fn a_fleet_that_does_not_report_the_disk_is_not_given_one() {
        // Trap 41: absent is absent. An older controld reports no device
        // size at all, and the CLI must not turn that into "0 bytes" or into
        // the number it wishes were true.
        let status = status_with(None);
        assert_eq!(status_json(&status)["disk"], Value::Null);
        let lines = status_lines(&status, 1_755_108_131_000);
        assert!(
            !lines.iter().any(|l| l.contains("disk:")),
            "no disk line at all: {lines:?}"
        );

        let status = status_with(Some(DeviceSize {
            workspace_bytes: 20 * 1024 * 1024 * 1024,
            new_workspace_bytes: 20 * 1024 * 1024 * 1024,
        }));
        let v = status_json(&status);
        assert_eq!(v["disk"]["device_bytes"], json!(20 * 1024 * 1024 * 1024u64));
        assert_eq!(
            v["disk"]["new_workspace_device_bytes"],
            json!(20 * 1024 * 1024 * 1024u64)
        );
        let lines = status_lines(&status, 1_755_108_131_000);
        assert!(
            lines.iter().any(|l| l.contains("disk:      20 GiB")),
            "{lines:?}"
        );
    }

    // -- WP-CP.4: free space, and the fleet that does not report it --------

    const GIB_U: u64 = 1024 * 1024 * 1024;

    /// The point of the line: a filling workspace is visible in `status`
    /// BEFORE a build discovers it.
    #[test]
    fn free_space_is_shown_with_the_size_it_is_free_of() {
        let line = free_line(&GuestDisk {
            free_bytes: 18 * GIB_U,
            total_bytes: 20 * GIB_U,
        });
        assert!(line.contains("18 GiB"), "{line}");
        assert!(line.contains("20 GiB"), "{line}");
        assert!(
            !line.contains("out of room"),
            "18 GiB free is not a warning: {line}"
        );
    }

    /// The warning fires on the same threshold the guest judges an exec by
    /// (`workspaced::disk::is_full`: the greater of 64 MiB and 1%). If these
    /// two drift, `status` reads calm right up to the command that fails.
    #[test]
    fn a_workspace_at_the_guests_own_threshold_is_warned_about() {
        let warned = free_line(&GuestDisk {
            free_bytes: 200 * 1024 * 1024,
            total_bytes: 20 * GIB_U,
        });
        assert!(warned.contains("out of room"), "{warned}");
        // …and one byte the other side of it is not.
        let calm = free_line(&GuestDisk {
            free_bytes: 220 * 1024 * 1024,
            total_bytes: 20 * GIB_U,
        });
        assert!(!calm.contains("out of room"), "{calm}");
    }

    /// **The trap-41 posture, and the control for the two tests above.** A
    /// fleet that reports no measurement produces no line and a JSON `null` —
    /// never a zero, which a script would read as an empty disk, and never a
    /// `?`. This is today's every fleet, so it is the case that must be right.
    #[test]
    fn negative_control_a_fleet_that_reports_no_free_space_says_nothing() {
        let status = status_with_free(None, None);
        let lines = status_lines(&status, 1_755_108_131_000);
        assert!(
            !lines.iter().any(|l| l.contains("free:")),
            "a free line was printed for a fleet that reported nothing: {lines:?}"
        );
        assert_eq!(status_json(&status)["guest_disk"], Value::Null);

        // …and with a measurement, both surfaces carry it.
        let reported = status_with_free(
            None,
            Some(GuestDisk {
                free_bytes: 3 * GIB_U,
                total_bytes: 20 * GIB_U,
            }),
        );
        assert!(status_lines(&reported, 1_755_108_131_000)
            .iter()
            .any(|l| l.contains("free:      3 GiB of 20 GiB")));
        assert_eq!(
            status_json(&reported)["guest_disk"]["free_bytes"],
            json!(3 * GIB_U)
        );
    }
}
