//! The ONE place wire spellings become the ones the surface promises.
//!
//! controld speaks `head_snapshot`, `origin.workspace_id` and milliseconds
//! since the epoch; the design speaks `head.snapshot`, `parent.workspace` and
//! RFC 3339. Doing that translation in each verb is how two verbs come to
//! disagree about what a field is called, so every verb renders through here.

use serde_json::{json, Value};

use crate::api::{Head, Limits, Parent, Status, Workspace};

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
    out.push(limits_line(&status.limits));
    out
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
}
