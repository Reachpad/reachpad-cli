//! Offline token inspection: print the §7.2 facts
//! (principal/workspace/role/exp) without verifying.
//!
//! Uses `UnverifiedBiscuit` — a pure parse, no root key, no signature-chain
//! authorization. This is deliberately NOT `authz::verify`: inspection must
//! work offline on any token the user already holds. Nothing secret is
//! revealed: a Biscuit's block source (facts + checks) is exactly what its
//! holder can already read out of the token bytes.

use anyhow::Context;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use biscuit_auth::UnverifiedBiscuit;

/// The facts pulled from a token's authority block, plus every block's
/// datalog source (attenuation blocks carry only checks — §7.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inspection {
    pub principal: Option<String>,
    pub workspace: Option<String>,
    pub role: Option<String>,
    pub exp_ms: Option<u64>,
    /// Number of attenuation blocks appended after the authority block.
    pub attenuation_blocks: usize,
    /// Datalog source of every block, authority first.
    pub block_sources: Vec<String>,
}

/// Parse a base64 Biscuit and extract its facts. No verification happens
/// here — expired, tampered-after-signing, or foreign-root tokens still
/// print (the point of offline inspection); only unparseable bytes fail.
pub fn inspect_b64(token_b64: &str) -> anyhow::Result<Inspection> {
    let bytes = BASE64
        .decode(token_b64.trim())
        .context("token is not valid base64")?;
    let token = UnverifiedBiscuit::from(&bytes).context("bytes do not parse as a Biscuit token")?;
    let mut block_sources = Vec::with_capacity(token.block_count());
    for i in 0..token.block_count() {
        block_sources.push(
            token
                .print_block_source(i)
                .with_context(|| format!("printing block {i}"))?,
        );
    }
    let authority = block_sources.first().map(String::as_str).unwrap_or("");
    Ok(Inspection {
        principal: fact_str(authority, "principal"),
        workspace: fact_str(authority, "workspace"),
        role: fact_str(authority, "role"),
        exp_ms: fact_u64(authority, "exp"),
        attenuation_blocks: block_sources.len().saturating_sub(1),
        block_sources,
    })
}

/// Extract `name("value")` from datalog source (§7.2 fact shape).
fn fact_str(source: &str, name: &str) -> Option<String> {
    fact_inner(source, name).and_then(|inner| {
        inner
            .strip_prefix('"')
            .and_then(|r| r.strip_suffix('"'))
            .map(str::to_owned)
    })
}

/// Extract `name(12345)` from datalog source.
fn fact_u64(source: &str, name: &str) -> Option<u64> {
    fact_inner(source, name).and_then(|inner| inner.parse().ok())
}

/// The text between the parens of a `name(...)` fact line, if present.
fn fact_inner<'s>(source: &'s str, name: &str) -> Option<&'s str> {
    source.lines().find_map(|line| {
        let line = line.trim().trim_end_matches(';');
        let rest = line.strip_prefix(name)?;
        rest.strip_prefix('(')?.strip_suffix(')')
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mint_b64(role: authz::Role, exp_ms: u64) -> String {
        let root = authz::generate_root(1);
        let token = authz::mint(&root, "p-1", "ws-1", role, exp_ms).unwrap();
        BASE64.encode(token.as_bytes())
    }

    #[test]
    fn inspects_a_minted_token_without_any_key() {
        let b64 = mint_b64(authz::Role::Owner, 1_234_567);
        let i = inspect_b64(&b64).unwrap();
        assert_eq!(i.principal.as_deref(), Some("p-1"));
        assert_eq!(i.workspace.as_deref(), Some("ws-1"));
        assert_eq!(i.role.as_deref(), Some("owner"));
        assert_eq!(i.exp_ms, Some(1_234_567));
        assert_eq!(i.attenuation_blocks, 0);
        assert_eq!(i.block_sources.len(), 1);
    }

    #[test]
    fn expired_tokens_still_inspect_offline() {
        // exp already in the past — verify would deny; inspect must not.
        let b64 = mint_b64(authz::Role::Viewer, 1);
        let i = inspect_b64(&b64).unwrap();
        assert_eq!(i.role.as_deref(), Some("viewer"));
        assert_eq!(i.exp_ms, Some(1));
    }

    #[test]
    fn attenuated_tokens_report_their_extra_blocks() {
        let root = authz::generate_root(2);
        let token = authz::mint(&root, "p-1", "ws-1", authz::Role::Owner, 2_000_000).unwrap();
        let narrowed = authz::attenuate(&token, authz::Role::Viewer, 1_000_000).unwrap();
        let i = inspect_b64(&BASE64.encode(narrowed.as_bytes())).unwrap();
        // The authority facts are unchanged; narrowing is checks-only (§7.2).
        assert_eq!(i.role.as_deref(), Some("owner"));
        assert_eq!(i.attenuation_blocks, 1);
        assert!(
            i.block_sources[1].contains("check if"),
            "attenuation block should carry checks: {}",
            i.block_sources[1]
        );
    }

    #[test]
    fn garbage_input_fails_cleanly() {
        assert!(inspect_b64("not-base64!!!").is_err());
        assert!(inspect_b64(&BASE64.encode(b"not a biscuit")).is_err());
    }

    #[test]
    fn fact_parsers_only_match_fact_lines() {
        let source = "principal(\"p\");\nexp(42);\ncheck if time($t), $t < 42;";
        assert_eq!(fact_str(source, "principal").as_deref(), Some("p"));
        assert_eq!(fact_u64(source, "exp"), Some(42));
        assert_eq!(fact_str(source, "workspace"), None);
        // The check line must not be misread as an exp fact.
        assert_eq!(fact_u64(source, "time"), None);
    }
}
