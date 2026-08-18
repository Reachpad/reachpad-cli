//! M0 gate tests for authz (INFRA_SPEC §7.2, I6): mint / attenuate / verify,
//! with adversarial widening attempts. Attenuation MUST only narrow.

use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::time::{Duration, Instant};

use authz::{
    attenuate, generate_root, mint, mint_harness, mint_node_token, mint_workspace_handle, verify,
    verify_node_token, verify_workspace_handle, Error, GuestOp, KeyPair, Op, PublicKey, Role,
    TokenBytes,
};
use biscuit_auth::builder::BlockBuilder;
use biscuit_auth::{Biscuit, UnverifiedBiscuit};

const WS: &str = "ws-1";
const OTHER_WS: &str = "ws-2";
const ALICE: &str = "principal-alice";
const BOB: &str = "principal-bob";
const EXP: u64 = 1_000_000; // ms since epoch, virtual
const NOW: u64 = 500_000; // strictly before EXP

fn root() -> KeyPair {
    generate_root(0xA11CE)
}

fn root_pub() -> PublicKey {
    root().public()
}

fn assert_denied(result: Result<authz::Verified, Error>, context: &str) {
    match result {
        Err(Error::Denied(_)) => {}
        other => panic!("expected Denied for {context}, got {other:?}"),
    }
}

/// Append a raw block (attacker-controlled datalog) to a token without the
/// root key, exactly as an adversary with a share link would.
fn append_raw_block(token: &TokenBytes, datalog: &str) -> TokenBytes {
    let unverified = UnverifiedBiscuit::from(token.as_bytes()).unwrap();
    let mut block = BlockBuilder::new();
    block
        .add_code_with_params(datalog, HashMap::new(), HashMap::new())
        .unwrap();
    TokenBytes::from_vec(unverified.append(block).unwrap().to_vec().unwrap())
}

/// Append a block with no datalog at all.
fn append_empty_block(token: &TokenBytes) -> TokenBytes {
    let unverified = UnverifiedBiscuit::from(token.as_bytes()).unwrap();
    let appended = unverified.append(BlockBuilder::new()).unwrap();
    TokenBytes::from_vec(appended.to_vec().unwrap())
}

// ---------------------------------------------------------------------------
// (a) mint owner -> verify Write ok
// ---------------------------------------------------------------------------

#[test]
fn a_owner_token_write_ok() {
    let token = mint(&root(), ALICE, WS, Role::Owner, EXP).unwrap();
    let verified = verify(&token, &root_pub(), WS, &Op::Write, NOW).unwrap();
    assert_eq!(verified.principal, ALICE);
    assert_eq!(verified.role_effective, Role::Owner);

    // Owner does everything, including harness ops as itself.
    for op in [
        Op::Read,
        Op::Write,
        Op::Admin,
        Op::MirrorSync,
        Op::AppendOwnEvents {
            principal: ALICE.into(),
        },
    ] {
        verify(&token, &root_pub(), WS, &op, NOW)
            .unwrap_or_else(|e| panic!("owner must pass {op:?}: {e}"));
    }
}

#[test]
fn a2_collaborator_and_viewer_direct_mints() {
    let collab = mint(&root(), ALICE, WS, Role::Collaborator, EXP).unwrap();
    let v = verify(&collab, &root_pub(), WS, &Op::Write, NOW).unwrap();
    assert_eq!(v.role_effective, Role::Collaborator);
    assert_denied(
        verify(&collab, &root_pub(), WS, &Op::Admin, NOW),
        "collaborator admin",
    );

    let viewer = mint(&root(), ALICE, WS, Role::Viewer, EXP).unwrap();
    let v = verify(&viewer, &root_pub(), WS, &Op::Read, NOW).unwrap();
    assert_eq!(v.role_effective, Role::Viewer);
    assert_denied(
        verify(&viewer, &root_pub(), WS, &Op::Write, NOW),
        "viewer write",
    );
}

// ---------------------------------------------------------------------------
// (b) attenuate owner -> viewer: Write fails, Read ok
// ---------------------------------------------------------------------------

#[test]
fn b_attenuate_owner_to_viewer() {
    let owner = mint(&root(), ALICE, WS, Role::Owner, EXP).unwrap();
    let share_link = attenuate(&owner, Role::Viewer, EXP).unwrap();

    assert_denied(
        verify(&share_link, &root_pub(), WS, &Op::Write, NOW),
        "attenuated viewer write",
    );
    assert_denied(
        verify(&share_link, &root_pub(), WS, &Op::Admin, NOW),
        "attenuated viewer admin",
    );
    let verified = verify(&share_link, &root_pub(), WS, &Op::Read, NOW).unwrap();
    assert_eq!(verified.principal, ALICE);
    assert_eq!(verified.role_effective, Role::Viewer);
}

// ---------------------------------------------------------------------------
// (c) widening MUST be impossible
// ---------------------------------------------------------------------------

#[test]
fn c_reattenuate_viewer_to_collaborator_does_not_widen() {
    // Chain: owner -> viewer -> "collaborator" (attempted widening).
    let owner = mint(&root(), ALICE, WS, Role::Owner, EXP).unwrap();
    let viewer = attenuate(&owner, Role::Viewer, EXP).unwrap();
    let widened = attenuate(&viewer, Role::Collaborator, EXP).unwrap();

    assert_denied(
        verify(&widened, &root_pub(), WS, &Op::Write, NOW),
        "viewer re-attenuated to collaborator, write",
    );
    // Still a viewer: read keeps working.
    let v = verify(&widened, &root_pub(), WS, &Op::Read, NOW).unwrap();
    assert_eq!(v.role_effective, Role::Viewer);

    // Same from a directly minted viewer token.
    let direct_viewer = mint(&root(), ALICE, WS, Role::Viewer, EXP).unwrap();
    let widened = attenuate(&direct_viewer, Role::Owner, EXP).unwrap();
    assert_denied(
        verify(&widened, &root_pub(), WS, &Op::Write, NOW),
        "direct viewer attenuated to owner, write",
    );
    assert_denied(
        verify(&widened, &root_pub(), WS, &Op::Admin, NOW),
        "direct viewer attenuated to owner, admin",
    );
}

/// Appended blocks carrying facts or rules widen nothing — they are refused
/// outright, before any datalog runs (the structural shape gate).
///
/// This test used to assert that such facts were *ignored* (a Read on the
/// forged token still succeeded as a viewer). Ignoring them was safe but
/// fail-slow: evaluating attacker-supplied datalog is the CPU-DoS in
/// `h_hostile_appended_datalog_is_rejected_cheaply`. Refusing them is strictly
/// stronger — nothing that used to be denied is now allowed — so the
/// expectations below were tightened from "ignored" to "denied".
#[test]
fn c_appended_facts_and_rules_are_refused() {
    let viewer = mint(&root(), ALICE, WS, Role::Viewer, EXP).unwrap();

    for (label, datalog) in [
        // Appended block asserting role("owner").
        ("role fact", r#"role("owner");"#),
        // Appended block forging the verifier's role_op table.
        ("role_op fact", r#"role_op("viewer", "write");"#),
        // Appended rule deriving role("owner") from anything visible.
        ("role-derivation rule", r#"role("owner") <- workspace($w);"#),
        // A whole kitchen sink of forged facts at once.
        (
            "kitchen sink",
            r#"role("owner");
               role_op("viewer", "write");
               role_op("viewer", "admin");
               workspace("ws-1");
               exp(9999999999);
               time(0);"#,
        ),
        // Facts mixed in with a legitimate-looking check.
        (
            "fact plus check",
            r#"role("owner");
               check if op($o), ["read"].contains($o);"#,
        ),
    ] {
        let forged = append_raw_block(&viewer, datalog);
        for op in [Op::Read, Op::Write, Op::Admin] {
            assert_denied(
                verify(&forged, &root_pub(), WS, &op, NOW),
                &format!("appended {label}, {op:?}"),
            );
        }
    }
}

#[test]
fn c_appended_check_only_block_changes_nothing() {
    let owner = mint(&root(), ALICE, WS, Role::Owner, EXP).unwrap();
    let viewer = attenuate(&owner, Role::Viewer, EXP).unwrap();

    // A block with no statements at all: earlier checks still apply.
    let padded = append_empty_block(&viewer);
    assert_denied(
        verify(&padded, &root_pub(), WS, &Op::Write, NOW),
        "empty appended block, write",
    );
    let v = verify(&padded, &root_pub(), WS, &Op::Read, NOW).unwrap();
    assert_eq!(v.role_effective, Role::Viewer);

    // A block whose only check is trivially satisfied: likewise.
    let padded = append_raw_block(&viewer, r#"check if workspace($w);"#);
    let v = verify(&padded, &root_pub(), WS, &Op::Read, NOW).unwrap();
    assert_eq!(v.role_effective, Role::Viewer);
    assert_denied(
        verify(&padded, &root_pub(), WS, &Op::Write, NOW),
        "tautological appended check, write",
    );
}

#[test]
fn c_appended_principal_fact_is_refused() {
    // Attribution (I5) can never be re-pointed by attenuation: the fact is
    // invisible to the authority-scoped query AND the block is refused for
    // carrying a fact at all. (The invisibility layer behind this gate is
    // pinned by the unit test
    // `unit_tests::appended_facts_are_invisible_to_authority_queries`.)
    let viewer = mint(&root(), ALICE, WS, Role::Viewer, EXP).unwrap();
    let forged = append_raw_block(&viewer, r#"principal("principal-mallory");"#);
    assert_denied(
        verify(&forged, &root_pub(), WS, &Op::Read, NOW),
        "appended principal fact",
    );
}

// ---------------------------------------------------------------------------
// (d) expiry
// ---------------------------------------------------------------------------

#[test]
fn d_expiry_enforced() {
    let token = mint(&root(), ALICE, WS, Role::Owner, EXP).unwrap();

    // now < exp passes; now == exp and now > exp fail.
    verify(&token, &root_pub(), WS, &Op::Read, EXP - 1).unwrap();
    assert_denied(
        verify(&token, &root_pub(), WS, &Op::Read, EXP),
        "now == exp",
    );
    assert_denied(
        verify(&token, &root_pub(), WS, &Op::Read, EXP + 1),
        "now > exp",
    );
}

#[test]
fn d_attenuating_to_later_exp_does_not_extend() {
    let token = mint(&root(), ALICE, WS, Role::Owner, EXP).unwrap();
    let extended = attenuate(&token, Role::Owner, EXP * 10).unwrap();

    // Between original and "extended" expiry: the original authority check
    // still fires.
    assert_denied(
        verify(&extended, &root_pub(), WS, &Op::Read, EXP + 1),
        "later-exp attenuation past original exp",
    );
    // Before the original expiry it still works.
    verify(&extended, &root_pub(), WS, &Op::Read, NOW).unwrap();
}

#[test]
fn d_attenuating_to_earlier_exp_narrows() {
    let token = mint(&root(), ALICE, WS, Role::Owner, EXP).unwrap();
    let short = attenuate(&token, Role::Owner, NOW).unwrap(); // expires at NOW

    assert_denied(
        verify(&short, &root_pub(), WS, &Op::Read, NOW),
        "attenuated earlier exp, at exp",
    );
    verify(&short, &root_pub(), WS, &Op::Read, NOW - 1).unwrap();
}

// ---------------------------------------------------------------------------
// (e) wrong workspace
// ---------------------------------------------------------------------------

#[test]
fn e_wrong_workspace_fails() {
    let token = mint(&root(), ALICE, WS, Role::Owner, EXP).unwrap();
    assert_denied(
        verify(&token, &root_pub(), OTHER_WS, &Op::Read, NOW),
        "wrong workspace",
    );
    // Forging a workspace fact in an appended block does not help.
    let forged = append_raw_block(&token, r#"workspace("ws-2");"#);
    assert_denied(
        verify(&forged, &root_pub(), OTHER_WS, &Op::Read, NOW),
        "forged workspace fact",
    );
}

// ---------------------------------------------------------------------------
// (f) harness tokens
// ---------------------------------------------------------------------------

#[test]
fn f_harness_ops_are_restricted() {
    let token = mint_harness(&root(), ALICE, WS, EXP).unwrap();

    // Can NOT read PTY, write, or admin.
    assert_denied(
        verify(&token, &root_pub(), WS, &Op::Read, NOW),
        "harness read",
    );
    assert_denied(
        verify(&token, &root_pub(), WS, &Op::Write, NOW),
        "harness write",
    );
    assert_denied(
        verify(&token, &root_pub(), WS, &Op::Admin, NOW),
        "harness admin",
    );

    // CAN append its own events and mirror-sync.
    let v = verify(
        &token,
        &root_pub(),
        WS,
        &Op::AppendOwnEvents {
            principal: ALICE.into(),
        },
        NOW,
    )
    .unwrap();
    assert_eq!(v.principal, ALICE);
    assert_eq!(v.role_effective, Role::Harness);
    verify(&token, &root_pub(), WS, &Op::MirrorSync, NOW).unwrap();
}

#[test]
fn f_harness_principal_binding() {
    // Token minted for BOB; append for ALICE must fail.
    let token = mint_harness(&root(), BOB, WS, EXP).unwrap();
    assert_denied(
        verify(
            &token,
            &root_pub(),
            WS,
            &Op::AppendOwnEvents {
                principal: ALICE.into(),
            },
            NOW,
        ),
        "harness append for foreign principal",
    );

    // Binding holds for non-harness tokens too (I5 attribution).
    let owner = mint(&root(), ALICE, WS, Role::Owner, EXP).unwrap();
    assert_denied(
        verify(
            &owner,
            &root_pub(),
            WS,
            &Op::AppendOwnEvents {
                principal: BOB.into(),
            },
            NOW,
        ),
        "owner append attributed to someone else",
    );
}

#[test]
fn f_harness_cannot_be_widened() {
    let token = mint_harness(&root(), ALICE, WS, EXP).unwrap();
    let forged = append_raw_block(&token, r#"role("owner"); role_op("harness", "read");"#);
    assert_denied(
        verify(&forged, &root_pub(), WS, &Op::Read, NOW),
        "harness widened to read",
    );
    // Attenuating a harness token to "owner" cannot grant read either: the
    // authority block's self-contained op check still applies.
    let widened = attenuate(&token, Role::Owner, EXP).unwrap();
    assert_denied(
        verify(&widened, &root_pub(), WS, &Op::Read, NOW),
        "harness attenuated to owner, read",
    );
}

// ---------------------------------------------------------------------------
// (g) tampered tokens fail signature verification
// ---------------------------------------------------------------------------

#[test]
fn g_tampered_bytes_fail() {
    let token = mint(&root(), ALICE, WS, Role::Owner, EXP).unwrap();
    let bytes = token.as_bytes();

    // Flip one byte at several positions across the token.
    for pos in [0, bytes.len() / 4, bytes.len() / 2, bytes.len() - 1] {
        let mut mutated = bytes.to_vec();
        mutated[pos] ^= 0x40;
        let result = verify(
            &TokenBytes::from_vec(mutated),
            &root_pub(),
            WS,
            &Op::Read,
            NOW,
        );
        assert!(
            matches!(result, Err(Error::Token(_))),
            "byte flip at {pos} must fail parse/signature, got {result:?}"
        );
    }

    // Truncation fails.
    let truncated = TokenBytes::from_vec(bytes[..bytes.len() - 5].to_vec());
    assert!(verify(&truncated, &root_pub(), WS, &Op::Read, NOW).is_err());

    // A token from a different root fails against ours.
    let foreign = mint(&generate_root(999), ALICE, WS, Role::Owner, EXP).unwrap();
    assert!(matches!(
        verify(&foreign, &root_pub(), WS, &Op::Read, NOW),
        Err(Error::Token(_))
    ));
}

// ---------------------------------------------------------------------------
// (h) verify() is fail-FAST: bounded work per call, no spurious denies
// ---------------------------------------------------------------------------

/// A validly signed, low-privilege share link whose appended block carries
/// datalog designed to burn CPU: 20 facts plus a check that never matches, so
/// the datalog engine must explore the whole 20³ join — on every one of the
/// authorize + effective-role-probe runs `verify` performs.
///
/// Before the structural gate this cost ~100 ms per verify (unoptimized) with
/// no way to make it cheaper without reintroducing spurious denies; the block
/// carries facts, so it is now refused before any authorizer is built.
fn cpu_burner_share_link() -> TokenBytes {
    let owner = mint(&root(), ALICE, WS, Role::Owner, EXP).unwrap();
    let share_link = attenuate(&owner, Role::Viewer, EXP).unwrap();
    let mut datalog = String::new();
    for i in 0..20 {
        datalog.push_str(&format!("burn({i});\n"));
    }
    datalog.push_str("check if burn($a), burn($b), burn($c), $a > 1000000;\n");
    append_raw_block(&share_link, &datalog)
}

#[test]
fn h_hostile_appended_datalog_is_rejected_cheaply() {
    let hostile = cpu_burner_share_link();
    assert_denied(
        verify(&hostile, &root_pub(), WS, &Op::Read, NOW),
        "cpu-burner share link",
    );

    // Wall-clock assertion (this is a test, not a core — I12 allows it).
    // Rejection happens before the signature chain is even verified, so each
    // verify is a parse plus a text-level shape check: ~0.45 ms unoptimized,
    // i.e. ~0.13 s for the loop below. The bound is deliberately loose (20x)
    // so that only an order-of-magnitude regression trips it — evaluating this
    // block's datalog costs ~136 ms per verify unoptimized (~41 s for the
    // loop), and even *verifying its signatures* before rejecting it costs
    // ~36 ms (~11 s for the loop).
    let rounds = 300;
    let start = Instant::now();
    for _ in 0..rounds {
        assert!(verify(&hostile, &root_pub(), WS, &Op::Read, NOW).is_err());
    }
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_secs(3),
        "{rounds} verifies of a hostile token took {elapsed:?}; a token whose \
         appended datalog is evaluated at all cannot meet this bound"
    );
}

#[test]
fn h_legitimate_tokens_never_spuriously_deny_under_load() {
    // The other failure mode: a budget so tight that honest tokens get denied
    // on a loaded host. Hammer the verifier from every core at once.
    let owner = mint(&root(), ALICE, WS, Role::Owner, EXP).unwrap();
    let share_link = attenuate(&owner, Role::Viewer, EXP).unwrap();
    let deep = (0..4).fold(share_link.clone(), |t, _| {
        attenuate(&t, Role::Viewer, EXP).unwrap()
    });
    let threads = std::thread::available_parallelism()
        .map(NonZeroUsize::get)
        .unwrap_or(4)
        .clamp(2, 8);
    let rounds = 60;

    std::thread::scope(|scope| {
        for _ in 0..threads {
            let tokens = [owner.clone(), share_link.clone(), deep.clone()];
            scope.spawn(move || {
                for _ in 0..rounds {
                    for token in &tokens {
                        let v = verify(token, &root_pub(), WS, &Op::Read, NOW)
                            .expect("a legitimate token must never be denied");
                        assert_eq!(v.principal, ALICE);
                    }
                }
            });
        }
    });
}

#[test]
fn h_oversized_and_overdeep_tokens_are_rejected() {
    let owner = mint(&root(), ALICE, WS, Role::Owner, EXP).unwrap();

    // 15 attenuations = 16 blocks: the deepest chain the scheme accepts.
    let deepest = (0..15).fold(owner.clone(), |t, _| {
        attenuate(&t, Role::Viewer, EXP).unwrap()
    });
    let v = verify(&deepest, &root_pub(), WS, &Op::Read, NOW).unwrap();
    assert_eq!(v.role_effective, Role::Viewer);

    // One more block is refused.
    let too_deep = attenuate(&deepest, Role::Viewer, EXP).unwrap();
    assert_denied(
        verify(&too_deep, &root_pub(), WS, &Op::Read, NOW),
        "17-block chain",
    );

    // A single huge (but checks-only) appended block is refused too.
    let bloated = append_raw_block(
        &owner,
        &format!(r#"check if op($o), $o != "{}";"#, "x".repeat(2000)),
    );
    assert_denied(
        verify(&bloated, &root_pub(), WS, &Op::Read, NOW),
        "2 KiB appended block",
    );

    // Neither is a token that is simply enormous.
    let mut giant = owner.as_bytes().to_vec();
    giant.resize(64 * 1024, 0);
    assert_denied(
        verify(
            &TokenBytes::from_vec(giant),
            &root_pub(),
            WS,
            &Op::Read,
            NOW,
        ),
        "64 KiB token",
    );
}

#[test]
fn h_appended_block_symbols_must_be_syntactically_inert() {
    // A predicate name containing spaces and parens can make a *fact* print
    // like a check, which is how a text-level shape check would be fooled.
    // Appended-block symbols are therefore restricted to an inert charset;
    // everything `attenuate` emits (op names) satisfies it.
    let owner = mint(&root(), ALICE, WS, Role::Owner, EXP).unwrap();
    let sneaky = append_raw_block(&owner, r#"check if op($o), $o != "read write";"#);
    assert_denied(
        verify(&sneaky, &root_pub(), WS, &Op::Read, NOW),
        "appended block with a non-inert symbol",
    );

    // Control: the same check with an inert string is accepted.
    let fine = append_raw_block(&owner, r#"check if op($o), $o != "read_write";"#);
    verify(&fine, &root_pub(), WS, &Op::Read, NOW).unwrap();
}

// ---------------------------------------------------------------------------
// (n) node-scoped token audience (ADR-0021, I2)
//
// These replace the former (i) tests, which pinned `fencing_token` as a
// *user-facing* authority fact. That amendment to §7.2 was rejected (ADR-0015:
// a fencing epoch inside a share link goes stale on the owner's next attach,
// destroying offline attenuation), so the behavior they encoded is now wrong.
// The property they were really after — an *attested* lease generation that a
// writer cannot self-declare — moves here, to a separate audience that is
// never shared and never attenuated.
// ---------------------------------------------------------------------------

const FENCE: u64 = 42;
const NODE: &str = "node-n1";

/// Mint an arbitrary authority block with the real root key: the only way to
/// build node tokens this crate would never emit (missing facts, oversized
/// blocks). An attacker without the root key cannot do this — these tests
/// exist to pin what the *verifier* insists on, independent of what the minter
/// happens to produce.
fn mint_raw_authority(datalog: &str) -> TokenBytes {
    let mut builder = Biscuit::builder();
    builder.add_code(datalog).unwrap();
    TokenBytes::from_vec(builder.build(&root()).unwrap().to_vec().unwrap())
}

fn assert_node_denied(result: Result<authz::VerifiedNode, Error>, context: &str) {
    match result {
        Err(Error::Denied(_)) => {}
        other => panic!("expected Denied for {context}, got {other:?}"),
    }
}

#[test]
fn n_node_token_attests_node_workspace_and_fencing_generation() {
    let token = mint_node_token(&root(), NODE, WS, FENCE, EXP).unwrap();

    let v = verify_node_token(&token, &root_pub(), WS, NOW).unwrap();
    assert_eq!(v.node, NODE);
    assert_eq!(v.workspace, WS);
    assert_eq!(v.fencing_token, FENCE);

    // Workspace binding and expiry bind exactly as they do for user tokens.
    assert_node_denied(
        verify_node_token(&token, &root_pub(), OTHER_WS, NOW),
        "node token, wrong workspace",
    );
    assert_node_denied(
        verify_node_token(&token, &root_pub(), WS, EXP),
        "node token at expiry",
    );
    verify_node_token(&token, &root_pub(), WS, EXP - 1).unwrap();

    // A token from a different root is not ours.
    let foreign = mint_node_token(&generate_root(999), NODE, WS, FENCE, EXP).unwrap();
    assert!(matches!(
        verify_node_token(&foreign, &root_pub(), WS, NOW),
        Err(Error::Token(_))
    ));

    // A fencing token outside the datalog integer domain is refused at mint.
    assert!(matches!(
        mint_node_token(&root(), NODE, WS, FENCE, u64::MAX),
        Err(Error::TimeOutOfRange(_))
    ));
    assert!(matches!(
        mint_node_token(&root(), NODE, WS, u64::MAX, EXP),
        Err(Error::FencingOutOfRange(_))
    ));
}

/// Audience separation, checked in BOTH directions and explicitly: a node
/// token must authorize nothing as a workspace capability, and a user-facing
/// token must attest no lease generation.
#[test]
fn n_audience_separation_is_checked_both_ways() {
    let node_token = mint_node_token(&root(), NODE, WS, FENCE, EXP).unwrap();

    // A node token is not a workspace capability, for ANY op.
    for op in [
        Op::Read,
        Op::Write,
        Op::Admin,
        Op::MirrorSync,
        Op::AppendOwnEvents {
            principal: NODE.into(),
        },
    ] {
        match verify(&node_token, &root_pub(), WS, &op, NOW) {
            Err(Error::Denied(msg)) => assert!(
                msg.contains("audience"),
                "the refusal must name the audience, not be incidental: {msg}"
            ),
            other => panic!("node token must not authorize {op:?}, got {other:?}"),
        }
    }

    // ...and the other way: user-facing tokens attest no generation.
    for user_token in [
        mint(&root(), ALICE, WS, Role::Owner, EXP).unwrap(),
        mint_harness(&root(), ALICE, WS, EXP).unwrap(),
    ] {
        match verify_node_token(&user_token, &root_pub(), WS, NOW) {
            Err(Error::Denied(msg)) => assert!(
                msg.contains("audience"),
                "the refusal must name the audience: {msg}"
            ),
            other => panic!("a user token is not a node token, got {other:?}"),
        }
    }

    // A share link is refused too. Its named reason is the single-block rule
    // rather than the audience: that gate runs before signature verification
    // (ADR-0014 — bound the work first), and it is just as much a node-token
    // rule, so the refusal is still explicit rather than incidental.
    let share_link = attenuate(
        &mint(&root(), ALICE, WS, Role::Owner, EXP).unwrap(),
        Role::Viewer,
        EXP,
    )
    .unwrap();
    assert_node_denied(
        verify_node_token(&share_link, &root_pub(), WS, NOW),
        "share link presented as a node token",
    );

    // A token minted for some third audience is refused by both verifiers.
    let other_audience = mint_raw_authority(&format!(
        "audience(\"gateway\");\nnode(\"{NODE}\");\nworkspace(\"{WS}\");\n\
         fencing_token({FENCE});\nexp({EXP});\ncheck if time($t), $t < {EXP};"
    ));
    assert_node_denied(
        verify_node_token(&other_audience, &root_pub(), WS, NOW),
        "third audience presented as a node token",
    );
    assert_denied(
        verify(&other_audience, &root_pub(), WS, &Op::Read, NOW),
        "third audience presented as a user token",
    );
}

/// Attenuation of a node token is REFUSED, not merely unused (ADR-0021).
#[test]
fn n_node_tokens_are_never_attenuated() {
    let node_token = mint_node_token(&root(), NODE, WS, FENCE, EXP).unwrap();

    match attenuate(&node_token, Role::Viewer, EXP) {
        Err(Error::Denied(msg)) => assert!(msg.contains("attenuat"), "{msg}"),
        other => panic!("attenuating a node token must error, got {other:?}"),
    }

    // And going around `attenuate` does not help: a node token carrying ANY
    // appended block is refused, checks-only or not.
    let appended = append_raw_block(&node_token, r#"check if workspace($w);"#);
    assert_node_denied(
        verify_node_token(&appended, &root_pub(), WS, NOW),
        "node token with an appended check-only block",
    );
    let padded = append_empty_block(&node_token);
    assert_node_denied(
        verify_node_token(&padded, &root_pub(), WS, NOW),
        "node token with an empty appended block",
    );
    // Not even one that tries to restate the audience or raise the generation.
    let forged = append_raw_block(
        &node_token,
        &format!("audience(\"node\");\nfencing_token({});", i64::MAX),
    );
    assert_node_denied(
        verify_node_token(&forged, &root_pub(), WS, NOW),
        "node token with a forged appended generation",
    );
}

/// An appended `audience` fact cannot turn a user token into a node token
/// (nor a node token into a user token): appended facts are refused by the
/// shape gate, and invisible to authority queries behind it.
#[test]
fn n_appended_audience_fact_cannot_change_the_audience() {
    let user = mint(&root(), ALICE, WS, Role::Owner, EXP).unwrap();
    let forged = append_raw_block(
        &user,
        &format!("audience(\"node\");\nnode(\"{NODE}\");\nfencing_token({FENCE});"),
    );
    assert_node_denied(
        verify_node_token(&forged, &root_pub(), WS, NOW),
        "user token wearing a node audience",
    );
    assert_denied(
        verify(&forged, &root_pub(), WS, &Op::Read, NOW),
        "user token with appended facts",
    );
}

/// A node token without a fencing generation attests nothing, so it is denied
/// — never accepted with some default.
#[test]
fn n_fencing_token_is_required_in_a_node_token() {
    let no_fence = mint_raw_authority(&format!(
        "audience(\"node\");\nnode(\"{NODE}\");\nworkspace(\"{WS}\");\n\
         exp({EXP});\ncheck if time($t), $t < {EXP};"
    ));
    assert_node_denied(
        verify_node_token(&no_fence, &root_pub(), WS, NOW),
        "node token with no fencing_token fact",
    );

    // Two generations are as meaningless as none.
    let two_fences = mint_raw_authority(&format!(
        "audience(\"node\");\nnode(\"{NODE}\");\nworkspace(\"{WS}\");\n\
         fencing_token({FENCE});\nfencing_token({});\nexp({EXP});\n\
         check if time($t), $t < {EXP};",
        FENCE + 1
    ));
    assert_node_denied(
        verify_node_token(&two_fences, &root_pub(), WS, NOW),
        "node token with two fencing_token facts",
    );

    // So is one that names no node, or two.
    let no_node = mint_raw_authority(&format!(
        "audience(\"node\");\nworkspace(\"{WS}\");\nfencing_token({FENCE});\n\
         exp({EXP});\ncheck if time($t), $t < {EXP};"
    ));
    assert_node_denied(
        verify_node_token(&no_node, &root_pub(), WS, NOW),
        "node token naming no node",
    );
}

/// The ADR-0014 hardening covers the node path too: bounded before any crypto,
/// and one shared datalog deadline that honest tokens never trip.
#[test]
fn n_shape_gate_and_datalog_budget_apply_to_node_tokens() {
    // Enormous token: refused before it is parsed.
    let mut giant = mint_node_token(&root(), NODE, WS, FENCE, EXP)
        .unwrap()
        .into_vec();
    giant.resize(64 * 1024, 0);
    assert_node_denied(
        verify_node_token(&TokenBytes::from_vec(giant), &root_pub(), WS, NOW),
        "64 KiB node token",
    );

    // Oversized authority datalog: refused after the signature says it is
    // ours, before any authorizer exists.
    let bloated = mint_raw_authority(&format!(
        "audience(\"node\");\nnode(\"{}\");\nworkspace(\"{WS}\");\n\
         fencing_token({FENCE});\nexp({EXP});\ncheck if time($t), $t < {EXP};",
        "n".repeat(1100)
    ));
    assert_node_denied(
        verify_node_token(&bloated, &root_pub(), WS, NOW),
        "node token with a 1 KiB+ authority block",
    );

    // Too many authority statements.
    let mut source = format!(
        "audience(\"node\");\nnode(\"{NODE}\");\nworkspace(\"{WS}\");\n\
         fencing_token({FENCE});\nexp({EXP});\ncheck if time($t), $t < {EXP};"
    );
    for i in 0..20 {
        source.push_str(&format!("\npad({i});"));
    }
    let padded = mint_raw_authority(&source);
    assert_node_denied(
        verify_node_token(&padded, &root_pub(), WS, NOW),
        "node token with 26 authority statements",
    );

    // The other failure mode (ADR-0014's first half): a budget so tight that
    // honest tokens are denied under load. Hammer it from every core.
    let token = mint_node_token(&root(), NODE, WS, FENCE, EXP).unwrap();
    let threads = std::thread::available_parallelism()
        .map(NonZeroUsize::get)
        .unwrap_or(4)
        .clamp(2, 8);
    std::thread::scope(|scope| {
        for _ in 0..threads {
            let token = token.clone();
            scope.spawn(move || {
                for _ in 0..60 {
                    let v = verify_node_token(&token, &root_pub(), WS, NOW)
                        .expect("a legitimate node token must never be denied");
                    assert_eq!(v.fencing_token, FENCE);
                }
            });
        }
    });
}

// ---------------------------------------------------------------------------
// (g) workspace-handle audience (ADR-0076, design §6)
//
// The third audience: the credential a guest holds. It mirrors the (n) set
// above — separation checked in every direction, never attenuated, every field
// read from the authority block — and adds the property the node audience has
// no analogue for: a **positive operation allowlist**, so the set of things a
// guest can ask for is a closed enum rather than a prose list of things it
// must not do.
// ---------------------------------------------------------------------------

const GEN: u64 = 7;

fn assert_handle_denied(result: Result<authz::VerifiedHandle, Error>, context: &str) {
    match result {
        Err(Error::Denied(_)) => {}
        other => panic!("expected Denied for {context}, got {other:?}"),
    }
}

/// Datalog for a handle-shaped authority block, so a test can mint one this
/// crate would never emit (a narrowed allowlist, a missing fact, two of one).
/// `ops` is the set literal for the block's own op check.
fn raw_handle_source(ops: &str) -> String {
    format!(
        "audience(\"guest\");\nworkspace(\"{WS}\");\nowner_principal(\"{ALICE}\");\n\
         generation({GEN});\nfencing_token({FENCE});\nexp({EXP});\n\
         check if time($t), $t < {EXP};\ncheck if op($o), {ops}.contains($o);"
    )
}

fn handle() -> TokenBytes {
    mint_workspace_handle(&root(), WS, ALICE, GEN, FENCE, EXP).unwrap()
}

#[test]
fn g_handle_attests_workspace_owner_generation_and_instance() {
    let token = handle();

    let v = verify_workspace_handle(&token, &root_pub(), WS, GuestOp::ListLinks, NOW).unwrap();
    assert_eq!(v.workspace, WS);
    // The handle acts as the workspace OWNER, never as whoever started the VM
    // (design §6 ruling) — attribution and billing follow this field.
    assert_eq!(v.owner_principal, ALICE);
    assert_eq!(v.generation, GEN);
    assert_eq!(v.fencing_token, FENCE);

    // Workspace binding and expiry bind exactly as they do everywhere else.
    assert_handle_denied(
        verify_workspace_handle(&token, &root_pub(), OTHER_WS, GuestOp::ListLinks, NOW),
        "handle, wrong workspace",
    );
    // Expiry binds at exactly the same instant it always did — and answers
    // its OWN variant (creds milestone C3, ADR-0080). The bound did not move;
    // only its classification did, because a handle lives five minutes by
    // design and its holder's remedy is *ask for a fresh one*, which is a
    // different action from the one every other refusal here calls for. It is
    // reachable only after the signature chain and the audience verify, so it
    // is no oracle — and the wrong-workspace case above still asserts
    // `Denied`, which is what stops the two being merged in the other
    // direction.
    match verify_workspace_handle(&token, &root_pub(), WS, GuestOp::ListLinks, EXP) {
        Err(Error::HandleExpired { exp_ms, now_ms }) => {
            assert_eq!(exp_ms, EXP, "the refusal names the expiry it read");
            assert_eq!(now_ms, EXP, "and the time it was judged against");
        }
        other => panic!("expected HandleExpired for a handle at expiry, got {other:?}"),
    }
    verify_workspace_handle(&token, &root_pub(), WS, GuestOp::ListLinks, EXP - 1).unwrap();

    // A handle from a different root is not ours.
    let foreign = mint_workspace_handle(&generate_root(999), WS, ALICE, GEN, FENCE, EXP).unwrap();
    assert!(matches!(
        verify_workspace_handle(&foreign, &root_pub(), WS, GuestOp::ListLinks, NOW),
        Err(Error::Token(_))
    ));

    // Counters outside the datalog integer domain are refused at mint, each
    // naming its own field.
    assert!(matches!(
        mint_workspace_handle(&root(), WS, ALICE, u64::MAX, FENCE, EXP),
        Err(Error::GenerationOutOfRange(_))
    ));
    assert!(matches!(
        mint_workspace_handle(&root(), WS, ALICE, GEN, u64::MAX, EXP),
        Err(Error::FencingOutOfRange(_))
    ));
    assert!(matches!(
        mint_workspace_handle(&root(), WS, ALICE, GEN, FENCE, u64::MAX),
        Err(Error::TimeOutOfRange(_))
    ));
}

/// Audience separation, checked in all THREE directions and explicitly. Each
/// verifier accepts its own token (the positive control) and refuses both
/// others by naming the audience, not by tripping over some downstream check.
#[test]
fn g_audience_separation_is_checked_three_ways() {
    let user_token = mint(&root(), ALICE, WS, Role::Owner, EXP).unwrap();
    let node_token = mint_node_token(&root(), NODE, WS, FENCE, EXP).unwrap();
    let handle_token = handle();

    // Positive controls: each verifier accepts its own.
    verify(&user_token, &root_pub(), WS, &Op::Read, NOW).unwrap();
    verify_node_token(&node_token, &root_pub(), WS, NOW).unwrap();
    verify_workspace_handle(&handle_token, &root_pub(), WS, GuestOp::ListLinks, NOW).unwrap();

    // 1. The user verifier refuses a handle, for every op, on the audience.
    for op in [
        Op::Read,
        Op::Write,
        Op::Admin,
        Op::MirrorSync,
        Op::AppendOwnEvents {
            principal: ALICE.into(),
        },
    ] {
        match verify(&handle_token, &root_pub(), WS, &op, NOW) {
            Err(Error::Denied(msg)) => assert!(
                msg.contains("audience"),
                "the refusal must name the audience, not be incidental: {msg}"
            ),
            other => panic!("a handle must not authorize {op:?}, got {other:?}"),
        }
    }

    // 2. The node verifier refuses a handle: it attests no lease generation of
    //    its own, whatever integer it happens to carry.
    match verify_node_token(&handle_token, &root_pub(), WS, NOW) {
        Err(Error::Denied(msg)) => assert!(msg.contains("audience"), "{msg}"),
        other => panic!("a handle is not a node token, got {other:?}"),
    }

    // 3. The guest verifier refuses a user token AND a node token.
    for (label, foreign) in [
        ("user token", user_token.clone()),
        (
            "harness token",
            mint_harness(&root(), ALICE, WS, EXP).unwrap(),
        ),
        ("node token", node_token.clone()),
    ] {
        match verify_workspace_handle(&foreign, &root_pub(), WS, GuestOp::ListLinks, NOW) {
            Err(Error::Denied(msg)) => assert!(
                msg.contains("audience"),
                "the refusal must name the audience for a {label}: {msg}"
            ),
            other => panic!("a {label} is not a workspace handle, got {other:?}"),
        }
    }

    // A share link is refused too — named on the single-block rule, which runs
    // before signature verification (ADR-0014) and is just as much a handle
    // rule, so the refusal is still explicit rather than incidental.
    let share_link = attenuate(&user_token, Role::Viewer, EXP).unwrap();
    assert_handle_denied(
        verify_workspace_handle(&share_link, &root_pub(), WS, GuestOp::ListLinks, NOW),
        "share link presented as a workspace handle",
    );

    // And a token minted for a fourth audience is refused by all three.
    let other_audience = mint_raw_authority(&format!(
        "audience(\"gateway\");\nworkspace(\"{WS}\");\nowner_principal(\"{ALICE}\");\n\
         generation({GEN});\nfencing_token({FENCE});\nexp({EXP});\n\
         check if time($t), $t < {EXP};"
    ));
    assert_handle_denied(
        verify_workspace_handle(&other_audience, &root_pub(), WS, GuestOp::ListLinks, NOW),
        "fourth audience presented as a handle",
    );
    assert_node_denied(
        verify_node_token(&other_audience, &root_pub(), WS, NOW),
        "fourth audience presented as a node token",
    );
    assert_denied(
        verify(&other_audience, &root_pub(), WS, &Op::Read, NOW),
        "fourth audience presented as a user token",
    );
}

/// A handle at a user route authorizes nothing — the regression pin on the
/// invariant the whole design leans on. `authorize_verified` refuses any
/// audience-bearing token *before* it authorizes anything, so this holds for
/// `Op::Write` even though a handle carries no `role` fact that could have
/// allowed it. Incidental refusal is not a contract; this one is.
#[test]
fn g_a_handle_authorizes_nothing_at_a_user_route() {
    let token = handle();
    assert_denied(
        verify(&token, &root_pub(), WS, &Op::Write, NOW),
        "handle presented for Op::Write at a user route",
    );
    // Not even for its own workspace's owner principal.
    assert_denied(
        verify(
            &token,
            &root_pub(),
            WS,
            &Op::AppendOwnEvents {
                principal: ALICE.into(),
            },
            NOW,
        ),
        "handle appending events as the owner it names",
    );
}

/// The allowlist is **positive and exhaustive**: every [`GuestOp`] variant gets
/// a verdict here, and the `match` below has no `_` arm, so a variant added to
/// the enum without deciding what the guest audience does with it fails to
/// compile. (Demonstrated once: adding a fourth variant makes this file fail
/// with `non-exhaustive patterns`.)
#[test]
fn g_the_guest_allowlist_is_positive_and_exhaustive() {
    let token = handle();

    for op in GuestOp::ALL {
        let allowed = match op {
            GuestOp::ListLinks => true,
            GuestOp::Spawn => true,
            GuestOp::RequestLink => true,
            GuestOp::UseCredential => true,
        };
        let result = verify_workspace_handle(&token, &root_pub(), WS, op, NOW);
        assert_eq!(
            result.is_ok(),
            allowed,
            "{op:?} verdict changed: got {result:?}"
        );
    }

    // The allowlist is enforced twice. Belt: it is carried in the minted
    // authority block, so it travels with the token rather than living only in
    // the verifier (`mint_harness`'s shape).
    let minted = UnverifiedBiscuit::from(token.as_bytes())
        .unwrap()
        .print_block_source(0)
        .unwrap();
    // biscuit prints a set literal sorted, so build the expectation the same
    // way rather than pinning the enum's declaration order.
    let mut names: Vec<&str> = GuestOp::ALL.iter().map(|op| op.name()).collect();
    names.sort_unstable();
    let literal = names
        .iter()
        .map(|n| format!("\"{n}\""))
        .collect::<Vec<_>>()
        .join(", ");
    assert!(
        minted.contains(&format!("check if op($o), [{literal}].contains($o)")),
        "the minted authority block must carry the allowlist itself:\n{minted}"
    );

    // Braces: the block half is load-bearing on its own — a handle whose
    // authority block lists only `list_links` refuses the others even
    // though the verifier's own match would admit them.
    let narrowed = mint_raw_authority(&raw_handle_source(r#"["list_links"]"#));
    verify_workspace_handle(&narrowed, &root_pub(), WS, GuestOp::ListLinks, NOW).unwrap();
    for op in [GuestOp::Spawn, GuestOp::RequestLink, GuestOp::UseCredential] {
        assert_handle_denied(
            verify_workspace_handle(&narrowed, &root_pub(), WS, op, NOW),
            &format!("{op:?} against a block that allowlists only list_links"),
        );
    }

    // Negative control for the pair: with the full allowlist in the block, the
    // same calls all pass — so the refusals above are the block's check
    // firing, not something else about a raw-minted handle.
    let full = mint_raw_authority(&raw_handle_source(
        r#"["list_links", "spawn", "request_link", "use_credential"]"#,
    ));
    for op in GuestOp::ALL {
        verify_workspace_handle(&full, &root_pub(), WS, op, NOW)
            .unwrap_or_else(|e| panic!("{op:?} must pass the full allowlist: {e}"));
    }
}

/// **The op set lives in the token bytes, so a handle minted before C4 refuses
/// `use_credential` — and that is the mechanism, not a bug.**
///
/// Every handle in the fleet at the moment controld gains this op carries the
/// three-op literal in its own authority block. A verifier that learned the
/// fourth op does not widen them: the block's `check if op($o), [...]` still
/// runs and still fails. The consequence is operational and belongs in the
/// deploy note rather than in a comment nobody reads — a guest cannot spend a
/// brokered credential until its node's refresher has re-minted, which is at
/// most one `HANDLE_TTL_MS` after the controld deploy.
///
/// The same handle keeps working for the three ops it was minted with, which
/// is what makes this a delay rather than an outage.
#[test]
fn g_a_handle_minted_before_use_credential_existed_refuses_it() {
    let pre_c4 = mint_raw_authority(&raw_handle_source(
        r#"["list_links", "spawn", "request_link"]"#,
    ));
    assert_handle_denied(
        verify_workspace_handle(&pre_c4, &root_pub(), WS, GuestOp::UseCredential, NOW),
        "a pre-C4 handle presented for use_credential",
    );
    for op in [GuestOp::ListLinks, GuestOp::Spawn, GuestOp::RequestLink] {
        verify_workspace_handle(&pre_c4, &root_pub(), WS, op, NOW)
            .unwrap_or_else(|e| panic!("a pre-C4 handle must still authorize {op:?}: {e}"));
    }
    // And the re-mint is the whole remedy: the same workspace, minted now,
    // authorizes the new op immediately.
    verify_workspace_handle(&handle(), &root_pub(), WS, GuestOp::UseCredential, NOW)
        .expect("a freshly minted handle carries the four-op allowlist");
}

/// Attenuation of a handle is REFUSED, not merely unused — asserted, not
/// assumed (ADR-0021's rule, inherited by ADR-0076 because a handle declares
/// an audience).
#[test]
fn g_handles_are_never_attenuated() {
    let token = handle();

    match attenuate(&token, Role::Viewer, EXP) {
        Err(Error::Denied(msg)) => assert!(msg.contains("attenuat"), "{msg}"),
        other => panic!("attenuating a workspace handle must error, got {other:?}"),
    }

    // Going around `attenuate` does not help: a handle carrying ANY appended
    // block is refused, checks-only or not.
    let appended = append_raw_block(&token, r#"check if workspace($w);"#);
    assert_handle_denied(
        verify_workspace_handle(&appended, &root_pub(), WS, GuestOp::ListLinks, NOW),
        "handle with an appended check-only block",
    );
    let padded = append_empty_block(&token);
    assert_handle_denied(
        verify_workspace_handle(&padded, &root_pub(), WS, GuestOp::ListLinks, NOW),
        "handle with an empty appended block",
    );
}

/// `generation` and `fencing_token` are read from the **authority block only**.
/// An appended block claiming different numbers does not change them — the
/// handle is refused outright, which is strictly stronger than ignoring the
/// claim.
#[test]
fn g_generation_and_fencing_come_from_the_authority_block_only() {
    let token = handle();

    let forged = append_raw_block(
        &token,
        &format!("generation({});\nfencing_token({});", GEN + 1000, FENCE + 1),
    );
    assert_handle_denied(
        verify_workspace_handle(&forged, &root_pub(), WS, GuestOp::ListLinks, NOW),
        "handle with a forged appended generation",
    );

    // Two of a counter are as meaningless as none, in either direction.
    for (label, source) in [
        (
            "two generations",
            format!(
                "audience(\"guest\");\nworkspace(\"{WS}\");\nowner_principal(\"{ALICE}\");\n\
                 generation({GEN});\ngeneration({});\nfencing_token({FENCE});\nexp({EXP});\n\
                 check if time($t), $t < {EXP};",
                GEN + 1
            ),
        ),
        (
            "no generation",
            format!(
                "audience(\"guest\");\nworkspace(\"{WS}\");\nowner_principal(\"{ALICE}\");\n\
                 fencing_token({FENCE});\nexp({EXP});\ncheck if time($t), $t < {EXP};"
            ),
        ),
        (
            "no fencing token",
            format!(
                "audience(\"guest\");\nworkspace(\"{WS}\");\nowner_principal(\"{ALICE}\");\n\
                 generation({GEN});\nexp({EXP});\ncheck if time($t), $t < {EXP};"
            ),
        ),
        (
            "no owner principal",
            format!(
                "audience(\"guest\");\nworkspace(\"{WS}\");\ngeneration({GEN});\n\
                 fencing_token({FENCE});\nexp({EXP});\ncheck if time($t), $t < {EXP};"
            ),
        ),
        (
            "negative generation",
            format!(
                "audience(\"guest\");\nworkspace(\"{WS}\");\nowner_principal(\"{ALICE}\");\n\
                 generation(-1);\nfencing_token({FENCE});\nexp({EXP});\n\
                 check if time($t), $t < {EXP};"
            ),
        ),
    ] {
        assert_handle_denied(
            verify_workspace_handle(
                &mint_raw_authority(&source),
                &root_pub(),
                WS,
                GuestOp::ListLinks,
                NOW,
            ),
            &format!("handle with {label}"),
        );
    }
}

/// The handle's authority block fits the statement ceiling with room to spare,
/// and the ADR-0014 hardening covers this path too.
#[test]
fn g_shape_gate_and_statement_budget_apply_to_handles() {
    // 6 facts + 2 checks = 8, against MAX_AUTHORITY_STATEMENTS = 16. Counted,
    // not assumed: the block is the widest this crate mints.
    let token = handle();
    let source = UnverifiedBiscuit::from(token.as_bytes())
        .unwrap()
        .print_block_source(0)
        .unwrap();
    let statements = source.split(';').filter(|s| !s.trim().is_empty()).count();
    assert_eq!(statements, 8, "handle authority block:\n{source}");
    assert!(statements <= 16, "authority statement ceiling");

    // Enormous token: refused before it is parsed.
    let mut giant = token.clone().into_vec();
    giant.resize(64 * 1024, 0);
    assert_handle_denied(
        verify_workspace_handle(
            &TokenBytes::from_vec(giant),
            &root_pub(),
            WS,
            GuestOp::ListLinks,
            NOW,
        ),
        "64 KiB handle",
    );

    // Oversized authority datalog: refused after the signature says it is
    // ours, before any authorizer exists.
    let bloated = mint_raw_authority(&format!(
        "audience(\"guest\");\nworkspace(\"{}\");\nowner_principal(\"{ALICE}\");\n\
         generation({GEN});\nfencing_token({FENCE});\nexp({EXP});\n\
         check if time($t), $t < {EXP};",
        "w".repeat(1100)
    ));
    assert_handle_denied(
        verify_workspace_handle(&bloated, &root_pub(), WS, GuestOp::ListLinks, NOW),
        "handle with a 1 KiB+ authority block",
    );

    // Too many authority statements.
    let mut padded = raw_handle_source(r#"["list_links", "spawn", "request_link"]"#);
    for i in 0..20 {
        padded.push_str(&format!("\npad({i});"));
    }
    assert_handle_denied(
        verify_workspace_handle(
            &mint_raw_authority(&padded),
            &root_pub(),
            WS,
            GuestOp::ListLinks,
            NOW,
        ),
        "handle with 28 authority statements",
    );

    // And the other failure mode (ADR-0014's first half): a shared datalog
    // budget so tight that honest handles are denied under load.
    let threads = std::thread::available_parallelism()
        .map(NonZeroUsize::get)
        .unwrap_or(4)
        .clamp(2, 8);
    std::thread::scope(|scope| {
        for _ in 0..threads {
            let token = token.clone();
            scope.spawn(move || {
                for _ in 0..60 {
                    let v =
                        verify_workspace_handle(&token, &root_pub(), WS, GuestOp::ListLinks, NOW)
                            .expect("a legitimate handle must never be denied");
                    assert_eq!(v.generation, GEN);
                }
            });
        }
    });
}

/// Untrusted strings stay strings on this path too: a workspace id or owner
/// principal full of datalog syntax is a value, never syntax.
#[test]
fn g_injection_in_handle_strings_is_inert() {
    let evil_ws = r#"ws") or true or workspace("x"#;
    let evil_owner = r#"eve") or true; audience("node"#;
    let token = mint_workspace_handle(&root(), evil_ws, evil_owner, GEN, FENCE, EXP).unwrap();

    let v = verify_workspace_handle(&token, &root_pub(), evil_ws, GuestOp::Spawn, NOW).unwrap();
    assert_eq!(v.workspace, evil_ws);
    assert_eq!(v.owner_principal, evil_owner);
    assert_handle_denied(
        verify_workspace_handle(&token, &root_pub(), WS, GuestOp::Spawn, NOW),
        "evil workspace does not match a normal one",
    );
    // The smuggled `audience("node")` is a substring of a string, not a fact.
    assert_node_denied(
        verify_node_token(&token, &root_pub(), evil_ws, NOW),
        "handle with an injection-shaped owner principal, as a node token",
    );
}

// ---------------------------------------------------------------------------
// datalog injection: untrusted strings stay strings
// ---------------------------------------------------------------------------

#[test]
fn injection_in_principal_and_workspace_is_inert() {
    let evil_principal = r#"eve") or true; role("owner"#;
    let evil_ws = r#"ws") or true or workspace("x"#;
    let token = mint(&root(), evil_principal, evil_ws, Role::Viewer, EXP).unwrap();

    // The evil strings round-trip as plain values...
    let v = verify(&token, &root_pub(), evil_ws, &Op::Read, NOW).unwrap();
    assert_eq!(v.principal, evil_principal);
    assert_eq!(v.role_effective, Role::Viewer);
    // ...and grant nothing extra.
    assert_denied(
        verify(&token, &root_pub(), evil_ws, &Op::Write, NOW),
        "evil-string viewer write",
    );
    assert_denied(
        verify(&token, &root_pub(), WS, &Op::Read, NOW),
        "evil workspace does not match a normal one",
    );

    let harness = mint_harness(&root(), evil_principal, WS, EXP).unwrap();
    verify(
        &harness,
        &root_pub(),
        WS,
        &Op::AppendOwnEvents {
            principal: evil_principal.into(),
        },
        NOW,
    )
    .unwrap();
}
