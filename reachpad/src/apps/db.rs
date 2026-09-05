//! `reachpad db "<sql>"` — one SQL statement against the app's database.
//!
//! The operator half of the data plane (reports/apps-v1 DATA-PLANE.html): the
//! app itself reads and writes through `env.reachpad.db` inside its own
//! function, and this verb is the terminal door onto the same store, for
//! reading a count or fixing a row by hand.
//!
//! Two refusals are decided HERE rather than by the server, and both before a
//! single byte leaves the machine:
//!
//! - **Schema changes.** `CREATE`, `ALTER`, `DROP` and their neighbours belong
//!   in the app's code, where they are versioned with everything else. The
//!   server refuses them too (`schema_change_refused`); the client refuses them
//!   in the same words, so an agent that types one learns the rule without
//!   spending a round trip on it.
//! - **Values in the SQL.** `--params` is the only way a value reaches a
//!   statement. The check that enforces it is the JSON array's element types:
//!   a string, a number, a boolean or a null, and nothing else.

use serde_json::Value;

use crate::errors::CliError;

/// What a statement may not begin with, whatever the comments in front of it
/// say. The server's nine, in the server's order, so the two lists read as one
/// list.
const SCHEMA_VERBS: &[&str] = &[
    "CREATE", "ALTER", "DROP", "ATTACH", "DETACH", "PRAGMA", "VACUUM", "REINDEX", "ANALYZE",
];

/// The sentence, said the same way on both sides of the wire.
pub const SCHEMA_REFUSAL: &str = "Schema changes go in the app's code, not through reachpad db.";

/// The statement with its leading whitespace and leading SQL comments removed.
///
/// `-- fix the count\nDROP TABLE items` is a `DROP`, and a check that read the
/// first word of the raw string would have called it a comment and let it
/// through. Both comment forms are stripped, repeatedly, because a statement
/// can be preceded by several.
fn statement_head(sql: &str) -> &str {
    let mut rest = sql.trim_start();
    loop {
        if let Some(after) = rest.strip_prefix("--") {
            rest = match after.find('\n') {
                Some(end) => after[end + 1..].trim_start(),
                // A line comment with no newline after it is the whole input.
                None => "",
            };
            continue;
        }
        if let Some(after) = rest.strip_prefix("/*") {
            rest = match after.find("*/") {
                Some(end) => after[end + 2..].trim_start(),
                // An unterminated block comment swallows the rest, which is
                // what SQLite would do with it too.
                None => "",
            };
            continue;
        }
        return rest;
    }
}

/// The first word of a statement, uppercased. Empty when there is none.
fn first_word(sql: &str) -> String {
    statement_head(sql)
        .chars()
        .take_while(|c| c.is_ascii_alphabetic())
        .collect::<String>()
        .to_ascii_uppercase()
}

/// Refuse a statement that changes the schema, before anything is sent.
pub fn refuse_schema_change(sql: &str) -> Result<(), CliError> {
    if SCHEMA_VERBS.contains(&first_word(sql).as_str()) {
        return Err(super::failure(SCHEMA_REFUSAL));
    }
    Ok(())
}

/// What an unacceptable `--params` element is, in a word a sentence can use.
fn kind_of(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Array(_) => "an array",
        Value::Object(_) => "an object",
    }
}

/// `--params` as the bound values, or the sentence that names what is wrong.
///
/// Absent means no placeholders, which is the common case and is an empty
/// array on the wire rather than a missing field.
pub fn parse_params(raw: Option<&str>) -> Result<Vec<Value>, CliError> {
    let Some(raw) = raw else {
        return Ok(Vec::new());
    };
    let parsed: Value = serde_json::from_str(raw)
        .map_err(|e| super::failure(format!("--params is not JSON: {e}.")))?;
    let Value::Array(items) = parsed else {
        return Err(super::failure(format!(
            "--params takes a JSON array of values, and this is {}.",
            kind_of(&parsed)
        )));
    };
    for (index, item) in items.iter().enumerate() {
        if matches!(item, Value::Array(_) | Value::Object(_)) {
            return Err(super::failure(format!(
                "--params takes strings, numbers, booleans and nulls, and element {index} is {}.",
                kind_of(item)
            )));
        }
    }
    Ok(items)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_schema_change_is_refused_however_it_is_dressed_up() {
        for sql in [
            "CREATE TABLE items (id integer)",
            "create table items (id integer)",
            "   \n\t DROP TABLE items",
            "-- housekeeping\nDROP TABLE items",
            "--housekeeping\r\n  drop table items",
            "/* two */ /* comments */ ALTER TABLE items ADD COLUMN done integer",
            "/* multi\nline */\nPRAGMA journal_mode = wal",
            "ATTACH DATABASE 'x' AS y",
            "detach y",
            "VACUUM",
            "reindex items",
            "ANALYZE items",
            "  /* nightly */ analyze",
        ] {
            let error = refuse_schema_change(sql)
                .expect_err(&format!("{sql:?} changes the schema and was allowed"));
            assert_eq!(error.message, SCHEMA_REFUSAL);
            assert_eq!(error.exit_code, 1);
        }
    }

    /// Nine, because the doc comment says the client's list and the server's
    /// are one list, and a client that refuses eight of nine sends the ninth.
    #[test]
    fn the_refused_list_is_the_servers_nine() {
        assert_eq!(SCHEMA_VERBS.len(), 9);
    }

    #[test]
    fn the_statements_this_verb_exists_for_are_not_refused() {
        for sql in [
            "SELECT count(*) FROM items",
            "  select 1",
            "-- the live count\nSELECT count(*) FROM items",
            "INSERT INTO items (owner) VALUES (?)",
            "UPDATE items SET done = 1 WHERE id = ?",
            "DELETE FROM items WHERE id = ?",
            "WITH recent AS (SELECT * FROM items) SELECT * FROM recent",
            // A column that merely NAMES one of the verbs is not one.
            "SELECT created_at FROM items WHERE title = 'drop table'",
            "",
        ] {
            assert!(
                refuse_schema_change(sql).is_ok(),
                "{sql:?} is a data statement and was refused"
            );
        }
    }

    #[test]
    fn params_are_scalars_or_a_sentence_naming_the_element() {
        assert_eq!(parse_params(None).unwrap(), Vec::<Value>::new());
        assert_eq!(
            parse_params(Some(r#"["a", 1, 2.5, true, null]"#)).unwrap(),
            vec![json!("a"), json!(1), json!(2.5), json!(true), json!(null)]
        );
        assert_eq!(parse_params(Some("[]")).unwrap(), Vec::<Value>::new());

        let nested = parse_params(Some(r#"[1, {"a": 2}]"#)).unwrap_err();
        assert_eq!(
            nested.message,
            "--params takes strings, numbers, booleans and nulls, and element 1 is an object."
        );
        let listed = parse_params(Some("[[1]]")).unwrap_err();
        assert!(
            listed.message.contains("element 0 is an array"),
            "{listed:?}"
        );
        let object = parse_params(Some(r#"{"a": 1}"#)).unwrap_err();
        assert_eq!(
            object.message,
            "--params takes a JSON array of values, and this is an object."
        );
        assert!(parse_params(Some("[1,"))
            .unwrap_err()
            .message
            .starts_with("--params is not JSON:"));
    }
}
