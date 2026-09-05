//! `reachpad skill get core` — the instructions a coding agent follows to build
//! and publish an app.
//!
//! Static text compiled into the binary and versioned with it, which is the
//! point: the console's build prompt says "run `reachpad skill get core` and
//! follow the printed instructions", so the instructions are always the ones
//! that match the CLI actually installed on that machine. A hosted copy would
//! drift the moment someone ran an older binary.

/// The topics `skill list` knows about. One today; the name is the contract.
pub const TOPICS: &[(&str, &str)] = &[(
    "core",
    "Build an app and publish it: the manifest, check, publish, sharing.",
)];

/// The `core` topic, with this binary's version stamped into it.
pub fn core() -> String {
    format!(
        "# Publishing an app to Reachpad\n\
         \n\
         Instructions for a coding agent, from `reachpad` {version}. Follow them in \
         order; do not stop after scaffolding.\n\
         \n\
         ## 1. Check the tool and the account\n\
         \n\
         ```\n\
         reachpad --version\n\
         reachpad whoami\n\
         ```\n\
         \n\
         `whoami` prints `org: <name> (<orgId>)`. If the task pinned an org id and this \
         one differs, or is missing, STOP and report it. Do not change files and do not \
         publish. If `whoami` says to sign in, run `reachpad login` and keep the process \
         open until the browser flow finishes.\n\
         \n\
         On reachpad.dev the sign-in is for apps: `login` ends with \"Workspaces are not \
         available on this endpoint.\" and `whoami` reports the org and \
         `credential: apps`. That is the normal state, not a failure: apps are the whole \
         surface here, and the workspace verbs refuse.\n\
         \n\
         ## 2. Prepare the folder\n\
         \n\
         ```\n\
         reachpad init\n\
         ```\n\
         \n\
         This writes `reachpad.json` beside the source and contacts nothing. The manifest \
         is small and additive:\n\
         \n\
         ```json\n\
         {{ \"kind\": \"page\", \"entry\": \"index.html\" }}\n\
         ```\n\
         \n\
         `kind` is `page` or `function`. `entry` is a path relative to that folder. \
         `env`, `services` and `secrets` are optional objects/arrays. Leave `app` alone: \
         the first publish writes it, and it is how every later command knows which app \
         this folder is.\n\
         \n\
         ## 3. Write the app\n\
         \n\
         A **page** is a file tree served as it is. Write a single `index.html`, or a \
         folder containing one plus its assets, and point `entry` at the HTML file that \
         answers `/`. There is no build step and no framework requirement; if you use a \
         bundler, publish its output folder.\n\
         \n\
         A **function** is one JavaScript module:\n\
         \n\
         ```js\n\
         export default {{\n\
         \x20 async fetch(request, env) {{\n\
         \x20   return new Response(\"hello\");\n\
         \x20 }},\n\
         }};\n\
         ```\n\
         \n\
         `request.reachpad` carries the caller's identity (`user`, `org`, `role`, `app`, \
         `version`) for a signed-in visitor. Never write your own sign-in, and never read a secret \
         from the source: name it in `secrets` and read it from `env`.\n\
         \n\
         Excluded from every snapshot: `node_modules`, `.git`, `.env*`, and anything \
         listed in `.reachpadignore`. `reachpad.json` IS uploaded, so a `pull` into an \
         empty folder gives a linked project.\n\
         \n\
         ## Secrets\n\
         \n\
         A key never goes in the source and never in `env`, which is stored as plain text. \
         Name it in the manifest instead:\n\
         \n\
         ```json\n\
         {{ \"kind\": \"function\", \"entry\": \"server.js\", \"secrets\": [\"STRIPE_KEY\"] }}\n\
         ```\n\
         \n\
         The handler then reads `env.STRIPE_KEY`. A secret belongs to the ORG, not to one \
         app: it is set once, and every app in the org that names it gets it.\n\
         \n\
         ```\n\
         reachpad secrets set STRIPE_KEY   # value from stdin, else a hidden prompt\n\
         reachpad secrets list             # names, who set them, which apps bind them\n\
         ```\n\
         \n\
         Never put a value on the command line. A publish that names a secret nobody has \
         set fails until it is set; ask the person to run the `set` line above.\n\
         \n\
         ## 4. Check, then publish\n\
         \n\
         ```\n\
         reachpad check\n\
         reachpad publish -m \"What changed\"\n\
         ```\n\
         \n\
         `check` validates locally and uploads nothing: the manifest, the entry file, \
         the file count and the file sizes. Fix what it names before publishing.\n\
         \n\
         `publish` creates the app on the first run and adds a version on every run after \
         it. It prints one line that matters:\n\
         \n\
         ```\n\
         URL: https://<slug>.<apps-domain>/\n\
         ```\n\
         \n\
         **Copy that line verbatim into your report. Never construct a URL from a slug, a \
         name or an id.** The address is the server's to decide, slugs get suffixed when \
         they collide, and a guessed URL is a link that 404s.\n\
         \n\
         ## 5. Sharing, only if asked\n\
         \n\
         New apps are visible to the owner. To widen that:\n\
         \n\
         ```\n\
         reachpad access                       # what it is now\n\
         reachpad access set org-link          # anyone in the org with the link\n\
         reachpad access set public-link       # anyone with the link\n\
         reachpad share someone@example.com --role editor\n\
         ```\n\
         \n\
         `restricted` is the narrow end. Do not widen access that was not asked for.\n\
         \n\
         ## Data\n\
         \n\
         A function gets a database and a file store when the manifest asks for them:\n\
         \n\
         ```json\n\
         {{ \"kind\": \"function\", \"entry\": \"server.js\", \"services\": [\"db\", \"files\"] }}\n\
         ```\n\
         \n\
         Inside the handler:\n\
         \n\
         ```js\n\
         const {{ rows, changes, lastInsertRowid }} =\n\
         \x20 await env.reachpad.db.query(\"SELECT id, title FROM items WHERE owner = ?\", [user]);\n\
         await env.reachpad.db.batch([\n\
         \x20 {{ sql: \"INSERT INTO items (owner, title) VALUES (?, ?)\", params: [user, title] }},\n\
         ]);\n\
         \n\
         const id = crypto.randomUUID();\n\
         await env.reachpad.files.put(id, await request.arrayBuffer(), \"image/png\");\n\
         const file = await env.reachpad.files.get(id);   // a Response, or null\n\
         await env.reachpad.files.head(id);\n\
         await env.reachpad.files.delete(id);\n\
         const {{ db_bytes, files, file_bytes }} = await env.reachpad.usage();\n\
         ```\n\
         \n\
         `batch` applies up to 20 statements atomically; one failure rolls the whole batch \
         back. Params are strings, numbers, booleans, nulls or \
         `{{ \"$blob\": \"<base64>\" }}`; the `reachpad db` verb takes the first four only. \
         A read answers at most 5,000 rows or 4 MB and is REFUSED past either, never \
         truncated, so page a large table rather than selecting it whole. Key rows on \
         `request.reachpad.user` when the data belongs to a person.\n\
         \n\
         The app chooses each file's id and it must be a uuid; there is no list call, so \
         keep your own table of them. A body is a string, an ArrayBuffer, a view or a Blob. \
         100 MB per file, and 1 GB and 10,000 files per app.\n\
         \n\
         Read or fix data from the terminal:\n\
         \n\
         ```\n\
         reachpad db \"SELECT count(*) FROM items\"\n\
         reachpad db \"DELETE FROM items WHERE id = ?\" --params '[7]'\n\
         ```\n\
         \n\
         One statement per call, values only through `--params`, and no schema changes.\n\
         \n\
         ## Migrations\n\
         \n\
         Schema changes go in `migrations/NNNN_name.sql` beside the code: four or more \
         digits, an underscore, then lowercase letters, digits, `-` or `_`. Only a function \
         app that lists `db` in `services` may carry the folder.\n\
         \n\
         Files run in ascending number order when the version GOES LIVE, not when it is \
         built, so a version held for review does not change the schema under the live one. \
         One change per file. Never edit a file that has already been published: the \
         platform records each file's hash and refuses a changed one, telling you to add a \
         new file instead.\n\
         \n\
         Each FILE is all or nothing, but a set is not. Three files can stop after the \
         first, and the ones before the failure stay applied. A failure fails the publish \
         with the SQLite message, and the app's link keeps serving the previous version. \
         Read the ledger, fix the file that failed, and publish again; what already applied \
         is skipped.\n\
         \n\
         ```\n\
         reachpad db \"SELECT name, applied_at, version_id FROM _rp_migrations\"\n\
         ```\n\
         \n\
         ## Working on an app that already exists\n\
         \n\
         ```\n\
         reachpad link <app URL>   # attach this folder to it\n\
         reachpad pull             # bring the live source down\n\
         reachpad sync             # pull, merge, publish; run before editing\n\
         reachpad versions         # what has been published\n\
         ```\n\
         \n\
         Read before you update. Every publish is an immutable version with its own \
         permanent link; nothing is ever overwritten.\n",
        version = env!("CARGO_PKG_VERSION"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_core_topic_is_short_and_says_the_things_it_has_to() {
        let text = core();
        assert!(
            text.lines().count() < 160,
            "the skill is {} lines and the budget is 160",
            text.lines().count()
        );
        for required in [
            "reachpad --version",
            "reachpad whoami",
            "reachpad init",
            "reachpad check",
            "reachpad publish",
            "reachpad secrets set STRIPE_KEY",
            "reachpad secrets list",
            "env.STRIPE_KEY",
            "Never put a value on the command line",
            "URL:",
            "Never construct a URL from a slug",
            "export default",
            "request.reachpad",
            "reachpad.json",
            "access set org-link",
            "\"services\": [\"db\", \"files\"]",
            "env.reachpad.db.query(",
            "env.reachpad.db.batch(",
            "env.reachpad.files.put(",
            "env.reachpad.files.get(",
            "env.reachpad.files.delete(",
            "env.reachpad.usage()",
            "5,000 rows or 4 MB",
            "100 MB per file",
            "10,000 files per app",
            "reachpad db \"SELECT count(*) FROM items\"",
            "values only through `--params`",
            r#"{ "$blob": "<base64>" }"#,
            "the first four only",
            // Migrations: the folder, when they run, the rule that keeps an
            // applied file frozen, and the ledger that says what applied.
            "migrations/NNNN_name.sql",
            "when the version GOES LIVE",
            "Never edit a file that has already been published",
            "_rp_migrations",
            // Apps-only sign-in: the state every reachpad.dev login lands in.
            "Workspaces are not available on this endpoint.",
            "credential: apps",
        ] {
            assert!(text.contains(required), "the skill never says {required:?}");
        }
        // Versioned with the binary, so an older install prints older advice.
        assert!(text.contains(env!("CARGO_PKG_VERSION")));
        // The JSON and JS samples survived the format string's brace escaping.
        assert!(text.contains(r#"{ "kind": "page", "entry": "index.html" }"#));
        assert!(text.contains("async fetch(request, env) {"));
        assert!(text.contains(r#""secrets": ["STRIPE_KEY"]"#));
    }
}
